# mini-vault

Minimal Go microservice that holds a set of named secrets in memory and serves
them exclusively to `wallet-signer` over mutually authenticated TLS (mTLS) gRPC.

> **This service must run on a separate physical server from `wallet-signer`.**
> A compromise of the signer server must not expose the secrets.

---

## How it works

```
[mini-vault server]          [signer server]
┌──────────────────┐  mTLS  ┌───────────────────┐
│  mini-vault      │───────►│  wallet-signer    │
│                  │◄───────│                   │
│  secrets map in │  value  │  uses secrets to  │
│  heap RAM       │        │  operate wallets  │
└──────────────────┘        └───────────────────┘
```

At startup the operator types a passphrase. mini-vault uses Argon2id to
derive an unwrapping key, decrypts `data/secrets.bin` (embedded in the
binary at build time), and holds the plaintext secrets in a `map[string][]byte`
protected by a `sync.RWMutex`. The passphrase and all intermediate key material
are zeroed immediately after decryption. Nothing is written to disk at runtime.

Clients authenticate with a mutual TLS certificate. The handler checks:
1. Client certificate CN matches the configured value (`wallet-signer` by default)
2. Request is within the rate limit (default: 5 calls per 60 s)

If both pass, the requested secret value is returned over the encrypted TLS
channel. If the name does not exist, `NOT_FOUND` is returned.

---

## First-time setup

### 1. Generate TLS certificates (offline workstation — never on a server)

```sh
# Internal CA
openssl genrsa -out keys/ca.key 4096
openssl req -x509 -new -nodes -key keys/ca.key -sha256 -days 3650 \
    -subj "/CN=mini-vault-ca" -out keys/ca.crt

# mini-vault server cert
openssl genrsa -out keys/server.key 4096
openssl req -new -key keys/server.key -subj "/CN=mini-vault" -out keys/server.csr
openssl x509 -req -in keys/server.csr -CA keys/ca.crt -CAkey keys/ca.key \
    -CAcreateserial -days 3650 -sha256 -out keys/server.crt

# wallet-signer client cert — CN must match VAULT_CLIENT_CN
openssl genrsa -out keys/client.key 4096
openssl req -new -key keys/client.key -subj "/CN=wallet-signer" -out keys/client.csr
openssl x509 -req -in keys/client.csr -CA keys/ca.crt -CAkey keys/ca.key \
    -CAcreateserial -days 3650 -sha256 -out keys/client.crt
```

Place `ca.crt`, `server.crt`, `server.key` in `keys/`.
Place `ca.crt`, `client.crt`, `client.key` on the `wallet-signer` server.
Store `ca.key` in cold storage — **never on any server**.

### 2. Define secrets (offline workstation)

Create `data/secrets.json` — a flat JSON object with string keys and string values:

```json
{
  "kek":         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "db_password": "hunter2",
  "api_key":     "sk-live-abc123"
}
```

**`data/secrets.json` must never be committed.** It is plaintext. It is
already gitignored.

### 3. Encrypt secrets (offline workstation)

```sh
go run ./cmd/vault-encrypt -in data/secrets.json -out data/secrets.bin
```

- Type a strong passphrase twice (no echo).
- `data/secrets.bin` is created. **Commit it to your private repo** — it is
  AES-256-GCM encrypted and safe to store. It is useless without the passphrase.

### 4. Build

```sh
go build -ldflags="-s -w" -o bin/mini-vault ./cmd/mini-vault
```

`data/secrets.bin`, `ca.crt`, `server.crt`, and `server.key` are embedded
in the binary at build time via `go:embed`. The running binary needs no
files on disk at runtime.

### 5. Deploy

```sh
scp bin/mini-vault vault-svc@mini-vault-host:/usr/local/bin/
```

### 6. Run

```sh
/usr/local/bin/mini-vault
# prompts: Enter passphrase:
```

On correct passphrase the server logs:
```json
{"level":"INFO","msg":"mini-vault ready","secrets_count":3,"port":"9000"}
```

Wrong passphrase → immediate exit, no retry.

---

## Configuration

All configuration is via environment variables. No config file.

| Variable | Default | Description |
|---|---|---|
| `VAULT_PORT` | `9000` | gRPC listen port |
| `VAULT_CLIENT_CN` | `wallet-signer` | Expected CN on client certificate |
| `VAULT_RATE_LIMIT_RPM` | `5` | Max `GetSecret` calls per 60 s per client |
| `VAULT_LOG_LEVEL` | `info` | Log level: `debug` / `info` / `warn` / `error` |

---

## API

Single gRPC service over mTLS (TLS 1.3 minimum). No other ports.

```protobuf
service VaultService {
  rpc GetSecret(GetSecretRequest) returns (GetSecretResponse);
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}
```

`GetSecretRequest.name` is the key to look up (e.g. `"kek"`, `"db_password"`).
On success `GetSecretResponse.value` contains the raw secret bytes, and
`GetSecretResponse.name` echoes the requested key.

`HealthCheckResponse.loaded` is `true` when secrets are in memory.
`HealthCheckResponse.count` is the number of secrets loaded.

Error codes:
| Code | Cause |
|---|---|
| `PERMISSION_DENIED` | Client cert CN does not match `VAULT_CLIENT_CN` |
| `RESOURCE_EXHAUSTED` | Rate limit exceeded |
| `NOT_FOUND` | Requested secret name does not exist |

---

## Systemd unit

```ini
[Unit]
Description=mini-vault secret distribution service
After=network.target

[Service]
Type=simple
User=vault-svc
ExecStart=/usr/local/bin/mini-vault
StandardInput=tty
TTYPath=/dev/tty
Restart=no
LimitCORE=0
LimitMEMLOCK=infinity
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
```

`Restart=no` is intentional. If the process crashes, an operator must
SSH in, restart it manually, and type the passphrase. Automatic restart
would require a cached passphrase, defeating the protection model.

---

## Local dev / CI

Generate a test `data/secrets.bin` with a fixed passphrase (never for production):

```sh
go run ./cmd/gentest-secrets   # writes data/secrets.json + data/secrets.bin
go build ./...
```

---

## Disaster recovery

**Required materials:**
1. Source code — clone from private git repo (contains `data/secrets.bin`)
2. Passphrase — operator's memory or password manager
3. TLS certs — in the git repo (`ca.crt`, `server.crt`, `server.key`)

**Steps:**
1. Provision a new server with the same firewall and OS hardening
2. Clone the private git repo
3. `go build -ldflags="-s -w" -o bin/mini-vault ./cmd/mini-vault`
4. Deploy and start; enter passphrase when prompted
5. Verify `HealthCheck` returns `loaded: true`
6. Verify `wallet-signer` can fetch secrets successfully
7. Update firewall rules if the server IP changed

**If the passphrase is permanently lost:** `data/secrets.bin` cannot be
decrypted. Edit `data/secrets.json` with the original values (recovered from
other secure storage), re-run `vault-encrypt`, rebuild, and redeploy.

---

## Security

### OS hardening (mandatory)

- Run as a dedicated non-root user (`vault-svc`)
- Disable core dumps: `ulimit -c 0` / `LimitCORE=0` in the unit
- Disable swap: `swapoff -a` — prevents heap pages from hitting disk
- Set `kernel.yama.ptrace_scope=1` — block non-root ptrace
- Firewall: allow **only** inbound TCP 9000 from the `wallet-signer` server IP

### What is protected and how

| Threat | Protection |
|---|---|
| Network interception | mTLS — all traffic encrypted, MITM requires compromising the CA |
| Client impersonation | Mutual TLS — client must present a CA-signed cert with the correct CN |
| `wallet-signer` server compromised | Secrets live on a separate server |
| mini-vault server compromised at rest | Startup passphrase required to decrypt; not stored anywhere |
| Binary or disk stolen | `data/secrets.bin` is AES-256-GCM encrypted; useless without the passphrase |

### What mini-vault does NOT do

- Does not store wallet keys or mnemonics directly
- Does not expose any HTTP endpoint
- Does not connect to any database
- Does not log any secret values at any log level
- Does not support runtime secret updates (requires rebuild)
- Does not auto-restart (operator must enter passphrase on every start)
