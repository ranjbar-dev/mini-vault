# mini-vault

Minimal Go microservice that holds a Key Encryption Key (KEK) in a
memguard-protected RAM enclave and serves it exclusively to `wallet-signer`
over mutually authenticated TLS (mTLS) gRPC.

> **This service must run on a separate physical server from `wallet-signer`.**
> A compromise of the signer server must not expose the KEK.

---

## How it works

```
[mini-vault server]          [signer server]
┌──────────────────┐  mTLS  ┌───────────────────┐
│  mini-vault      │───────►│  wallet-signer    │
│                  │◄───────│                   │
│  KEK in         │   KEK  │  decrypts wallet  │
│  memguard RAM   │        │  private keys     │
└──────────────────┘        └───────────────────┘
```

At startup the operator types a passphrase. mini-vault uses Argon2id to
derive an unwrapping key, decrypts the embedded `kek.bin`, and holds the
plaintext KEK in a locked memory page (`memguard.LockedBuffer`). The
passphrase and all intermediate key material are zeroed immediately after
decryption. Nothing is written to disk.

Clients authenticate with a mutual TLS certificate. The handler checks:
1. Client certificate CN matches the configured value (`wallet-signer` by default)
2. Request is within the rate limit (default: 5 calls per 60 s)
3. Requested KEK version matches the configured version string

If all three pass, the 32-byte KEK is returned over the encrypted TLS channel.

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

### 2. Generate the wrapped KEK (offline workstation)

```sh
go run ./cmd/vault-keygen -out keys/kek.bin
```

- Type a strong passphrase twice (no echo).
- The KEK hex is printed **once** — write it down and store in a physically
  secure location (safe, sealed envelope). It is only needed if you must
  re-encrypt wallet keys under a new KEK.
- `keys/kek.bin` is created. **Commit it to your private repo** — it is
  encrypted and safe to store. It is useless without the passphrase.

### 3. Build

```sh
go build -ldflags="-s -w" -o bin/mini-vault ./cmd/mini-vault
```

`kek.bin`, `ca.crt`, `server.crt`, and `server.key` are embedded in the
binary at build time via `go:embed`. The running binary needs no files on disk.

### 4. Deploy

```sh
scp bin/mini-vault vault-svc@mini-vault-host:/usr/local/bin/
```

### 5. Run

```sh
/usr/local/bin/mini-vault
# prompts: Enter passphrase:
```

On correct passphrase the server logs:
```json
{"level":"INFO","msg":"mini-vault ready","kek_version":"v1","port":"9000"}
```

Wrong passphrase → immediate exit, no retry.

---

## Configuration

All configuration is via environment variables. No config file.

| Variable | Default | Description |
|---|---|---|
| `VAULT_PORT` | `9000` | gRPC listen port |
| `VAULT_CLIENT_CN` | `wallet-signer` | Expected CN on client certificate |
| `VAULT_KEK_VERSION` | `v1` | KEK version string clients must request |
| `VAULT_RATE_LIMIT_RPM` | `5` | Max `GetKEK` calls per 60 s per client |
| `VAULT_LOG_LEVEL` | `info` | Log level: `debug` / `info` / `warn` / `error` |

---

## API

Single gRPC service over mTLS (TLS 1.3 minimum). No other ports.

```protobuf
service VaultService {
  rpc GetKEK(GetKEKRequest) returns (GetKEKResponse);
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}
```

`GetKEKRequest.version` must equal `VAULT_KEK_VERSION`. On success the
response contains the raw 32-byte KEK in `GetKEKResponse.kek`.

Error codes:
| Code | Cause |
|---|---|
| `PERMISSION_DENIED` | Client cert CN does not match `VAULT_CLIENT_CN` |
| `RESOURCE_EXHAUSTED` | Rate limit exceeded |
| `INVALID_ARGUMENT` | Requested version does not match configured version |

---

## Systemd unit

```ini
[Unit]
Description=mini-vault KEK service
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

`Restart=no` is intentional. If the process crashes an operator must
SSH in, restart it manually, and type the passphrase. Automatic restart
would require a cached passphrase, defeating the protection model.

`StandardInput=tty` + `TTYPath=/dev/tty` lets systemctl prompt for the
passphrase on the operator's terminal at start time.

---

## Local dev / CI

Generate a test `kek.bin` with a fixed passphrase (never for production):

```sh
go run ./cmd/gentest-kek   # writes keys/kek.bin
go build ./...
```

---

## Disaster recovery

**Required materials:**
1. Source code — clone from private git repo (already contains `kek.bin`)
2. Passphrase — operator's memory or password manager
3. TLS certs — in the git repo (`ca.crt`, `server.crt`, `server.key`)

**Steps:**
1. Provision a new server with the same firewall and OS hardening
2. Clone the private git repo
3. `go build -ldflags="-s -w" -o bin/mini-vault ./cmd/mini-vault`
4. Deploy and start; enter passphrase when prompted
5. Verify `HealthCheck` returns `kek_loaded: true`
6. Verify `wallet-signer` can fetch the KEK successfully
7. Update firewall rules if the server IP changed

**If the passphrase is permanently lost:** `kek.bin` cannot be decrypted.
Generate a new KEK, and re-encrypt all wallet private keys in the database
under the new KEK. Coordinate with the `wallet-signer` team.

---

## Security

### OS hardening (mandatory)

- Run as a dedicated non-root user (`vault-svc`)
- Disable core dumps: `ulimit -c 0` / `LimitCORE=0` in the unit
- Disable swap: `swapoff -a` — prevents memguard-locked pages from hitting disk
- Set `kernel.yama.ptrace_scope=1` — block non-root ptrace
- Firewall: allow **only** inbound TCP 9000 from the `wallet-signer` server IP

### What is protected and how

| Threat | Protection |
|---|---|
| Network interception | mTLS — all traffic encrypted, MITM requires compromising the CA |
| Client impersonation | Mutual TLS — client must present a CA-signed cert with the correct CN |
| `wallet-signer` server compromised | KEK lives on a separate server; attacker must also compromise mini-vault |
| mini-vault server compromised at rest | Startup passphrase required to unwrap KEK; passphrase not stored anywhere |
| Memory dump of running process | memguard uses locked pages + guard canaries; reduces but does not eliminate risk |
| Binary or disk stolen | `kek.bin` is AES-256-GCM encrypted; useless without the passphrase |

### What mini-vault does NOT do

- Does not store wallet keys or mnemonics
- Does not expose any HTTP endpoint
- Does not connect to any database
- Does not log any key material at any log level
- Does not support key rotation without a binary rebuild (v1)
- Does not auto-restart (operator must enter passphrase on every start)
