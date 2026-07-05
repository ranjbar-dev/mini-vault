# mini-vault

Minimal Go microservice that holds a set of named secrets in memory and serves
them to authenticated clients over mutually authenticated TLS (mTLS) gRPC.

> **Run mini-vault on a separate server from the services that consume secrets.**
> A compromise of a consumer server must not expose the secrets themselves.

See [`llm.txt`](llm.txt) for a condensed, machine-oriented summary of this
repo (architecture, gRPC contract, auth model, env vars, conventions) — it
exists so an AI coding assistant can work on this repo without reading
every source file first. Keep it and this README updated together whenever
the API, auth, config, or client package changes.

---

## How it works

```
[mini-vault server]           [your application]
┌───────────────────┐  mTLS  ┌────────────────────┐
│  mini-vault       │───────►│  your-service      │
│                   │◄───────│                    │
│  secrets map in  │  value  │  uses secret to    │
│  heap RAM        │        │  connect / sign /  │
└───────────────────┘        │  authenticate ...  │
                             └────────────────────┘
```

At startup the operator enters a passphrase (or sets `VAULT_PASSPHRASE`).
mini-vault uses Argon2id to derive an unwrapping key, decrypts
`data/secrets.bin` (embedded in the binary at build time), and holds the
plaintext secrets in a `map[string][]byte` protected by a `sync.RWMutex`.
The passphrase and all intermediate key material are zeroed immediately after
decryption. Nothing is written to disk at runtime.

Every gRPC client must present a mutual TLS certificate. Before returning
any secret the server checks:
1. Client certificate CN matches `VAULT_CLIENT_CN`
2. Request count is within `VAULT_RATE_LIMIT_RPM` per 60 s

If both pass, the requested secret value is returned over the encrypted
channel. If the name does not exist, `NOT_FOUND` is returned.

---

## First-time setup

### 1. Generate TLS certificates (offline workstation — never on a server)

```sh
# Internal CA
openssl genrsa -out keys/ca.key 4096
openssl req -x509 -new -nodes -key keys/ca.key -sha256 -days 3650 \
    -subj "/CN=mini-vault-ca" -out keys/ca.crt

# mini-vault server cert — SAN is required, Go rejects CN-only certs (Go >= 1.15)
openssl genrsa -out keys/server.key 4096
openssl req -new -key keys/server.key -subj "/CN=mini-vault" -out keys/server.csr
printf "subjectAltName=DNS:mini-vault,DNS:localhost,IP:127.0.0.1" > keys/server.ext
# Edit keys/server.ext to list every hostname/IP this server will actually be dialed by.
openssl x509 -req -in keys/server.csr -CA keys/ca.crt -CAkey keys/ca.key \
    -CAcreateserial -days 3650 -sha256 -extfile keys/server.ext -out keys/server.crt

# Client cert for your application — CN must match VAULT_CLIENT_CN
openssl genrsa -out keys/client.key 4096
openssl req -new -key keys/client.key -subj "/CN=vault-client" -out keys/client.csr
openssl x509 -req -in keys/client.csr -CA keys/ca.crt -CAkey keys/ca.key \
    -CAcreateserial -days 3650 -sha256 -out keys/client.crt
```

Place `ca.crt`, `server.crt`, `server.key` in `keys/`.
Copy `ca.crt`, `client.crt`, `client.key` to each application server that
needs to call mini-vault.
Store `ca.key` in cold storage — **never on any server**.

### 2. Define secrets (offline workstation)

Create `data/secrets.json` — a flat JSON object, string keys and string values:

```json
{
  "db_password":  "correct-horse-battery-staple",
  "api_key":      "sk-live-abc123",
  "signing_key":  "0f1e2d3c4b5a..."
}
```

**`data/secrets.json` must never be committed.** It is plaintext and already
gitignored.

Values are always strings. Encode binary material as hex or base64 before
putting it here; your application decodes it after receiving it.

### 3. Encrypt secrets

```sh
go run ./cmd/vault-encrypt -in data/secrets.json -out data/secrets.bin
```

- Type a strong passphrase twice (no echo). The passphrase is the only thing
  standing between a leaked repo and your secrets — use a long, generated one.
- `data/secrets.bin` is created. **Commit it** — it is AES-256-GCM encrypted
  and safe to store. It is useless without the passphrase.
- **Delete `data/secrets.json` now.** The plaintext file lingering on the
  workstation is the most likely leak in this whole system.

### 4. Build

```sh
go build -ldflags="-s -w" -o bin/mini-vault ./cmd/mini-vault
```

`data/secrets.bin`, `ca.crt`, `server.crt`, and `server.key` are all
embedded in the binary at build time. The running binary needs no files on
disk.

### 5. Deploy and run

```sh
scp bin/mini-vault user@vault-host:/usr/local/bin/

# On the vault server — interactive passphrase prompt:
mini-vault
```

For non-interactive startup, set `VAULT_PASSPHRASE` from a root-only file
(see the systemd `EnvironmentFile` example below). **Never pass it inline on
the command line** — `VAULT_PASSPHRASE=... mini-vault` writes the passphrase
to your shell history, and environment variables are readable from
`/proc/<pid>/environ` for the life of the process.

Successful startup logs:
```json
{"level":"INFO","msg":"mini-vault ready","secrets_count":3,"port":"9000"}
```

Wrong passphrase → immediate exit, no retry.

---

## Configuration

All configuration is via environment variables. No config file.

| Variable | Default | Description |
|---|---|---|
| `VAULT_PASSPHRASE` | *(empty)* | Passphrase to decrypt secrets. If unset, prompted interactively on stdin. |
| `VAULT_PORT` | `9000` | gRPC listen port |
| `VAULT_CLIENT_CN` | `vault-client` | Expected CN on the client certificate |
| `VAULT_RATE_LIMIT_RPM` | `5` | Max `GetSecret` calls per 60 s per client |
| `VAULT_LOG_LEVEL` | `info` | Log level: `debug` / `info` / `warn` / `error` |

---

## gRPC API

Single service over mTLS (TLS 1.3 minimum). No other ports are opened.

```protobuf
service VaultService {
  rpc GetSecret(GetSecretRequest) returns (GetSecretResponse);
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}

message GetSecretRequest  { string name  = 1; }
message GetSecretResponse { bytes value  = 1; string name = 2; }
message HealthCheckRequest {}
message HealthCheckResponse { bool loaded = 1; int32 count = 2; }
```

| gRPC code | Cause |
|---|---|
| `PERMISSION_DENIED` | Client cert CN does not match `VAULT_CLIENT_CN` |
| `RESOURCE_EXHAUSTED` | Rate limit exceeded |
| `NOT_FOUND` | Requested secret name does not exist in the store |

---

## Using mini-vault from a Go application

Use the `client` package — it wraps the mTLS dial and gRPC calls so you
don't have to.

### Install

```sh
go get github.com/ranjbar-dev/mini-vault/client
```

For raw proto access instead (advanced use), `go get
github.com/ranjbar-dev/mini-vault/proto/minivault/v1` and call
`pb.NewVaultServiceClient` directly.

### Example client

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/ranjbar-dev/mini-vault/client"
)

func main() {
    c, err := client.NewFromFiles("vault-host:9000", "mini-vault", // ServerName must match the CN in server.crt
        "ca.crt", "client.crt", "client.key")
    if err != nil {
        log.Fatal(err)
    }
    defer c.Close()

    password, err := c.GetSecretString(context.Background(), "db_password")
    if err != nil {
        log.Fatalf("GetSecret: %v", err)
    }
    fmt.Println("got secret, length:", len(password))
}
```

For highly sensitive values, use `c.GetSecret(ctx, name)` to get a `[]byte`
and `client.Zero(b)` it after use — Go strings can't be zeroed.

### Fetching multiple secrets at startup

```go
func loadSecrets(ctx context.Context, c *client.Client) (map[string]string, error) {
    names := []string{"db_password", "api_key", "signing_key"}
    out := make(map[string]string, len(names))

    for _, name := range names {
        val, err := c.GetSecretString(ctx, name)
        if err != nil {
            return nil, fmt.Errorf("fetch %q: %w", name, err)
        }
        out[name] = val
    }
    return out, nil
}
```

### Health check

```go
loaded, count, err := c.HealthCheck(context.Background())
if err != nil {
    log.Fatal(err)
}
fmt.Printf("vault loaded=%v secrets=%d\n", loaded, count)
```

### Handling errors

`GetSecret`/`GetSecretString` return gRPC status errors. Check them with the
package's helpers instead of importing `grpc/status` yourself:

```go
if client.IsNotFound(err) { ... }        // unknown secret name
if client.IsPermissionDenied(err) { ... } // client cert CN not allowed
if client.IsRateLimited(err) { ... }      // VAULT_RATE_LIMIT_RPM exceeded
```

---

## Local dev / CI

Generate a test `data/secrets.bin` with hardcoded values and passphrase
(never for production):

```sh
go run ./cmd/gentest-secrets   # writes data/secrets.json + data/secrets.bin
go build ./...

# Run with the test passphrase via env var:
VAULT_PASSPHRASE=test-passphrase-change-before-production ./bin/mini-vault
```

---

## Systemd unit

See `deploy/mini-vault.service` for the canonical unit file (kept in sync
with this section):

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
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallFilter=@system-service
LockPersonality=true
RestrictNamespaces=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

`Restart=no` is intentional — automatic restart would require a cached
passphrase, which defeats the protection model. An operator must SSH in and
restart the service manually after any crash.

`StandardInput=tty` lets the systemd unit prompt for the passphrase on the
operator's terminal. Alternatively, set `VAULT_PASSPHRASE` in an
`EnvironmentFile` with `0600` permissions:

```ini
EnvironmentFile=/etc/mini-vault/passphrase.env
```

```sh
# /etc/mini-vault/passphrase.env  (chmod 600, owned by vault-svc)
VAULT_PASSPHRASE=your-strong-passphrase
```

---

## Disaster recovery

**Required materials:**
1. Source code — private git repo (contains `data/secrets.bin` and the
   public certs `ca.crt`, `server.crt`)
2. Passphrase — operator's memory or password manager
3. `server.key` — cold storage alongside `ca.key` (private keys are
   gitignored and must never be committed). If it is lost, generate a new
   server cert from the CA before rebuilding.

**Steps:**
1. Provision a new server with the same firewall rules
2. Clone the private git repo
3. `go build -ldflags="-s -w" -o bin/mini-vault ./cmd/mini-vault`
4. Deploy binary; start; enter passphrase
5. Verify `HealthCheck` returns `loaded: true`
6. Update firewall rules if the server IP changed

**If the passphrase is permanently lost:** edit `data/secrets.json` with the
original values (from other secure storage), re-run `vault-encrypt`, rebuild,
and redeploy.

---

## Security

### OS hardening (mandatory)

- Run as a dedicated non-root user
- Disable core dumps: `LimitCORE=0` in the unit file
- Disable swap: `swapoff -a` — prevents heap pages from hitting disk
- Set `kernel.yama.ptrace_scope=1`
- Firewall: allow **only** inbound TCP on `VAULT_PORT` from known client IPs

### Threat model

| Threat | Protection |
|---|---|
| Network interception | mTLS — all traffic encrypted; MITM requires compromising the CA |
| Client impersonation | Mutual TLS — client must present a CA-signed cert with matching CN |
| Consumer server compromised | Secrets live on a separate server; attacker must also compromise mini-vault |
| mini-vault server compromised at rest | Passphrase required at startup; never stored on disk |
| Binary stolen | `data/secrets.bin` is AES-256-GCM encrypted; useless without passphrase |

### What mini-vault never does

- Does not expose any HTTP endpoint
- Does not log secret values at any log level
- Does not connect to any database
- Does not support runtime secret updates (requires rebuild to change secrets)
