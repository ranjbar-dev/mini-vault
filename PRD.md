# Product Requirements Document: `mini-vault`

**Project:** Custodial Crypto Payment Processor  
**Service:** `mini-vault` — Multi-Secret Distribution Service  
**Language:** Go  
**Status:** v2 — Multi-Secret Store  
**Version:** 2.0.0  

---

## 1. Purpose

`mini-vault` is a standalone, minimal Go microservice whose responsibility is to
securely hold a set of named secrets and serve them to authenticated clients over
mutually authenticated TLS (mTLS) gRPC. Secrets are defined as a JSON file
before build time, encrypted with a passphrase, and embedded in the binary.
At runtime the operator enters the passphrase once; thereafter any secret can
be fetched by name.

It exists as a separate server to establish a physical security boundary: a
compromise of a consumer server does not expose the secrets, because plaintext
secrets never reside on that machine.

---

## 2. Background and Security Model

### 2.1 Role in the Larger System

```
[mini-vault server]           [consumer service(s)]
┌───────────────────┐  mTLS  ┌────────────────────┐
│   mini-vault      │───────►│   your-service     │
│                   │◄───────│                    │
│  secrets map in  │  value  │  uses secret to    │
│  heap RAM        │        │  connect/sign/auth │
└───────────────────┘        └────────────────────┘
```

### 2.2 Threat Model

| Threat | Protection |
|--------|-----------|
| Database stolen | Secrets not in DB — attacker has only ciphertext |
| `wallet-signer` server compromised | Secrets live on a separate server |
| Network interception | mTLS encrypts all traffic; mutual cert auth prevents MITM |
| `mini-vault` server compromised after startup | Secrets in heap RAM protected by RWMutex; no plaintext on disk |
| `mini-vault` server compromised before startup | Startup passphrase required to decrypt; not stored on disk |
| Binary stolen | `data/secrets.bin` in binary is useless without the startup passphrase |
| Memory dump of running process | memguard uses locked pages and canaries; reduces but does not eliminate risk |

### 2.3 What `mini-vault` Does NOT Do

- Does not have a web UI or admin panel
- Does not connect to any database
- Does not expose any HTTP endpoint
- Does not log secret values in any form
- Does not support runtime secret updates (requires rebuild)
- Does not implement token-based access, lease TTLs, or audit logs (v2)

---

## 3. Secret Management Design

### 3.1 Secret Hierarchy

```
Startup Passphrase (typed by operator at boot)
         │
         ▼
    Argon2id (memory: 256MB, iterations: 3, parallelism: 2)
    + salt embedded in secrets.bin
         │
         ▼
  Unwrapping Key (32 bytes, in memory only, never stored)
         │
         ▼  AES-256-GCM decrypt
  Encrypted secrets blob (stored in binary via go:embed)
         │
         ▼
  Secrets map (map[string]string, in memguard-protected memory)
         │
         ▼  served via mTLS gRPC to wallet-signer
  wallet-signer uses secret values to operate
```

### 3.2 Secrets Definition (Pre-Build, Offline)

The operator defines secrets in `data/secrets.json` — a plain JSON object
with string keys and string values:

```json
{
  "kek":          "base64-or-hex-encoded-aes-key",
  "db_password":  "hunter2",
  "api_key":      "sk-live-abc123"
}
```

**`data/secrets.json` must be gitignored.** It is plaintext and must never
be committed to any repository.

Values are always strings. Binary values (e.g. raw AES keys) must be encoded
as hex or base64 by the operator before placing them in the JSON. The
`wallet-signer` is responsible for decoding if needed.

### 3.3 Pre-Build Encryption Step

Before building, the operator runs the `vault-encrypt` CLI on their offline
workstation to produce `data/secrets.bin`:

```
vault-encrypt -in data/secrets.json -out data/secrets.bin
```

Steps performed by `vault-encrypt`:
1. Read `data/secrets.json`
2. Validate that it is a flat `map[string]string` (no nested objects)
3. Prompt operator for passphrase twice (no echo, must match)
4. Generate 16-byte random Argon2id salt via `crypto/rand`
5. Derive 32-byte wrapping key via Argon2id (memory: 256MB, iterations: 3, parallelism: 2)
6. Generate 12-byte random AES-GCM nonce via `crypto/rand`
7. Encode secrets as a length-prefixed binary payload (see §3.4)
8. Encrypt the payload with AES-256-GCM
9. Write `data/secrets.bin`: `[version | salt | argon params | nonce | ciphertext+tag]`
10. Zero all key material in memory before exit

**`data/secrets.bin` may be committed to the private git repo** — it is
encrypted and safe to store. It is useless without the passphrase.

### 3.4 Encrypted File Format (`secrets.bin`)

```
[2 bytes  ] version prefix (0x0003)
[16 bytes ] Argon2id salt       (random, not secret)
[4 bytes  ] Argon2id memory     (in KB, e.g. 262144 = 256MB)
[4 bytes  ] Argon2id iterations
[1 byte   ] Argon2id parallelism
[12 bytes ] AES-GCM nonce       (random, not secret)
[N bytes  ] AES-GCM ciphertext + 16-byte auth tag
─────────────────────────────
 39 + N bytes total (variable length)
```

Header is exactly 39 bytes. The Argon2id params read from the header are
bounds-checked before use (≤4GB memory, ≤100 iterations, ≤64 threads) so a
corrupted header cannot demand an arbitrary allocation before the GCM tag
is verified.

The plaintext inside the GCM envelope is a length-prefixed binary payload —
**not JSON** — so decoding never materialises secret values as Go strings
(strings cannot be zeroed):

```
[4 bytes  ] uint32 secret count
per secret:
  [2 bytes] uint16 name length | name bytes
  [4 bytes] uint32 value length | value bytes
```

### 3.5 go:embed

```go
//go:embed data/secrets.bin
var encryptedSecrets []byte
```

`data/secrets.bin` is embedded at build time. The running binary needs no
files on disk at runtime.

### 3.6 Runtime Secret Store

After startup passphrase entry:

- The wrapping key is derived and used to decrypt the secrets blob
- The decrypted binary payload is parsed into `map[string][]byte` — all
  values stay `[]byte` end to end; no unwipeable string copies are created
- The map is protected in memory via a `sync.RWMutex`; individual values
  are copied out on demand and zeroed by the caller after use
- The wrapping key and passphrase bytes are zeroed immediately after decryption
- The AES-GCM plaintext buffer is zeroed after parsing
- No plaintext secret material ever touches the filesystem or stdout

Note: individual secret values in the map are in regular heap memory (not in
individual memguard buffers), which is an accepted trade-off for simplicity.
The unwrapping key is stored in a `memguard.LockedBuffer` until decryption
is complete, then destroyed.

---

## 4. API Design

### 4.1 Transport

- **Protocol:** gRPC over mTLS (TLS 1.3 minimum)
- **Port:** 9000 (configurable via `VAULT_PORT`)
- **Authentication:** Mutual TLS — both client and server must present a valid certificate signed by the shared internal CA
- **No other ports are opened** — no HTTP, no metrics, no management port

### 4.2 Certificate Architecture

```
Internal CA (self-signed, generated offline)
├── mini-vault server cert  (used by mini-vault as TLS server)
└── client cert             (one per consumer application, CN must match VAULT_CLIENT_CN)
```

### 4.3 Proto Definition

```protobuf
syntax = "proto3";

package minivault.v1;

option go_package = "github.com/yourorg/mini-vault/proto/minivault/v1";

service VaultService {
  // GetSecret returns a named secret value to an authenticated client.
  rpc GetSecret(GetSecretRequest) returns (GetSecretResponse);

  // HealthCheck confirms the vault is live and secrets are loaded.
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}

message GetSecretRequest {
  // name is the key to look up in the secrets map (e.g. "kek", "db_password").
  string name = 1;
}

message GetSecretResponse {
  // value is the raw secret value bytes. Never logged.
  bytes value = 1;

  // name echoes back the requested key name.
  string name = 2;
}

message HealthCheckRequest {}

message HealthCheckResponse {
  // loaded is true when secrets have been successfully decrypted and are in memory.
  bool loaded = 1;

  // count is the number of secrets currently loaded.
  int32 count = 2;
}
```

### 4.4 Request Authorization Logic

Before returning any secret:

1. **Client cert CN check** — the certificate Common Name must match `VAULT_CLIENT_CN` (default: `vault-client`); mismatch returns `PERMISSION_DENIED`
2. **Rate limit** — maximum `VAULT_RATE_LIMIT_RPM` `GetSecret` calls per 60 seconds per client CN; excess returns `RESOURCE_EXHAUSTED`
3. **Secret existence** — if the requested name does not exist in the map, return `NOT_FOUND`

### 4.5 What the API Never Does

- Never returns partial secret material
- Never accepts secret values from clients
- Never exposes any endpoint to add, update, or delete secrets at runtime
- Never logs secret values — not in debug, not in errors
- Never includes secret values in gRPC error details

---

## 5. Startup Sequence

```
1. Process starts
2. Load encrypted secrets blob from go:embed into memory
3. Parse secrets.bin: extract Argon2id salt + params, nonce, ciphertext
4. Prompt operator for passphrase on stdin (no echo, single attempt)
5. Derive 32-byte wrapping key via Argon2id using parsed salt + params
   (uses ~256MB RAM for ~1-2 seconds — one-time cost)
6. Decrypt ciphertext with AES-256-GCM → binary payload
7. Zero wrapping key and passphrase bytes immediately
8. Parse payload → map[string][]byte (values never exist as Go strings)
9. Zero the plaintext payload bytes
10. Load mTLS certs from go:embed into memory
11. Start gRPC server on configured port
12. Log "mini-vault ready" with secret count (no secret names or values in log)
13. Serve GetSecret / HealthCheck requests indefinitely
```

If any step fails, the process exits immediately with a non-zero code and a
generic error message. It does not retry or prompt again.

---

## 6. Project Structure

```
mini-vault/
├── cmd/
│   ├── mini-vault/
│   │   └── main.go              # service entrypoint
│   ├── vault-encrypt/
│   │   └── main.go              # pre-build: encrypts data/secrets.json → data/secrets.bin
│   └── gentest-secrets/
│       └── main.go              # dev/CI only: generates a test secrets.bin
├── internal/
│   ├── secrets/
│   │   └── store.go             # in-memory secrets store (decryption + map)
│   ├── server/
│   │   ├── server.go            # gRPC server setup + mTLS config
│   │   └── handler.go           # GetSecret + HealthCheck handlers
│   ├── ratelimit/
│   │   └── limiter.go           # per-cert rate limiter (unchanged)
│   └── config/
│       └── config.go            # env-based configuration
├── proto/
│   └── minivault/v1/
│       ├── vault.proto
│       ├── vault.pb.go          # generated
│       └── vault_grpc.pb.go     # generated
├── data/
│   ├── secrets.json             # GITIGNORED — plaintext secrets (edit this)
│   └── secrets.bin              # committed — AES-256-GCM encrypted blob
├── keys/
│   ├── ca.crt                   # go:embed target
│   ├── server.crt               # go:embed target
│   └── server.key               # go:embed target
├── embed.go                     # go:embed declarations
├── go.mod
├── go.sum
└── README.md
```

**Removed from v1:**
- `cmd/vault-keygen/` → replaced by `cmd/vault-encrypt/`
- `cmd/gentest-kek/` → replaced by `cmd/gentest-secrets/`
- `internal/kek/` → replaced by `internal/secrets/`
- `keys/kek.bin` → replaced by `data/secrets.bin`

---

## 7. Configuration

All configuration is via environment variables. No config file.

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_PASSPHRASE` | *(empty)* | Passphrase to decrypt `secrets.bin`. If unset, prompted interactively on stdin. |
| `VAULT_PORT` | `9000` | gRPC listen port |
| `VAULT_CLIENT_CN` | `vault-client` | Expected CN on client cert |
| `VAULT_RATE_LIMIT_RPM` | `5` | Max GetSecret calls per 60s per client |
| `VAULT_LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |

---

## 8. Logging

- Structured JSON logging via `log/slog`
- Every `GetSecret` call is logged: timestamp, client CN, secret name, result
- **Never logged:** secret values, passphrase, wrapping key, any key material
- **Never logged:** secret names that do not exist (to avoid confirming their absence to log readers)

Example log lines:
```json
{"time":"...","level":"INFO","msg":"mini-vault ready","secrets_count":3,"port":"9000"}
{"time":"...","level":"INFO","msg":"secret_served","client_cn":"vault-client","name":"db_password"}
{"time":"...","level":"WARN","msg":"secret_denied","client_cn":"unknown","reason":"cert_cn_mismatch"}
{"time":"...","level":"WARN","msg":"secret_denied","client_cn":"vault-client","reason":"rate_limit_exceeded"}
{"time":"...","level":"WARN","msg":"secret_not_found","client_cn":"vault-client"}
```

Note: `secret_not_found` does NOT log the requested name to avoid leaking which
names exist. It logs only the client CN.

---

## 9. Error Handling

| Condition | Behavior |
|-----------|----------|
| Wrong passphrase at startup | Exit immediately, generic error, no retry |
| Decryption failure | Exit immediately |
| Payload parse failure | Exit immediately |
| Client cert CN mismatch | `PERMISSION_DENIED`, log warning |
| Rate limit exceeded | `RESOURCE_EXHAUSTED`, log warning |
| Secret name not found | `NOT_FOUND`, log warning (no name in log) |
| Internal error | `INTERNAL`, never include secret values in message |
| SIGTERM | Zero all in-memory secret values, call `memguard.Purge()`, exit 0 |

---

## 10. `vault-encrypt` CLI (Pre-Build Tool)

```
Usage:
  vault-encrypt -in data/secrets.json -out data/secrets.bin

Steps:
  1. Read and validate data/secrets.json (must be flat map[string]string)
  2. Prompt operator for passphrase twice (no echo, must match)
  3. Generate random salt + nonce via crypto/rand
  4. Derive wrapping key via Argon2id (256MB, 3 iterations, 2 parallelism)
  5. Encode secrets as binary payload; encrypt with AES-256-GCM
  6. Write secrets.bin: [version | salt | params | nonce | ciphertext+tag]
  7. Zero all key material before exit

Output:
  data/secrets.bin  → safe to commit to private repo (encrypted)
```

---

## 11. `gentest-secrets` CLI (Dev/CI Only)

```
Usage:
  go run ./cmd/gentest-secrets

Steps:
  1. Write a hardcoded data/secrets.json with test values
  2. Encrypt it with passphrase "test-passphrase-change-before-production"
  3. Write data/secrets.bin

NOT for production. The passphrase and secret values are hardcoded and public.
```

---

## 12. Proto Regeneration

The proto-generated files (`vault.pb.go`, `vault_grpc.pb.go`) must be
regenerated after changing `vault.proto`. The new service replaces `GetKEK`
with `GetSecret` and updates message types accordingly.

Required tool versions (pin in CI):
- `protoc` v6.33.0
- `protoc-gen-go` v1.36.10
- `protoc-gen-go-grpc` v1.5.1

Regeneration command:
```sh
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/minivault/v1/vault.proto
```

---

## 13. Security Hardening (Deployment)

### 13.1 OS-level

- Run as a dedicated non-root user (`vault-svc`)
- `ulimit -c 0` — disable core dumps
- `/proc/sys/kernel/yama/ptrace_scope` set to `1` or higher
- No swap (`swapoff -a`)

### 13.2 Network

- Firewall allows **only** inbound TCP 9000 from the `wallet-signer` server IP
- No outbound connections required or permitted

### 13.3 Systemd Unit

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

### 13.4 Build

```sh
go build -ldflags="-s -w" -o bin/mini-vault ./cmd/mini-vault
```

---

## 14. Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/awnumar/memguard` | Locked RAM for wrapping key during decryption |
| `google.golang.org/grpc` | gRPC server |
| `google.golang.org/protobuf` | Proto serialization |
| `golang.org/x/crypto` | Argon2id key derivation |
| stdlib only for everything else | slog, crypto/aes, crypto/cipher, crypto/rand, encoding/json |

---

## 15. Acceptance Criteria

### Functional

- [ ] Service decrypts secrets on startup with correct passphrase; wrong passphrase → immediate exit
- [ ] `GetSecret("kek")` returns the value defined in `data/secrets.json`
- [ ] `GetSecret("db_password")` returns the value defined in `data/secrets.json`
- [ ] `GetSecret("nonexistent")` returns `NOT_FOUND`
- [ ] `GetSecret` returns `PERMISSION_DENIED` for wrong client cert CN
- [ ] `GetSecret` returns `RESOURCE_EXHAUSTED` after exceeding rate limit
- [ ] `HealthCheck` returns `loaded: true` and correct `count` after startup
- [ ] Process exits cleanly on SIGTERM, zeroing secret values from memory

### Security

- [ ] No secret values in any log line at any log level
- [ ] No secret values in any gRPC error message
- [ ] `data/secrets.json` is gitignored
- [ ] `data/secrets.bin` is committed (encrypted, safe to store)
- [ ] Core dumps disabled (`LimitCORE=0`)
- [ ] Only port 9000 open
- [ ] Connections without valid CA-signed cert rejected at TLS handshake

---

## 16. Disaster Recovery

**Required materials:**
1. Source code → private git repo (contains `data/secrets.bin`)
2. Passphrase → operator memory / password manager
3. TLS certs → git repo (`ca.crt`, `server.crt`, `server.key`)

**Recovery steps:**
1. Provision new server with same firewall rules
2. Clone private git repo
3. `go build -ldflags="-s -w" -o bin/mini-vault ./cmd/mini-vault`
4. Deploy binary; start; enter passphrase (or set `VAULT_PASSPHRASE`)
5. Verify `HealthCheck` returns `loaded: true`
6. Update firewall rules if server IP changed

**If the passphrase is lost:** `data/secrets.bin` cannot be decrypted. Edit
`data/secrets.json` with the original values (from other secure storage),
re-run `vault-encrypt`, rebuild, and redeploy.

---

## 17. Out of Scope (v2)

- Runtime secret updates without rebuild
- Per-secret access control (all secrets accessible to `VAULT_CLIENT_CN`)
- Audit log to external storage
- Multiple allowed clients
- Metrics endpoint
- Automatic cert rotation
- HA / multi-instance
