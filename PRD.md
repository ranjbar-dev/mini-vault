# Product Requirements Document: `mini-vault`

**Project:** Custodial Crypto Payment Processor  
**Service:** `mini-vault` — Key Encryption Key (KEK) Distribution Service  
**Language:** Go  
**Status:** Pre-implementation  
**Version:** 1.0.0  

---

## 1. Purpose

`mini-vault` is a standalone, minimal Go microservice whose sole responsibility is to securely hold the Key Encryption Key (KEK) and serve it exclusively to the `wallet-signer` service over mutually authenticated TLS (mTLS). It has no database, no user-facing API, no admin UI, and no functionality beyond authenticated key delivery.

It exists as a separate server to establish a physical security boundary: a compromise of the `wallet-signer` server does not automatically expose the KEK, because the KEK never permanently resides on that machine.

---

## 2. Background and Security Model

### 2.1 Role in the Larger System

```
[mini-vault server]          [signer server]           [api server]
┌──────────────────┐  mTLS  ┌───────────────────┐ mTLS ┌─────────────────┐
│   mini-vault     │───────►│   wallet-signer   │◄─────│   business API  │
│                  │◄───────│                   │      │                 │
│  holds KEK in   │  KEK   │  uses KEK to      │      │  sends sign     │
│  memguard RAM   │        │  decrypt wallet   │      │  requests only  │
└──────────────────┘        │  private keys     │      └─────────────────┘
                            └───────────────────┘
```

### 2.2 Threat Model

| Threat | Protection |
|--------|-----------|
| Database stolen | KEK not in DB — attacker has only ciphertext |
| `wallet-signer` server compromised | KEK lives on a separate server; attacker must also compromise `mini-vault` |
| Network interception | mTLS encrypts all traffic; mutual cert auth prevents MITM |
| `mini-vault` server compromised after startup | KEK is in memguard-protected RAM; no plaintext on disk |
| `mini-vault` server compromised before startup | Startup passphrase required to unwrap KEK; not stored anywhere |
| Binary stolen | Wrapped KEK in binary is useless without the startup passphrase |
| Memory dump of running process | memguard uses locked pages and canaries; reduces but does not eliminate risk |

### 2.3 What `mini-vault` Does NOT Do

- It does not store wallet keys or mnemonics
- It does not have a web UI or admin panel
- It does not connect to any database
- It does not expose any HTTP endpoint
- It does not log key material in any form
- It does not support multiple clients or multi-tenancy
- It does not implement token-based access, lease TTLs, or audit logs (v1)

---

## 3. Key Management Design

### 3.1 Key Hierarchy

```
Startup Passphrase (typed by single operator at boot)
         │
         ▼
    Argon2id (memory: 256MB, iterations: 3, parallelism: 2)
    + salt embedded in kek.bin
         │
         ▼
  Unwrapping Key (32 bytes, in memory only, never stored)
         │
         ▼  AES-256-GCM unwrap
  Wrapped KEK (stored in binary via go:embed)
         │
         ▼
  KEK (plaintext, in memguard enclave only)
         │
         ▼  served via mTLS gRPC to wallet-signer
  wallet-signer uses KEK to decrypt per-wallet DEKs
```

### 3.2 KEK Generation (Offline, One-Time Setup)

The KEK is generated once offline using a dedicated CLI tool (`vault-keygen`) that is part of this repository but not part of the running service:

1. Generate a 256-bit random KEK using `crypto/rand`
2. Generate a 16-byte random Argon2id salt using `crypto/rand`
3. Derive a 32-byte unwrapping key via Argon2id (memory: 256MB, iterations: 3, parallelism: 2) from the operator passphrase + salt
4. Wrap the KEK with AES-256-GCM using the unwrapping key
5. Write `[version | salt | argon2id params | nonce | ciphertext | tag]` to `keys/kek.bin`
6. The raw KEK and passphrase are never written to disk

Argon2id parameters are stored inside `kek.bin` so that `mini-vault` can always reconstruct the exact unwrapping key without hardcoding params in the binary. This also allows future `vault-keygen` versions to use stronger parameters without breaking existing binaries.

### 3.3 Key Storage at Rest

The wrapped KEK is embedded into the binary at build time using `go:embed`:

```go
//go:embed keys/kek.bin
var wrappedKEK []byte
```

`keys/kek.bin` contains the Argon2id salt, Argon2id parameters, AES-256-GCM nonce, KEK ciphertext, and authentication tag — in that order. It is useless without the operator passphrase. Its binary layout is:

```
[2 bytes  ] version prefix
[16 bytes ] Argon2id salt       (random, not secret)
[4 bytes  ] Argon2id memory     (in KB, e.g. 262144 = 256MB)
[4 bytes  ] Argon2id iterations
[1 byte   ] Argon2id parallelism
[12 bytes ] AES-GCM nonce       (random, not secret)
[32 bytes ] KEK ciphertext
[16 bytes ] AES-GCM auth tag
─────────────────────────────
 87 bytes total
```

### 3.4 Key Storage at Runtime

After startup passphrase entry:

- The unwrapping key is derived and used to decrypt the KEK
- The KEK is stored exclusively in a `memguard.LockedBuffer`:
  - Memory pages are locked against swap (`mlock`)
  - Pages are encrypted at rest in RAM
  - Guard pages surround the allocation to catch overreads
  - The buffer is zeroed automatically on process exit via `defer memguard.Purge()`
- The unwrapping key and passphrase bytes are zeroed immediately after KEK decryption
- No plaintext key material ever touches the filesystem or stdout

---

## 4. API Design

### 4.1 Transport

- **Protocol:** gRPC over mTLS (TLS 1.3 minimum)
- **Port:** 9000 (configurable via environment variable)
- **Authentication:** Mutual TLS — both client and server must present a valid certificate signed by the shared internal CA
- **No other ports are opened** — no HTTP, no health check port, no metrics port (v1)

### 4.2 Certificate Architecture

```
Internal CA (self-signed, generated offline)
├── mini-vault server cert  (used by mini-vault as TLS server)
└── wallet-signer client cert  (used by wallet-signer as TLS client)
```

- The CA private key is generated offline and stored only in cold storage — never on any server
- The CA certificate is embedded in both binaries via `go:embed`
- Server and client certs are embedded in their respective binaries
- Cert rotation requires a new build and deployment

### 4.3 Proto Definition

```protobuf
syntax = "proto3";

package minivault.v1;

option go_package = "github.com/yourorg/mini-vault/proto/minivault/v1";

service VaultService {
  // GetKEK returns the active KEK to an authenticated wallet-signer instance.
  rpc GetKEK(GetKEKRequest) returns (GetKEKResponse);

  // HealthCheck confirms the vault is live and the KEK is loaded.
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}

message GetKEKRequest {
  // version specifies which KEK version is requested.
  // Must match the version embedded in the binary.
  string version = 1;
}

message GetKEKResponse {
  // kek is the 32-byte raw Key Encryption Key.
  // Transmitted only over mTLS; never logged.
  bytes kek = 1;

  // version identifies this KEK (e.g. "v1").
  string version = 2;
}

message HealthCheckRequest {}

message HealthCheckResponse {
  bool kek_loaded = 1;
  string version  = 2;
}
```

### 4.4 Request Authorization Logic

Even with a valid mTLS client certificate, `mini-vault` applies the following checks before returning the KEK:

1. **Client cert CN check** — the certificate Common Name must match the configured allowed value (e.g. `wallet-signer`)
2. **Rate limit** — maximum 5 `GetKEK` calls per 60 seconds per client cert; excess requests are rejected with `RESOURCE_EXHAUSTED`
3. **Version match** — requested KEK version must match the embedded version string; mismatch returns `INVALID_ARGUMENT`

### 4.5 What the API Never Does

- Never returns partial key material
- Never accepts key material from clients
- Never exposes any endpoint to set, rotate, or delete the KEK at runtime
- Never logs the KEK in any form — not in debug, not in errors

---

## 5. Startup Sequence

```
1. Process starts
2. Load wrapped KEK blob from go:embed into memory
3. Parse kek.bin: extract Argon2id salt + params, nonce, ciphertext, tag
4. Prompt operator for passphrase on stdin (no echo, single attempt)
5. Derive 32-byte unwrapping key via Argon2id using parsed salt + params
   (uses ~256MB RAM for ~1-2 seconds — one-time cost)
6. Decrypt KEK ciphertext with AES-256-GCM → load into memguard.LockedBuffer
7. Zero passphrase bytes, unwrapping key, and all intermediate buffers immediately
8. Release the 256MB Argon2id working memory back to OS
9. Load mTLS certs from go:embed into memory
10. Start gRPC server on configured port
11. Log "mini-vault ready" (no key material in log)
12. Serve GetKEK / HealthCheck requests indefinitely
```

If any step fails (wrong passphrase, decryption error, cert load failure), the process exits immediately with a non-zero code and a generic error message. It does not retry or prompt again — the operator must restart the process.

---

## 6. Project Structure

```
mini-vault/
├── cmd/
│   ├── mini-vault/
│   │   └── main.go              # service entrypoint
│   └── vault-keygen/
│       └── main.go              # offline KEK generation CLI (not part of running service)
├── internal/
│   ├── kek/
│   │   ├── loader.go            # unwrap KEK from embedded blob + passphrase
│   │   └── store.go             # memguard-backed KEK store
│   ├── server/
│   │   ├── server.go            # gRPC server setup + mTLS config
│   │   └── handler.go           # GetKEK + HealthCheck handlers
│   ├── ratelimit/
│   │   └── limiter.go           # per-cert rate limiter
│   └── config/
│       └── config.go            # env-based configuration
├── proto/
│   └── minivault/v1/
│       ├── vault.proto
│       └── vault.pb.go          # generated
├── keys/
│   ├── kek.bin                  # wrapped KEK (go:embed target, gitignored)
│   ├── ca.crt                   # internal CA cert (go:embed target)
│   ├── server.crt               # mini-vault server cert (go:embed target)
│   └── server.key               # mini-vault server key (go:embed target)
├── embed.go                     # go:embed declarations (single file)
├── Makefile
├── Dockerfile                   # minimal scratch/distroless image
├── .gitignore                   # keys/*.bin, keys/*.key must be gitignored
└── README.md
```

### 6.1 `embed.go` (single source of truth for embedded files)

```go
package minivault

import _ "embed"

//go:embed keys/kek.bin
var WrappedKEK []byte

//go:embed keys/ca.crt
var CACert []byte

//go:embed keys/server.crt
var ServerCert []byte

//go:embed keys/server.key
var ServerKey []byte
```

---

## 7. Configuration

All configuration is via environment variables. No config file is read from disk.

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_PORT` | `9000` | gRPC listen port |
| `VAULT_CLIENT_CN` | `wallet-signer` | Expected CN on client cert |
| `VAULT_KEK_VERSION` | `v1` | KEK version string to match in requests |
| `VAULT_RATE_LIMIT_RPM` | `5` | Max GetKEK requests per 60s per client |
| `VAULT_LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |

---

## 8. Logging

- Structured JSON logging via `log/slog` (stdlib, no external dependency)
- Every `GetKEK` call is logged: timestamp, client cert CN, result (success/denied), reason
- **Never logged:** KEK bytes, passphrase, unwrapping key, any key material
- **Never logged:** full TLS handshake details beyond cert CN

Example log lines:
```json
{"time":"2026-06-29T10:00:00Z","level":"INFO","msg":"mini-vault ready","kek_version":"v1","port":9000}
{"time":"2026-06-29T10:01:23Z","level":"INFO","msg":"kek_served","client_cn":"wallet-signer","version":"v1"}
{"time":"2026-06-29T10:01:25Z","level":"WARN","msg":"kek_denied","client_cn":"unknown","reason":"cert_cn_mismatch"}
{"time":"2026-06-29T10:01:26Z","level":"WARN","msg":"kek_denied","client_cn":"wallet-signer","reason":"rate_limit_exceeded"}
```

---

## 9. Error Handling

| Condition | Behavior |
|-----------|----------|
| Wrong passphrase at startup | Exit immediately, generic error, no retry |
| KEK decryption failure | Exit immediately |
| Client cert CN mismatch | Return gRPC `PERMISSION_DENIED`, log warning |
| Rate limit exceeded | Return gRPC `RESOURCE_EXHAUSTED`, log warning |
| KEK version mismatch | Return gRPC `INVALID_ARGUMENT` |
| Internal error during key read | Return gRPC `INTERNAL`, never include key material in error message |
| Graceful shutdown signal (SIGTERM) | Zero memguard buffers, call `memguard.Purge()`, exit 0 |

---

## 10. Security Hardening (Deployment)

These are deployment requirements, not code requirements, but they are mandatory for the security model to hold.

### 10.1 OS-level

- Run as a dedicated non-root user (`vault-svc`)
- `ulimit -c 0` — disable core dumps
- `/proc/sys/kernel/yama/ptrace_scope` set to `1` or higher — prevent ptrace by non-root
- No swap (`swapoff -a`) — prevents memguard-protected pages from being paged to disk

### 10.2 Network

- Firewall allows **only** inbound TCP on port 9000 from the `wallet-signer` server's IP
- No outbound connections required or permitted
- No SSH from the internet — bastion host only
- No other services run on this server

### 10.3 Systemd Unit

```ini
[Unit]
Description=mini-vault KEK service
After=network.target

[Service]
Type=simple
User=vault-svc
ExecStart=/usr/local/bin/mini-vault
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

Note: `Restart=no` is intentional. If the process crashes, an operator must manually restart and re-enter the passphrase. Automatic restart would accept the old passphrase from a cached source, which defeats the protection.

### 10.4 Build

- Builds must be reproducible (pinned Go toolchain version, pinned dependencies via `go.sum`)
- `keys/kek.bin` and `keys/*.key` are gitignored and delivered to the build environment via a secure out-of-band channel
- The binary is stripped (`-ldflags="-s -w"`) to reduce symbol information

---

## 11. Dependencies

Kept deliberately minimal.

| Package | Purpose | Justification |
|---------|---------|---------------|
| `github.com/awnumar/memguard` | Secure RAM storage for KEK | Locked pages, guard canaries, auto-wipe |
| `google.golang.org/grpc` | gRPC server | Transport layer |
| `google.golang.org/protobuf` | Proto serialization | Required by gRPC |
| `golang.org/x/crypto` | Argon2id + AES-256-GCM | Key derivation and unwrapping |
| stdlib only for everything else | — | Logging (slog), TLS, rate limiting, `crypto/rand` |

No web framework. No ORM. No external secret manager.

---

## 12. `vault-keygen` CLI (Offline Tool)

This tool is used once by the operator to generate the wrapped KEK. It is never deployed to any server. It must be run on the operator's own machine (laptop or offline workstation), not on any server.

```
Usage:
  vault-keygen generate --out keys/kek.bin --version v1

Steps:
  1. Prompts operator for passphrase on stdin (twice, must match, no echo)
  2. Generates 16-byte random Argon2id salt via crypto/rand
  3. Derives 32-byte unwrapping key via Argon2id
     (memory: 256MB, iterations: 3, parallelism: 2)
  4. Generates 32-byte random KEK via crypto/rand
  5. Wraps KEK with AES-256-GCM using the unwrapping key
  6. Writes kek.bin: [version | salt | params | nonce | ciphertext | tag]
  7. Prints KEK hex to stdout ONCE with a clear warning to record it securely
  8. Zeroes all key material in memory before exit

Output:
  keys/kek.bin  → commit to private git repo (already encrypted, safe to store)
  KEK hex       → printed once to stdout; operator writes it down and stores
                  in a physically secure location (e.g. safe or sealed envelope)
                  This is only needed for wallet-signer's first bootstrap and
                  can be destroyed afterwards once all DEKs are in the database.
```

### 12.1 Passphrase Custody

The startup passphrase is held by a **single designated operator**. There is no splitting or distribution. The operator is responsible for:

- Memorising the passphrase or storing it in a personal password manager
- Being available to type it whenever `mini-vault` is restarted
- Never storing it in plaintext on any networked machine
- Keeping it strictly separate from the `kek.bin` backup

The accepted risk of single-person custody is: if the operator is permanently unavailable and the passphrase is lost, the KEK cannot be recovered from `kek.bin`. In that scenario the `kek.bin` must be regenerated, a new KEK produced, and all wallet private keys re-encrypted with the new KEK — a recovery procedure requiring access to the database.

---

## 13. Acceptance Criteria

### Functional

- [ ] Service starts only after correct passphrase entry; wrong passphrase causes immediate exit
- [ ] `GetKEK` returns correct 32-byte KEK to a valid mTLS client
- [ ] `GetKEK` returns `PERMISSION_DENIED` to a client with an unrecognized cert CN
- [ ] `GetKEK` returns `RESOURCE_EXHAUSTED` after exceeding rate limit
- [ ] `HealthCheck` returns `kek_loaded: true` after successful startup
- [ ] Process exits cleanly on SIGTERM, zeroing all memguard buffers

### Security

- [ ] No key material appears in any log line under any log level
- [ ] No key material appears in any gRPC error message or status detail
- [ ] `keys/kek.bin` and `keys/*.key` are absent from git history
- [ ] Core dumps are disabled and verified (`ulimit -c` returns 0)
- [ ] Only port 9000 is open; verified with `ss -tlnp`
- [ ] Client connections without a valid CA-signed cert are rejected at TLS handshake
- [ ] Connections from a cert with wrong CN are rejected after handshake with `PERMISSION_DENIED`

### Operational

- [ ] Service can be built reproducibly from source + embedded key files
- [ ] `vault-keygen` produces a valid `kek.bin` that `mini-vault` can unwrap
- [ ] Systemd unit starts, stops, and does not auto-restart correctly
- [ ] Disaster recovery procedure tested: destroy server → rebuild from git + kek.bin + passphrase → confirm same KEK is served

---

## 14. Disaster Recovery Procedure

If the `mini-vault` server is destroyed or lost, the recovery procedure is:

```
Required materials:
  1. Source code        → clone from private git repo (contains kek.bin already)
  2. Passphrase         → provided by the operator from memory / password manager
  3. TLS certs          → stored in git repo (ca.crt, server.crt, server.key)

Recovery steps:
  1. Provision a new server (same firewall rules, same OS hardening)
  2. Clone the private git repo
  3. Build the binary:  make build
  4. Deploy binary to new server
  5. Start mini-vault, enter passphrase when prompted
  6. Verify HealthCheck returns kek_loaded: true
  7. Verify wallet-signer can fetch KEK successfully
  8. Update firewall rules if the new server has a different IP
```

Because `kek.bin` is committed to the private git repo (it is already encrypted and safe to store there), and TLS certs are also in the repo, a full server rebuild requires only the operator's passphrase and git access. No other out-of-band material is needed.

**What cannot be recovered without the passphrase:** if the passphrase is permanently lost, `kek.bin` cannot be decrypted. In this case a new KEK must be generated, and all wallet private keys in the database must be re-encrypted under the new KEK. This is a serious operational event requiring database-level access and coordination with the `wallet-signer` team.

---

## 15. Out of Scope (v1)

These are explicitly deferred and must not be built into v1:

- KEK rotation without a binary rebuild
- Multiple KEK versions active simultaneously
- Audit log to external storage
- TOTP / hardware token second factor at startup
- Multiple allowed clients / multi-tenant access
- Metrics endpoint (Prometheus etc.)
- Automatic cert rotation
- HA / multi-instance mini-vault

---

## 16. Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | Argon2id vs PBKDF2 for passphrase KDF | Amir | ✅ Resolved — Argon2id (256MB, 3 iterations, 2 parallelism) |
| 2 | Who holds the startup passphrase? | Amir | ✅ Resolved — single operator; no splitting |
| 3 | Recovery procedure if mini-vault server is destroyed | Amir | ✅ Resolved — rebuild from git + passphrase; see §14 |
| 4 | Backup strategy for kek.bin | Amir | ✅ Resolved — committed to private git repo (already encrypted) |