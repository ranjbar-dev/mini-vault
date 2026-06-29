# mini-vault

Minimal Go microservice that holds the Key Encryption Key (KEK) in a
memguard-protected RAM enclave and serves it exclusively to `wallet-signer`
over mutually authenticated TLS gRPC.

> **This service must run on a separate server from `wallet-signer`.**
> A compromise of the signer server must not expose the KEK.

---

## First-time setup

### 1. Generate TLS certificates

Run on an offline workstation. The CA private key must never touch a server.

```sh
# CA
openssl genrsa -out keys/ca.key 4096
openssl req -x509 -new -nodes -key keys/ca.key -sha256 -days 3650 \
    -subj "/CN=mini-vault-ca" -out keys/ca.crt

# Server cert (mini-vault)
openssl genrsa -out keys/server.key 4096
openssl req -new -key keys/server.key \
    -subj "/CN=mini-vault" -out keys/server.csr
openssl x509 -req -in keys/server.csr -CA keys/ca.crt -CAkey keys/ca.key \
    -CAcreateserial -days 3650 -sha256 -out keys/server.crt

# Client cert (wallet-signer) — CN must match VAULT_CLIENT_CN
openssl genrsa -out keys/client.key 4096
openssl req -new -key keys/client.key \
    -subj "/CN=wallet-signer" -out keys/client.csr
openssl x509 -req -in keys/client.csr -CA keys/ca.crt -CAkey keys/ca.key \
    -CAcreateserial -days 3650 -sha256 -out keys/client.crt
```

Place `ca.crt`, `server.crt`, and `server.key` in `keys/`.
Place `ca.crt`, `client.crt`, and `client.key` on the `wallet-signer` server.
Store `ca.key` in cold storage — never on any server.

### 2. Generate the wrapped KEK

```sh
make keygen
# or: go run ./cmd/vault-keygen --out keys/kek.bin --version v1
```

- Type a strong passphrase twice (no echo).
- The KEK hex is printed once to stdout — write it down and store it in a
  physically secure location (safe, sealed envelope). It is needed if you
  ever need to re-encrypt wallet keys under a new KEK.
- `keys/kek.bin` is now created. **Commit it** — it is encrypted and safe
  to store in a private git repo.

### 3. Build and deploy

```sh
make build
# outputs: bin/mini-vault  bin/vault-keygen

# copy to server
scp bin/mini-vault vault-svc@mini-vault-host:/usr/local/bin/
scp deploy/mini-vault.service root@mini-vault-host:/etc/systemd/system/

# on the server
systemctl daemon-reload
systemctl enable mini-vault
systemctl start mini-vault
# enter passphrase when prompted via the TTY or ExecStartPre helper
```

---

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|---|---|---|
| `VAULT_PORT` | `9000` | gRPC listen port |
| `VAULT_CLIENT_CN` | `wallet-signer` | Expected CN on client certificate |
| `VAULT_KEK_VERSION` | `v1` | KEK version to match in requests |
| `VAULT_RATE_LIMIT_RPM` | `5` | Max `GetKEK` calls per 60 s per client |
| `VAULT_LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |

---

## Disaster Recovery Procedure

> From PRD §14 — follow exactly.

**Required materials:**
1. Source code → clone from private git repo (contains `kek.bin` already)
2. Passphrase → provided by the operator from memory / password manager
3. TLS certs → stored in git repo (`ca.crt`, `server.crt`, `server.key`)

**Recovery steps:**
1. Provision a new server (same firewall rules, same OS hardening)
2. Clone the private git repo
3. Build the binary: `make build`
4. Deploy binary to new server
5. Start mini-vault, enter passphrase when prompted
6. Verify `HealthCheck` returns `kek_loaded: true`
7. Verify `wallet-signer` can fetch KEK successfully
8. Update firewall rules if the new server has a different IP

**What cannot be recovered without the passphrase:** if the passphrase is
permanently lost, `kek.bin` cannot be decrypted. A new KEK must be generated
and all wallet private keys in the database re-encrypted. This is a serious
operational event requiring database-level access and coordination with the
`wallet-signer` team.

---

## Security notes

- Run as a dedicated non-root user (`vault-svc`)
- Disable core dumps: `ulimit -c 0` / `LimitCORE=0` in the unit file
- Disable swap: `swapoff -a` (prevents memguard pages from hitting disk)
- Firewall: allow **only** inbound TCP 9000 from the `wallet-signer` IP
- `Restart=no` is intentional — automatic restart would require a cached
  passphrase, defeating the protection
