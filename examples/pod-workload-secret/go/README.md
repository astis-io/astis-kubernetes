# pod-workload-secret — Go

Self-contained RFC-020 workload-secret client in Go. Decrypts the PostgreSQL credentials
from ASTIS at startup and opens a real connection — mirroring the Java/Spring Boot and
Python examples. See the [use-case overview](../README.md) for the concept, the four-layer
model, and the threat model.

HPKE is RFC 9180 base mode (DHKEM-X25519-HKDF-SHA256 + ChaCha20-Poly1305) via
[Cloudflare CIRCL](https://github.com/cloudflare/circl); the payload is AES-256-GCM with an
AAD that binds the workload identity. Same `ASTIS:v2` wire contract as every other example.

## Use it in your app

```go
// No identity args (RFC-020 §12.2): the gateway derives cluster from the API-key
// binding and namespace/serviceaccount/pod from the verified SA JWT (pod mounts).
client, _ := astisFromKubernetes("https://api.astis.io")
pw, _ := client.OpenSecret(string(must(os.ReadFile("/etc/astis-sealed/db-password"))))
// pw is plaintext, only in this process's RAM
```

`OpenSecret` establishes one workload session per pod (RFC-020 pins a single credential
per pod UID) and reuses it for every secret.

## Files

| File | Role |
|---|---|
| `astis_workload.go` | the reusable client (CIRCL HPKE + AES-GCM + Ed25519 DPoP + flow + mounts) |
| `main.go` | demo: decrypt DB creds, connect to PostgreSQL, `select version()` |
| `astis_workload_test.go` | cross-language KAT against `kat-fixture.json` |

## Test (no cluster needed)

```bash
go test ./...
```
Opens the Python-sealed `kat-fixture.json`, and checks that a tampered binding AAD and a
corrupted HPKE encapsulation are rejected.

## Build & deploy

```bash
docker build -t registry.example.com/workload-go:1.0 .
docker push registry.example.com/workload-go:1.0   # approve the @sha256:... digest in the portal
```
Then deploy with the shared manifests in [`../base/`](../base/) (swap the image and the SA).
The secret is never logged — only a sha256 prefix; set `ASTIS_ENV=local` +
`ASTIS_DEMO_PRINT_SECRET=true` for a local smoke test only.
