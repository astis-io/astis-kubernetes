# pod-workload-secret — Node.js

Self-contained RFC-020 workload-secret client in Node.js. Decrypts the PostgreSQL
credentials from ASTIS at startup and opens a real connection — mirroring the
Java/Spring Boot, Go, and Python examples. See the [use-case overview](../README.md) for
the concept, the four-layer model, and the threat model.

HPKE is RFC 9180 base mode (DHKEM-X25519-HKDF-SHA256 + ChaCha20-Poly1305) implemented on
Node's built-in `crypto` primitives (no third-party crypto dependency); the payload is
AES-256-GCM with an AAD that binds the workload identity. Same `ASTIS:v2` wire contract as
every other example.

## Use it in your app

```js
import { fromKubernetes } from "./astis-workload.js";

// No identity args (RFC-020 §12.2): the gateway derives cluster from the API-key
// binding and namespace/serviceaccount/pod from the verified SA JWT (pod mounts).
const client = fromKubernetes("https://api.astis.io");
const pw = await client.openSecret(fs.readFileSync("/etc/astis-sealed/db-password", "utf8").trim());
// pw is a Buffer, plaintext only in this process's RAM
```

`openSecret` establishes one workload session per pod (RFC-020 pins a single credential
per pod UID) and reuses it for every secret.

## Files

| File | Role |
|---|---|
| `astis-workload.js` | the reusable client (inline HPKE + AES-GCM + Ed25519 DPoP + flow + mounts) |
| `main.js` | demo: decrypt DB creds, connect to PostgreSQL (`pg`), `select version()` |
| `astis-workload.test.js` | cross-language KAT against `kat-fixture.json` |

## Test (no cluster, no DB, no install)

```bash
node --test
```
The crypto test depends only on Node's `crypto`; it opens the Python-sealed
`kat-fixture.json` and checks that a tampered binding AAD and a corrupted HPKE
encapsulation are rejected. (`npm install` is only needed to run the demo, which uses `pg`.)

## Build & deploy

```bash
docker build -t registry.example.com/workload-node:1.0 .
docker push registry.example.com/workload-node:1.0   # approve the @sha256:... digest in the portal
```
Then deploy with the shared manifests in [`../base/`](../base/) (swap the image and the SA).
The secret is never logged — only a sha256 prefix; set `ASTIS_ENV=local` +
`ASTIS_DEMO_PRINT_SECRET=true` for a local smoke test only.
