# Decrypt a secret inside a Kubernetes pod (RFC-020 pod-side unseal)

A complete, runnable example of an app that boots inside a Kubernetes pod and
recovers its database password **in pod memory only**. Ciphertext is all that lives
in the cluster; the plaintext is reconstructed inside the running container and
never crosses the ASTIS edge.

The Python, Go, and Node.js examples are **self-contained** — each ships its own copy of
the pod client and depends on nothing outside this repository. The Java / Spring Boot
example instead consumes **`astis-spring-boot-starter`** (from the astis-sdk
repo) as a Maven dependency — the productized integration: add a dependency, map a few
properties, ship no ASTIS code. All implementations conform to the ASTIS `ASTIS:v2` wire
contract and are verified by a cross-language known-answer test against the Python
reference, so any language opens what any other (and CVS) sealed.

> For the reusable, importable client (to integrate ASTIS into your own code), see
> the **astis-sdk** repository. This repo answers "how do I run it in a cluster?";
> astis-sdk answers "how do I program against ASTIS?".

## Languages

| Language | Crypto | What it shows | Directory |
|---|---|---|---|
| Python | inline RFC 9180 (`cryptography`) | A pod boots, decrypts `DB_PASSWORD` in RAM, logs only a sha256 prefix. | [`python/`](./python/) |
| Java / Spring Boot | BouncyCastle HPKE (via `astis-spring-boot-starter`) | Adds the starter dependency; its `EnvironmentPostProcessor` decrypts credentials at startup and injects them as Spring properties, so the **DataSource connection factory** consumes them with no code change. App ships no ASTIS code. Connects to real Postgres. | [`java-springboot/`](./java-springboot/) |
| Go | Cloudflare CIRCL HPKE | Self-contained client; decrypts DB creds, connects to Postgres, `select version()`. | [`go/`](./go/) |
| Node.js | inline RFC 9180 (Node `crypto`) | Self-contained client; decrypts DB creds, connects to Postgres, `select version()`. | [`nodejs/`](./nodejs/) |

All four implement the **same `ASTIS:v2` wire contract** and are cross-checked by a
known-answer test: the Python reference seals `kat-fixture.json`, and every language opens
it — so any language decrypts what any other (and CVS) sealed. The Kubernetes wiring in
[`base/`](./base/) is **language-agnostic** — only the container image differs per language.

---

## What it protects — be precise

**Protects against** passive cluster read access, GitOps/Git leaks, and `etcd`
backups: all of these see **ciphertext only**. The data-encryption key is rewrapped
by CVS to the pod's ephemeral key and opened in RAM; the ASTIS edge sees only
HPKE-sealed blobs.

**Does NOT protect** the plaintext after it has been revealed inside an authorized
workload. An attacker with **active** access — `kubectl exec` into the running pod,
node-root / memory inspection, full control-plane compromise, or theft of the
pod's service-account credentials — can reach the decrypted value. Mitigate with
distroless images, RBAC `deny exec`, and (for control-plane threats) confidential
computing.

So the honest one-liner is: **passive infrastructure access yields ciphertext;
active workload compromise is out of scope.** It separates *data trust* from
*passive infrastructure trust* — not from a live attacker already inside the pod.

---

## How it works

```
 pod (your app)                         api.astis.io                 CVS
 ──────────────                         ────────────                 ───
 1. read api-key + SA-JWT + envelope
 2. gen ephemeral Ed25519 + X25519  ──▶ POST /v1/workload/session/init
                                        ├─ verify API-key binding   (Layer 1)
                                        ├─ verify SA-JWT via JWKS    (Layer 2)
                                        ├─ JWT claims == declared id (Layer 3)
                                        └─ k8s API: image digest ok  (Layer 4)
 3. send wrapped-DEK + DPoP proof   ──▶ POST /v1/workload/unwrap  ──▶ HPKE-decap DEK,
    (ciphertext NEVER sent)                                          re-seal to pod pubkey
 4. HPKE-open DEK with ephemeral X25519 privkey  (RAM only)  ◀────────┘
 5. AES-256-GCM decrypt ciphertext locally
 6. use secret, drop the reference
```

The API key is the entry credential (Layer 1), but it is one of four enforcement
layers. The request must come from the bound pod (cluster + namespace + service
account) running an **approved image digest**, read directly from your k8s API.

Crypto is RFC 9180 HPKE base mode (DHKEM-X25519-HKDF-SHA256 + ChaCha20-Poly1305)
plus AES-256-GCM with an AAD that binds the workload identity to the ciphertext.

---

## What the pod consumes

| Mount | Source | Purpose |
|---|---|---|
| `/etc/astis/api-key` | Secret `astis-api-key` | bound API key (Layer 1) |
| `/var/run/secrets/astis-audience/token` | projected SA token, `audience=astis.io` | identity proof (Layer 2) |
| `/etc/astis-sealed/envelope` | Secret `astis-sealed-db-password` | sealed envelope (**ciphertext**) |

See [`base/`](./base/) for the exact manifests.

---

## Run it

### 1. Provision (one-time, in the portal)
- Register your cluster (k8s API URL + read-only token) so ASTIS can verify image digests.
- Create a **bound API key**: cluster + namespace + service account + approved image digest(s).
- Scope: `workload:session.init` + `workload:cvs.unwrap`. Environment: `live`.

### 2. Seal the secret (encrypt side, SecOps)
The sealed envelope is produced with your **org public key**, bound to the workload,
using astis-cli / the SDK. This example covers the **decrypt** (pod) side.

### 3. Build the image and deploy
```bash
cd python && docker build -t registry.example.com/hr-portal:1.0 . && docker push registry.example.com/hr-portal:1.0
# (or: cd java-springboot && docker build ...)
# approve the resulting @sha256:... digest in the portal (Layer 4)

kubectl apply -f base/00-namespace.yaml
kubectl apply -f base/10-rbac.yaml
# create the two secrets (see base/20-secrets.example.yaml header for commands)
kubectl apply -f base/30-deployment.yaml
kubectl -n hr-portal-demo logs -f deploy/hr-portal
```

Expected tail (the plaintext is **never** logged):
```
[astis] decrypted successfully          sha256=2f4a9c1b7e0d…  (29 chars)
[astis] edge saw                        only HPKE-sealed blobs — plaintext never left this pod
```
For a **local** smoke test only, you may print the plaintext with
`ASTIS_DEMO_PRINT_SECRET=true` **and** `ASTIS_ENV=local`; the flag is refused
(fail-closed) when `ASTIS_ENV` is production.

### 4. Prove the boundary
Redeploy with an **unapproved** image (same namespace, SA, API key, sealed secret —
only the image changes). `POST /v1/workload/unwrap` returns **HTTP 403
`image_digest_mismatch`** and the secret is never recovered.

---

## Test (no cluster needed)
```bash
cd python && pip install -r requirements.txt && python test_astis_workload.py
# Java: cd java-springboot && mvn test   (runs the cross-language KAT)
```
Verifies the RFC 9180 HPKE open path, the empty-AAD wire contract, AES-GCM with the
identity-binding AAD, envelope parsing, and the fail-closed plaintext-print guard.
