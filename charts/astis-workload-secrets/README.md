# astis-workload-secrets (Helm chart)

Deploys **your workload wired for ASTIS Workload Secrets**: bound API key +
projected ServiceAccount token + sealed envelopes mounted read-only. The pod
decrypts its secrets **in RAM** after four-layer attestation; everything stored
in the cluster stays ciphertext. Same wiring as
[`examples/pod-workload-secret`](../../examples/pod-workload-secret/), templated.

The chart intentionally does **not** create the API key or the envelopes — those
are created out-of-band (portal + `astis-cli` / an SDK seal helper) and
referenced by name. Never put plaintext or a real API key into values files.

## Install

```bash
helm install my-app ./charts/astis-workload-secrets \
  --namespace my-namespace \
  --set image.repository=registry.example.com/my-app \
  --set image.digest=sha256:… \
  --set astis.apiKeySecret=astis-api-key \
  --set astis.sealedSecrets[0].secretName=astis-sealed-db-password \
  --set astis.sealedSecrets[0].fileName=db-password
```

## The two integration paths

- **SDK in code (Path B)** — leave `command` empty; your app calls
  `fromKubernetes().openSecret()` and reads `/etc/astis-sealed/<fileName>`.
- **Unmodified app (Path A)** — wrap it with astis-exec:
  `command: ["astis-exec", "--fork", "--", "./my-app"]` and pass envelopes as
  env vars instead of (or alongside) mounts.

## Key values

| Value | Meaning |
|---|---|
| `serviceAccount.name` | Workload identity; part of the API-key binding (default: release name) |
| `image.digest` | Pin the image by digest — must match the digest approved in the portal (Layer 4) |
| `astis.apiKeySecret` | Existing Secret with the bound API key under key `api-key` |
| `astis.sealedSecrets[]` | `{secretName, key (default "envelope"), fileName}` → mounted at `/etc/astis-sealed/<fileName>` |
| `command` | Empty = SDK path; `["astis-exec", …]` = unmodified-app path |
| `env` | Plain, non-secret config only (DB hosts, ports) |

See `values.yaml` for the full list.

## Verify

```bash
helm template my-app ./charts/astis-workload-secrets | kubectl apply --dry-run=client -f -
kubectl get secret <sealed-secret> -o jsonpath='{.data.envelope}' | base64 -d
# -> ASTIS:v2:… — ciphertext, not a usable secret
```
