# ASTIS for Kubernetes

**Runnable examples** of [ASTIS Workload Secrets](https://astis.io/workload-secrets)
in a real cluster. What it does in one sentence: your pod decrypts its secret **in
its own RAM**, after four-layer workload attestation — while everything stored in
the cluster (Kubernetes Secrets, etcd, backups, Git) stays **ciphertext**, so
infrastructure access no longer means secret access.

**Start here →** [`examples/pod-workload-secret`](./examples/pod-workload-secret/):
a complete, deployable example — base manifests plus the same app in
**Python / Go / Node.js / Java+Spring Boot** that boots, opens its DB password in
pod memory only, and connects to a real PostgreSQL with it. `kubectl get secret`
and an etcd backup show only sealed `ASTIS:v2:…` blobs; the repo itself contains
placeholders, never real credentials.

This repo answers **"how do I run ASTIS in a cluster?"**. Related:

- [`astis-sdk`](https://github.com/astis-io/astis-sdk) — the importable client
  libraries ("how do I program against ASTIS?"). The two repos evolve
  independently and share only the `ASTIS:v2` wire contract; nothing here
  imports SDK code.
- [10-minute quickstart](https://astis.io/workload-secrets/quickstart) — the
  no-code-changes path (`astis-exec` wraps an unmodified app).
- [How it works / architecture](https://astis.io/workload-secrets).

## Examples

| Example | Status | What it shows |
|---|---|---|
| [pod-workload-secret](./examples/pod-workload-secret/) | ✅ ready | An app inside a pod decrypts its secret in pod RAM (RFC-020). Passive cluster/Git/etcd access sees ciphertext only. Self-contained; proven by live round trip. |

Examples are self-contained and runnable. Each carries its own copy of the pod
client and conforms to the `ASTIS:v2` wire contract — correctness is proven against
the live `api.astis.io`, not by importing the SDK.

## Roadmap (not yet present — added when work starts)

- `examples/pod-workload-secret/overlays/{dev,staging,prod}` — GitOps demo: distinct
  synthetic ciphertext committed per environment (ciphertext is safe to version; the
  API key is not).
- `integrations/external-secrets` — ESO provider (native Secret **compatibility** mode;
  weaker trust boundary — plaintext lands in `etcd`).
- `integrations/csi` — CSI / mounted-file delivery (no native Secret).
- `charts/astis-workload-secrets` — Helm chart.

## Conventions

- Never commit plaintext or API keys. Synthetic ciphertext for demos may be committed
  intentionally (it is safe to version).
- Security claims differ per delivery mode — do not conflate pod-side unseal (strong)
  with ESO/native-Secret (compatibility).
