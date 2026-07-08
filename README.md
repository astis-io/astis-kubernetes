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

## Charts

| Chart | Status | What it deploys |
|---|---|---|
| [astis-workload-secrets](./charts/astis-workload-secrets/) | ✅ ready | Your workload wired for ASTIS: bound API key + projected SA token + sealed envelopes, both integration paths (SDK in code, or `astis-exec` for unmodified apps). Same wiring as the example, templated. |

Examples are self-contained and runnable. Each carries its own copy of the pod
client and conforms to the `ASTIS:v2` wire contract — correctness is proven against
the live `api.astis.io`, not by importing the SDK.

## What's next

More delivery modes are planned — per-environment GitOps overlays,
ESO / CSI integrations. Need one sooner?
[Open an issue](https://github.com/astis-io/astis-kubernetes/issues) — real demand
moves things up the list.

## Conventions

- Never commit plaintext or API keys. Synthetic ciphertext for demos may be committed
  intentionally (it is safe to version).
- Security claims differ per delivery mode — do not conflate pod-side unseal (strong)
  with ESO/native-Secret (compatibility).
