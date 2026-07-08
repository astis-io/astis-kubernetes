#!/usr/bin/env python3
"""Reference app: an HR portal that needs its DB password at boot.

This is the part you adapt into your own service. The integration is three lines —
construct the client, open the secret, use it, drop the reference:

    client = WorkloadSecretClient()
    db_password = client.open_secret().decode()
    ...                      # open your DB connection
    del db_password          # keep plaintext lifetime short

The client declares NO identity (RFC-020 §12.2): the gateway derives cluster from
the API-key binding and namespace/serviceaccount/pod from the verified SA JWT.

The secret only ever exists in this pod's RAM; the ASTIS edge sees HPKE-sealed
blobs. By default this app NEVER prints the plaintext — `kubectl logs` are read by
DevOps and shipped to Loki/ELK/CloudWatch/Datadog and backups, so printing the
secret there would break the "plaintext only in pod RAM" guarantee. It logs a
sha256 prefix instead, which is enough to confirm a correct decrypt.
"""

import hashlib
import os
import sys

from astis_workload import WorkloadConfig, WorkloadSecretClient, WorkloadSecretError

# The bound API key + projected SA token are read from the standard k8s mounts; the
# client declares no identity (RFC-020 §12.2) — the binding lives on the API key.
API_URL = os.environ.get("ASTIS_API_URL", "https://api.astis.io")

# Printing the decrypted secret is OFF by default and fail-closed. It is honored
# ONLY for a local smoke test: the opt-in flag is ignored unless ASTIS_ENV is
# explicitly non-production. A real deployment never sets ASTIS_ENV=local, so the
# flag is inert there even if someone sets it.
ASTIS_ENV = os.environ.get("ASTIS_ENV", "production")
PRINT_SECRET = os.environ.get("ASTIS_DEMO_PRINT_SECRET") == "true"


def log(step: str, detail: str = "") -> None:
    print(f"[astis] {step:<32} {detail}", flush=True)


def plaintext_print_allowed(astis_env: str, print_flag: bool) -> bool:
    """Whether the decrypted secret may be printed to stdout.

    Fail-closed: the plaintext is printed ONLY when the operator both opts in
    (``print_flag``) AND declares a non-production environment. A deployed pod
    leaves ``astis_env`` at its default ("production"), so the secret can never
    reach ``kubectl logs`` there even if the flag is set.
    """
    return print_flag and astis_env.lower() not in ("production", "prod", "")


def main() -> int:
    log("ASTIS Workload Secret Layer", "RFC-020 zero-knowledge pod boot")
    log("api", API_URL)

    client = WorkloadSecretClient(WorkloadConfig(api_url=API_URL))

    try:
        secret = client.open_secret().decode()
    except WorkloadSecretError as exc:
        log("FAILED", str(exc))
        # A denied layer (e.g. unapproved image digest) lands here as an HTTP 403.
        return 1

    # Default: prove a correct decrypt WITHOUT exposing the plaintext.
    digest = hashlib.sha256(secret.encode()).hexdigest()
    log("decrypted successfully", f"sha256={digest[:12]}…  ({len(secret)} chars)")
    log("edge saw", "only HPKE-sealed blobs — plaintext never left this pod")

    if plaintext_print_allowed(ASTIS_ENV, PRINT_SECRET):
        # LOCAL SMOKE TEST ONLY — never enable in a deployed pod.
        print("\n" + "=" * 64, flush=True)
        print(f"  DB_PASSWORD = {secret}", flush=True)
        print("=" * 64 + "\n", flush=True)
    elif PRINT_SECRET:
        log(
            "print flag ignored",
            "ASTIS_DEMO_PRINT_SECRET refused unless ASTIS_ENV is non-production",
        )

    # In a real app you would now open your database connection and discard the
    # plaintext. We keep the pod alive so the demo stays observable.
    del secret
    log("done", "sleeping to keep the demo pod alive…")
    try:
        import time

        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
