"""ASTIS Workload Secret client — decrypt a sealed secret inside a Kubernetes pod.

This is the app-level "CTL": drop this single file into your service and call

    from astis_workload import WorkloadSecretClient
    plaintext = WorkloadSecretClient().open_secret()

`open_secret()` performs the full RFC-020 zero-knowledge round trip:

  1. Generate ephemeral Ed25519 (DPoP) + X25519 (KEM) keypairs — in RAM only,
     once per pod (RFC-020 pins a single credential per pod UID).
  2. POST /v1/workload/session/init  — register ONLY the ephemeral pubkeys. The
     client declares no identity (RFC-020 §12.2): the gateway derives cluster from
     the API-key binding and namespace/serviceaccount/pod from the verified SA JWT.
  3. Parse the sealed envelope (`ASTIS:v2:...`) mounted as a k8s Secret.
  4. POST /v1/workload/unwrap        — send ONLY the wrapped-DEK material and a
     DPoP proof. Ciphertext, IV and tag never leave the pod.
  5. HPKE-open the DEK that CVS re-wrapped to this pod's ephemeral X25519 pubkey.
  6. AES-256-GCM decrypt the ciphertext locally.

The ASTIS edge never sees plaintext or the bare DEK — only HPKE-sealed blobs.
The API key is the entry credential, but it is one of four enforcement layers
(key binding, SA JWT, DPoP, image digest): an API key plus cluster root is not
enough to recover the secret.

Crypto is RFC 9180 HPKE base mode (DHKEM-X25519-HKDF-SHA256 + ChaCha20-Poly1305)
implemented on top of `cryptography` primitives, matched byte-for-byte to the
server-side BouncyCastle contract. Do not change the suite IDs, the empty-AAD
convention, or the `info` string without changing CVS in lockstep.

Requires: cryptography>=42.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

__all__ = ["WorkloadConfig", "WorkloadSecretClient", "WorkloadSecretError"]

_USER_AGENT = "astis-workload-client/1.0"
_ENVELOPE_PREFIX = "ASTIS:v2:"

# Standard mount paths used by the reference Deployment. Override via WorkloadConfig
# if your manifest mounts them elsewhere.
_DEFAULT_API_KEY_PATH = "/etc/astis/api-key"
_DEFAULT_ENVELOPE_PATH = "/etc/astis-sealed/envelope"
_DEFAULT_SA_TOKEN_PATH = "/var/run/secrets/astis-audience/token"  # projected, aud=astis.io


class WorkloadSecretError(RuntimeError):
    """Raised when the workload unwrap flow fails (HTTP error, denied layer, bad envelope)."""


# --------------------------------------------------------------------------- #
# RFC 9180 HPKE base mode: DHKEM-X25519-HKDF-SHA256 (0x0020) +                 #
# HKDF-SHA256 (0x0001) + ChaCha20-Poly1305 (0x0003).                          #
# --------------------------------------------------------------------------- #

_HPKE_SUITE_ID = b"HPKE" + bytes.fromhex("00200001") + bytes.fromhex("0003")
_KEM_SUITE_ID = b"KEM" + bytes.fromhex("0020")


def _i2osp(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    # HKDF-Extract = HMAC-SHA256(salt, ikm); an empty salt is the 32-byte zero vector.
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes, suite_id: bytes) -> bytes:
    return _hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(prk: bytes, label: bytes, info: bytes, length: int, suite_id: bytes) -> bytes:
    labeled_info = _i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=labeled_info).derive(prk)


def _kem_extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = _labeled_extract(b"", b"eae_prk", dh, _KEM_SUITE_ID)
    return _labeled_expand(eae_prk, b"shared_secret", kem_context, 32, _KEM_SUITE_ID)


def _hpke_open(enc: bytes, ciphertext: bytes, recipient_priv_raw: bytes, info: bytes) -> bytes:
    """Single-shot HPKE base-mode open (seq=0). Returns the decrypted payload (the DEK)."""
    recipient_priv = X25519PrivateKey.from_private_bytes(recipient_priv_raw)
    enc_pub = X25519PublicKey.from_public_bytes(enc)

    # Decap
    dh = recipient_priv.exchange(enc_pub)
    recipient_pub_raw = recipient_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared_secret = _kem_extract_and_expand(dh, enc + recipient_pub_raw)

    # KeySchedule, mode_base (0x00), empty psk / psk_id.
    psk_id_hash = _labeled_extract(b"", b"psk_id_hash", b"", _HPKE_SUITE_ID)
    info_hash = _labeled_extract(b"", b"info_hash", info, _HPKE_SUITE_ID)
    key_schedule_context = bytes([0]) + psk_id_hash + info_hash
    secret = _labeled_extract(shared_secret, b"secret", b"", _HPKE_SUITE_ID)
    key = _labeled_expand(secret, b"key", key_schedule_context, 32, _HPKE_SUITE_ID)
    base_nonce = _labeled_expand(secret, b"base_nonce", key_schedule_context, 12, _HPKE_SUITE_ID)

    # seq=0 for the first and only open → base_nonce used directly (no XOR).
    # AAD is empty by contract: identity binds through `info` in the key schedule.
    return ChaCha20Poly1305(key).decrypt(base_nonce, ciphertext, b"")


# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


@dataclass
class WorkloadConfig:
    """Where the pod's credentials live.

    The client declares NO identity (RFC-020 §12.2): only the bound API key and the
    projected SA token are read. The gateway derives cluster from the API-key binding
    and namespace/serviceaccount/pod from the verified SA JWT.
    """

    api_url: str = "https://api.astis.io"

    api_key_path: str = _DEFAULT_API_KEY_PATH
    envelope_path: str = _DEFAULT_ENVELOPE_PATH
    sa_token_path: str = _DEFAULT_SA_TOKEN_PATH

    http_timeout_seconds: float = 15.0


# --------------------------------------------------------------------------- #
# Client                                                                       #
# --------------------------------------------------------------------------- #


class WorkloadSecretClient:
    """Decrypts ASTIS sealed secrets from inside a bound Kubernetes pod.

    Typical use::

        client = WorkloadSecretClient()
        db_password = client.open_secret().decode()

    One workload session (DPoP + KEM keypair) is established per pod and reused for
    every secret — RFC-020 pins a single credential per pod UID, so a second
    session/init with a different keypair would be rejected (binding_mismatch).
    """

    def __init__(self, config: Optional[WorkloadConfig] = None) -> None:
        self.config = config or WorkloadConfig()

        # One workload session per pod, established lazily and reused.
        self._api_key: Optional[str] = None
        self._sa_jwt: Optional[str] = None
        self._sig_priv: Optional[Ed25519PrivateKey] = None
        self._kem_priv_raw: Optional[bytes] = None
        self._session_id: Optional[str] = None

    # -- public API -------------------------------------------------------- #

    def open_secret(self, envelope_wire: Optional[str] = None) -> bytes:
        """Run the full unwrap flow and return the decrypted secret bytes.

        ``envelope_wire`` is the ``ASTIS:v2:...`` string; when omitted it is read from
        ``config.envelope_path``. Raises :class:`WorkloadSecretError` on any failure.
        """
        envelope = self._parse_envelope(envelope_wire or _read(self.config.envelope_path))
        self._ensure_session()
        rewrap = self._unwrap(envelope, self._session_id)
        dek = self._hpke_open_dek(envelope, rewrap)
        try:
            return self._aes_gcm_decrypt(envelope, dek)
        finally:
            # Best-effort scrub of the DEK reference; CPython can't truly zeroize an
            # immutable bytes object, so keep DEK lifetime as short as possible.
            del dek

    # -- flow steps -------------------------------------------------------- #

    def _ensure_session(self) -> None:
        """Establish the pod's single workload session once; reuse it for all unwraps."""
        if self._session_id is not None:
            return
        self._api_key = _read(self.config.api_key_path)
        self._sa_jwt = _read(self.config.sa_token_path)

        self._sig_priv = Ed25519PrivateKey.generate()
        sig_pub_b64 = base64.b64encode(
            self._sig_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        kem_priv = X25519PrivateKey.generate()
        self._kem_priv_raw = kem_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        kem_pub_b64 = base64.b64encode(
            kem_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        self._session_id = self._session_init(sig_pub_b64, kem_pub_b64)

    def _session_init(self, sig_pub_b64: str, kem_pub_b64: str) -> str:
        # RFC-020 §12.2: the client declares NO identity — the gateway derives it from
        # the API-key binding + the verified SA JWT. Send only the ephemeral pod pubkeys.
        body = {"podPubkey": sig_pub_b64, "podKemPubkey": kem_pub_b64}
        status, resp = self._post(
            "/v1/workload/session/init",
            {"Authorization": f"Bearer {self._api_key}", "X-Workload-Proof": self._sa_jwt},
            json.dumps(body).encode(),
        )
        if status != 200:
            raise WorkloadSecretError(f"session/init failed: HTTP {status} {resp}")
        return resp["session_id"]

    def _unwrap(self, envelope: dict, session_id: str) -> dict:
        # Phase 1.7 contract: send ONLY the DEK wrap material + binding metadata.
        # ciphertext / iv / tag stay in the pod and never cross the ASTIS edge.
        unwrap_body = {
            "encap_b64": envelope["encap_b64"],
            "wrapped_dek_b64": envelope["wrapped_dek_b64"],
            "kek_ref": envelope["kek_ref"],
            "request_id": envelope["request_id"],
            "workload_binding": envelope["workload_binding"],
        }
        raw = json.dumps(unwrap_body, separators=(",", ":")).encode()

        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(12)
        body_hash = hashlib.sha256(raw).hexdigest()
        canonical = f"POST\n/v1/workload/unwrap\n{body_hash}\n{timestamp}\n{nonce}".encode()
        dpop_sig = base64.b64encode(self._sig_priv.sign(canonical)).decode()

        status, resp = self._post(
            "/v1/workload/unwrap",
            {
                "Authorization": f"Bearer {self._api_key}",
                "X-Workload-Proof": self._sa_jwt,
                "X-Astis-Session": session_id,
                "X-Pod-Signature": dpop_sig,
                "X-Pod-Timestamp": timestamp,
                "X-Pod-Nonce": nonce,
            },
            raw,
        )
        if status != 200:
            raise WorkloadSecretError(f"unwrap failed: HTTP {status} {resp}")
        return resp

    def _hpke_open_dek(self, envelope: dict, rewrap: dict) -> bytes:
        enc = base64.b64decode(rewrap["kemEncapsulatedKeyB64"])
        ciphertext = base64.b64decode(rewrap["kemCiphertextB64"])
        info = (
            "astis-rfc020|" + envelope["request_id"] + "|" + envelope["kek_ref"]
        ).encode()
        return _hpke_open(enc, ciphertext, self._kem_priv_raw, info)

    @staticmethod
    def _aes_gcm_decrypt(envelope: dict, dek: bytes) -> bytes:
        ciphertext = base64.b64decode(envelope["ciphertext"])
        iv = base64.b64decode(envelope["iv"])
        tag = base64.b64decode(envelope["tag"])
        # Extended AAD cryptographically binds the workload identity to the ciphertext.
        # It must match exactly what SecOps used at encrypt time.
        binding = envelope["workload_binding"]
        aad = "|".join(
            [
                envelope["request_id"],
                envelope["kek_ref"],
                binding["cluster_id"],
                binding["namespace"],
                binding["serviceaccount"],
            ]
        ).encode()
        return AESGCM(dek).decrypt(iv, ciphertext + tag, aad)

    # -- helpers ----------------------------------------------------------- #

    @staticmethod
    def _parse_envelope(wire: str) -> dict:
        if not wire.startswith(_ENVELOPE_PREFIX):
            raise WorkloadSecretError(f"envelope missing {_ENVELOPE_PREFIX} prefix")
        encoded = wire[len(_ENVELOPE_PREFIX) :]
        try:
            return json.loads(base64.urlsafe_b64decode(encoded + "==").decode())
        except (ValueError, json.JSONDecodeError) as exc:
            raise WorkloadSecretError(f"malformed sealed envelope: {exc}") from exc

    def _post(self, path: str, headers: dict, body: bytes) -> tuple[int, dict]:
        request = urllib.request.Request(
            self.config.api_url + path,
            data=body,
            headers={"User-Agent": _USER_AGENT, "Content-Type": "application/json", **headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.http_timeout_seconds) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read())
            except (ValueError, json.JSONDecodeError):
                payload = {"error": exc.reason}
            return exc.code, payload
        except urllib.error.URLError as exc:
            raise WorkloadSecretError(f"cannot reach {self.config.api_url}{path}: {exc.reason}") from exc
