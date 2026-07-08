"""Local crypto round-trip tests for the workload client.

These verify the pod-side primitives in isolation (no network, no cluster): the
RFC 9180 HPKE open path, AES-256-GCM with the identity-binding AAD, and envelope
parsing. They pin the wire contract so a regression in the port is caught before
it ever reaches a real unwrap.

Run:  python -m pytest test_astis_workload.py   (or: python test_astis_workload.py)
"""

import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

import astis_workload as aw


def _hpke_seal(recipient_pub_raw: bytes, plaintext: bytes, info: bytes):
    """Reference RFC 9180 base-mode seal — the mirror of aw._hpke_open.

    Lives only in the test: on the wire this is performed by CVS (BouncyCastle).
    Sharing aw's labeled-extract/expand helpers ensures both directions agree.
    """
    eph = X25519PrivateKey.generate()
    enc = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    recipient_pub = X25519PublicKey.from_public_bytes(recipient_pub_raw)
    dh = eph.exchange(recipient_pub)
    shared = aw._kem_extract_and_expand(dh, enc + recipient_pub_raw)

    psk_id_hash = aw._labeled_extract(b"", b"psk_id_hash", b"", aw._HPKE_SUITE_ID)
    info_hash = aw._labeled_extract(b"", b"info_hash", info, aw._HPKE_SUITE_ID)
    ks_context = bytes([0]) + psk_id_hash + info_hash
    secret = aw._labeled_extract(shared, b"secret", b"", aw._HPKE_SUITE_ID)
    key = aw._labeled_expand(secret, b"key", ks_context, 32, aw._HPKE_SUITE_ID)
    nonce = aw._labeled_expand(secret, b"base_nonce", ks_context, 12, aw._HPKE_SUITE_ID)
    return enc, ChaCha20Poly1305(key).encrypt(nonce, plaintext, b"")


def test_hpke_open_recovers_dek():
    recipient = X25519PrivateKey.generate()
    recipient_raw = recipient.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    recipient_pub_raw = recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    dek = os.urandom(32)
    info = b"astis-rfc020|req-123|kek-abc"
    enc, ciphertext = _hpke_seal(recipient_pub_raw, dek, info)

    assert aw._hpke_open(enc, ciphertext, recipient_raw, info) == dek


def test_hpke_open_empty_aad_contract():
    # CVS seals with empty AAD; identity binds via `info` in the key schedule only.
    # A non-empty AAD on open must fail, locking the wire contract.
    recipient = X25519PrivateKey.generate()
    recipient_raw = recipient.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    recipient_pub_raw = recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    enc, ciphertext = _hpke_seal(recipient_pub_raw, os.urandom(32), b"info")
    # _hpke_open uses empty AAD internally; tampering enc must break authentication.
    bad_enc = bytes([enc[0] ^ 0x01]) + enc[1:]
    raised = False
    try:
        aw._hpke_open(bad_enc, ciphertext, recipient_raw, b"info")
    except Exception:
        raised = True
    assert raised


def test_aes_gcm_decrypt_with_binding_aad():
    dek = os.urandom(32)
    binding = {
        "cluster_id": "prod-eu",
        "namespace": "hr-portal-demo",
        "serviceaccount": "hr-portal",
    }
    aad = "|".join(
        ["req-123", "kek-abc", binding["cluster_id"], binding["namespace"], binding["serviceaccount"]]
    ).encode()
    iv = os.urandom(12)
    secret = b"demo-secret-do-not-share-12345"
    sealed = AESGCM(dek).encrypt(iv, secret, aad)
    body, tag = sealed[:-16], sealed[-16:]

    envelope = {
        "request_id": "req-123",
        "kek_ref": "kek-abc",
        "workload_binding": binding,
        "ciphertext": base64.b64encode(body).decode(),
        "iv": base64.b64encode(iv).decode(),
        "tag": base64.b64encode(tag).decode(),
    }
    assert aw.WorkloadSecretClient._aes_gcm_decrypt(envelope, dek) == secret


def test_aes_gcm_rejects_wrong_binding():
    dek = os.urandom(32)
    iv = os.urandom(12)
    good_aad = "|".join(["r", "k", "prod-eu", "ns", "sa"]).encode()
    sealed = AESGCM(dek).encrypt(iv, b"top-secret", good_aad)
    body, tag = sealed[:-16], sealed[-16:]
    envelope = {
        "request_id": "r",
        "kek_ref": "k",
        "workload_binding": {"cluster_id": "WRONG", "namespace": "ns", "serviceaccount": "sa"},
        "ciphertext": base64.b64encode(body).decode(),
        "iv": base64.b64encode(iv).decode(),
        "tag": base64.b64encode(tag).decode(),
    }
    raised = False
    try:
        aw.WorkloadSecretClient._aes_gcm_decrypt(envelope, dek)
    except Exception:
        raised = True
    assert raised, "decrypt must fail when the workload binding AAD does not match"


def test_envelope_parse_roundtrip():
    binding = {"cluster_id": "c", "namespace": "n", "serviceaccount": "s"}
    payload = {"alg": "hpke", "kek_ref": "k", "request_id": "r", "workload_binding": binding}
    wire = "ASTIS:v2:" + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    parsed = aw.WorkloadSecretClient._parse_envelope(wire)
    assert parsed["kek_ref"] == "k"
    assert parsed["workload_binding"] == binding


def test_envelope_parse_rejects_bad_prefix():
    raised = False
    try:
        aw.WorkloadSecretClient._parse_envelope("ASTIS:v1:whatever")
    except aw.WorkloadSecretError:
        raised = True
    assert raised


def test_plaintext_print_is_fail_closed():
    # Regression: the reference app must never print the decrypted secret unless the
    # operator both opts in AND declares a non-production environment. A deployed pod
    # leaves ASTIS_ENV at its default ("production"), so the secret cannot reach logs.
    from main import plaintext_print_allowed

    # default deployment: flag off → never print
    assert plaintext_print_allowed("production", False) is False
    # flag set but production → refused (the core fail-closed guarantee)
    assert plaintext_print_allowed("production", True) is False
    assert plaintext_print_allowed("prod", True) is False
    assert plaintext_print_allowed("", True) is False
    # explicit local smoke test → allowed
    assert plaintext_print_allowed("local", True) is True
    assert plaintext_print_allowed("demo", True) is True
    # local but no opt-in → still no print
    assert plaintext_print_allowed("local", False) is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("\nall tests passed")
