// Self-contained RFC-020 workload-secret client for Node.js.
//
// Decrypts an ASTIS sealed secret from inside a Kubernetes pod, targeting the same
// ASTIS:v2 wire contract as the Python/Java/Go examples (verified by a cross-language
// known-answer test). HPKE is RFC 9180 base mode (DHKEM-X25519-HKDF-SHA256 +
// ChaCha20-Poly1305) implemented on Node's crypto primitives; the payload is
// AES-256-GCM with an AAD that binds the workload identity. The ASTIS edge never sees
// plaintext or the bare DEK.

import crypto from "node:crypto";
import fs from "node:fs";

const DEFAULT_API_URL = "https://api.astis.io";
const ENVELOPE_PREFIX = "ASTIS:v2:";

// ---- RFC 9180 HPKE base mode: DHKEM-X25519 (0x0020) + HKDF-SHA256 (0x0001) +
// ChaCha20-Poly1305 (0x0003). ----
const HPKE_SUITE = Buffer.concat([Buffer.from("HPKE"), Buffer.from("00200001", "hex"), Buffer.from("0003", "hex")]);
const KEM_SUITE = Buffer.concat([Buffer.from("KEM"), Buffer.from("0020", "hex")]);

const i2osp = (n, l) => { const b = Buffer.alloc(l); b.writeUIntBE(n, 0, l); return b; };
const extract = (salt, ikm) =>
  crypto.createHmac("sha256", salt.length ? salt : Buffer.alloc(32)).update(ikm).digest();
// single-block HKDF-expand (output length <= 32, which covers key=32 and nonce=12)
const expand = (prk, info, L) =>
  crypto.createHmac("sha256", prk).update(Buffer.concat([info, Buffer.from([1])])).digest().subarray(0, L);
const lblExtract = (salt, label, ikm, suite) =>
  extract(salt, Buffer.concat([Buffer.from("HPKE-v1"), suite, Buffer.from(label), ikm]));
const lblExpand = (prk, label, info, L, suite) =>
  expand(prk, Buffer.concat([i2osp(L, 2), Buffer.from("HPKE-v1"), suite, Buffer.from(label), info]), L);

const X_PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
const X_SPKI = Buffer.from("302a300506032b656e032100", "hex");
const xPriv = (raw) => crypto.createPrivateKey({ key: Buffer.concat([X_PKCS8, raw]), format: "der", type: "pkcs8" });
const xPub = (raw) => crypto.createPublicKey({ key: Buffer.concat([X_SPKI, raw]), format: "der", type: "spki" });
const rawPub = (keyObject) => keyObject.export({ type: "spki", format: "der" }).subarray(-32);

/** RFC 9180 base-mode open (seq=0). Empty AAD by contract — identity binds via `info`. */
export function hpkeOpen(enc, ciphertext, recipientPrivRaw, info) {
  const priv = xPriv(recipientPrivRaw);
  const recipientPubRaw = rawPub(crypto.createPublicKey(priv));
  const dh = crypto.diffieHellman({ privateKey: priv, publicKey: xPub(enc) });
  const shared = lblExpand(
    lblExtract(Buffer.alloc(0), "eae_prk", dh, KEM_SUITE),
    "shared_secret", Buffer.concat([enc, recipientPubRaw]), 32, KEM_SUITE,
  );
  const ks = Buffer.concat([
    Buffer.from([0]),
    lblExtract(Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0), HPKE_SUITE),
    lblExtract(Buffer.alloc(0), "info_hash", info, HPKE_SUITE),
  ]);
  const secret = lblExtract(shared, "secret", Buffer.alloc(0), HPKE_SUITE);
  const key = lblExpand(secret, "key", ks, 32, HPKE_SUITE);
  const nonce = lblExpand(secret, "base_nonce", ks, 12, HPKE_SUITE);
  const tag = ciphertext.subarray(ciphertext.length - 16);
  const body = ciphertext.subarray(0, ciphertext.length - 16);
  const d = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  d.setAuthTag(tag);
  return Buffer.concat([d.update(body), d.final()]);
}

/** AES-256-GCM decrypt with the identity-binding AAD. */
export function aesGcmDecrypt(env, dek) {
  const b = env.workload_binding;
  const aad = Buffer.from([env.request_id, env.kek_ref, b.cluster_id, b.namespace, b.serviceaccount].join("|"));
  const d = crypto.createDecipheriv("aes-256-gcm", dek, Buffer.from(env.iv, "base64"));
  d.setAuthTag(Buffer.from(env.tag, "base64"));
  d.setAAD(aad);
  return Buffer.concat([d.update(Buffer.from(env.ciphertext, "base64")), d.final()]);
}

export function parseEnvelope(wire) {
  if (!wire.startsWith(ENVELOPE_PREFIX)) throw new Error(`envelope missing ${ENVELOPE_PREFIX} prefix`);
  const s = wire.slice(ENVELOPE_PREFIX.length);
  return JSON.parse(Buffer.from(s.padEnd(s.length + ((4 - (s.length % 4)) % 4), "="), "base64url").toString());
}

const b64 = (buf) => buf.toString("base64");

// Standard Kubernetes mount paths.
const PATHS = {
  apiKey: "/etc/astis/api-key",
  saToken: "/var/run/secrets/astis-audience/token",
};
const read = (p) => fs.readFileSync(p, "utf8").trim();

export class WorkloadClient {
  constructor({ apiUrl = DEFAULT_API_URL, apiKey, identityToken }) {
    this.apiUrl = apiUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.identityToken = identityToken; // OIDC / SA JWT, aud=astis.io
    this._session = null; // one workload session per pod, established lazily
  }

  /** Unwrap one envelope and return the decrypted secret (Buffer). */
  async openSecret(envelopeWire) {
    const env = parseEnvelope(envelopeWire);
    await this._ensureSession();
    const rewrap = await this._unwrap(env);
    const info = Buffer.from(`astis-rfc020|${env.request_id}|${env.kek_ref}`);
    const dek = hpkeOpen(
      Buffer.from(rewrap.kemEncapsulatedKeyB64, "base64"),
      Buffer.from(rewrap.kemCiphertextB64, "base64"),
      this._session.kemPrivRaw, info,
    );
    return aesGcmDecrypt(env, dek);
  }

  // RFC-020 pins one credential per pod UID, so establish the session once and reuse it.
  async _ensureSession() {
    if (this._session) return;
    const sig = crypto.generateKeyPairSync("ed25519");
    const kem = crypto.generateKeyPairSync("x25519");
    const kemPrivRaw = kem.privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
    const sigPubB64 = b64(sig.publicKey.export({ type: "spki", format: "der" }).subarray(-32));
    const kemPubB64 = b64(rawPub(kem.publicKey));
    const sessionId = await this._sessionInit(sigPubB64, kemPubB64);
    this._session = { sigPriv: sig.privateKey, kemPrivRaw, sessionId };
  }

  async _sessionInit(sigPubB64, kemPubB64) {
    // RFC-020 §12.2: the client declares NO identity — send only the ephemeral pubkeys.
    const body = { podPubkey: sigPubB64, podKemPubkey: kemPubB64 };
    const { status, json } = await this._post("/v1/workload/session/init",
      Buffer.from(JSON.stringify(body)),
      { Authorization: `Bearer ${this.apiKey}`, "X-Workload-Proof": this.identityToken });
    if (status !== 200) throw new Error(`session/init failed: HTTP ${status} ${JSON.stringify(json)}`);
    return json.session_id;
  }

  async _unwrap(env) {
    // Send only the DEK wrap material + binding; ciphertext/iv/tag never leave the pod.
    const body = Buffer.from(JSON.stringify({
      encap_b64: env.encap_b64, wrapped_dek_b64: env.wrapped_dek_b64,
      kek_ref: env.kek_ref, request_id: env.request_id, workload_binding: env.workload_binding,
    }));
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomBytes(9).toString("base64url");
    const bodyHash = crypto.createHash("sha256").update(body).digest("hex");
    const canonical = Buffer.from(`POST\n/v1/workload/unwrap\n${bodyHash}\n${ts}\n${nonce}`);
    const sig = b64(crypto.sign(null, canonical, this._session.sigPriv));
    const { status, json } = await this._post("/v1/workload/unwrap", body, {
      Authorization: `Bearer ${this.apiKey}`, "X-Workload-Proof": this.identityToken,
      "X-Astis-Session": this._session.sessionId, "X-Pod-Signature": sig,
      "X-Pod-Timestamp": ts, "X-Pod-Nonce": nonce,
    });
    if (status !== 200) throw new Error(`unwrap failed: HTTP ${status} ${JSON.stringify(json)}`);
    return json;
  }

  async _post(path, body, headers) {
    const resp = await fetch(this.apiUrl + path, {
      method: "POST",
      headers: { "User-Agent": "astis-workload-node/1.0", "Content-Type": "application/json", ...headers },
      body,
      signal: AbortSignal.timeout(15000),
    });
    let json = {};
    try { json = await resp.json(); } catch { /* non-JSON error body */ }
    return { status: resp.status, json };
  }
}

/**
 * Build a client from in-pod mounts: the bound API key + projected SA token.
 * The client declares NO identity (RFC-020 §12.2) — the gateway resolves cluster from
 * the API-key binding and namespace/serviceaccount/pod from the verified SA JWT.
 */
export function fromKubernetes(apiUrl) {
  return new WorkloadClient({
    apiUrl,
    apiKey: read(PATHS.apiKey),
    identityToken: read(PATHS.saToken),
  });
}
