// Cross-language known-answer test (node --test). The fixture is sealed by the verified
// Python reference; this Node client opens it — proving both ends agree on the ASTIS:v2
// wire contract (the same contract CVS uses).

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { hpkeOpen, aesGcmDecrypt, parseEnvelope } from "./astis-workload.js";

const fixture = JSON.parse(fs.readFileSync(new URL("./kat-fixture.json", import.meta.url)));
const b64 = (s) => Buffer.from(s, "base64");

function recoverDek(f, env) {
  const info = Buffer.from(`astis-rfc020|${env.request_id}|${env.kek_ref}`);
  return hpkeOpen(b64(f.rewrap_enc), b64(f.rewrap_hpke_ct), b64(f.recip_priv), info);
}

test("node opens python-sealed envelope", () => {
  const env = parseEnvelope(fixture.envelope_wire);
  const dek = recoverDek(fixture, env);
  assert.equal(dek.length, 32);
  assert.equal(aesGcmDecrypt(env, dek).toString(), fixture.expect);
});

test("wrong binding AAD fails", () => {
  const env = parseEnvelope(fixture.envelope_wire);
  const dek = recoverDek(fixture, env);
  env.workload_binding.namespace = "attacker-ns";
  assert.throws(() => aesGcmDecrypt(env, dek));
});

test("hpke open tamper fails", () => {
  const env = parseEnvelope(fixture.envelope_wire);
  const info = Buffer.from(`astis-rfc020|${env.request_id}|${env.kek_ref}`);
  const enc = b64(fixture.rewrap_enc);
  enc[0] ^= 0x01;
  assert.throws(() => hpkeOpen(enc, b64(fixture.rewrap_hpke_ct), b64(fixture.recip_priv), info));
});

test("rejects non-v2 prefix", () => {
  assert.throws(() => parseEnvelope("ASTIS:v1:whatever"));
});
