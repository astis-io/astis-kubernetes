package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Cross-language known-answer test: the fixture is sealed by the verified Python
// reference implementation; this Go client opens it — proving both ends agree on the
// ASTIS:v2 wire contract (the same contract CVS uses). If suite IDs, the empty-AAD
// convention, the info string, or the binding AAD drift, this fails.

func loadFixture(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("kat-fixture.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f map[string]string
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

func TestGoOpensPythonSealedEnvelope(t *testing.T) {
	f := loadFixture(t)
	env, err := parseEnvelope(f["envelope_wire"])
	if err != nil {
		t.Fatal(err)
	}
	info := []byte("astis-rfc020|" + env.RequestID + "|" + env.KekRef)
	dek, err := hpkeOpen(b64d(f["rewrap_enc"]), b64d(f["rewrap_hpke_ct"]), b64d(f["recip_priv"]), info)
	if err != nil {
		t.Fatalf("hpke open: %v", err)
	}
	if len(dek) != 32 {
		t.Fatalf("DEK len = %d, want 32", len(dek))
	}
	pt, err := aesGCMDecrypt(env, dek)
	if err != nil {
		t.Fatalf("aes-gcm: %v", err)
	}
	if string(pt) != f["expect"] {
		t.Fatalf("plaintext = %q, want %q", pt, f["expect"])
	}
}

func TestWrongBindingAADFails(t *testing.T) {
	f := loadFixture(t)
	env, _ := parseEnvelope(f["envelope_wire"])
	info := []byte("astis-rfc020|" + env.RequestID + "|" + env.KekRef)
	dek, _ := hpkeOpen(b64d(f["rewrap_enc"]), b64d(f["rewrap_hpke_ct"]), b64d(f["recip_priv"]), info)
	env.WorkloadBinding["namespace"] = "attacker-ns"
	if _, err := aesGCMDecrypt(env, dek); err == nil {
		t.Fatal("decrypt must fail when the binding AAD is tampered")
	}
}

func TestHPKEOpenTamperFails(t *testing.T) {
	f := loadFixture(t)
	env, _ := parseEnvelope(f["envelope_wire"])
	info := []byte("astis-rfc020|" + env.RequestID + "|" + env.KekRef)
	enc := b64d(f["rewrap_enc"])
	enc[0] ^= 0x01
	if _, err := hpkeOpen(enc, b64d(f["rewrap_hpke_ct"]), b64d(f["recip_priv"]), info); err == nil {
		t.Fatal("hpke open must fail on a corrupted encapsulation")
	}
}

func TestRejectsBadPrefix(t *testing.T) {
	if _, err := parseEnvelope("ASTIS:v1:whatever"); err == nil {
		t.Fatal("must reject a non-v2 prefix")
	}
}

func TestEnvelopeFieldsDecode(t *testing.T) {
	f := loadFixture(t)
	wire := strings.TrimPrefix(f["envelope_wire"], "ASTIS:v2:")
	if _, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(wire, "=")); err != nil {
		t.Fatalf("envelope body not base64url: %v", err)
	}
}
