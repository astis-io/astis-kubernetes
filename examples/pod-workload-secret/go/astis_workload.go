// Package astisworkload is a self-contained RFC-020 workload-secret client.
//
// It decrypts an ASTIS sealed secret from inside a Kubernetes pod, targeting the same
// ASTIS:v2 wire contract as the Python/Java examples (verified by a cross-language
// known-answer test). HPKE is RFC 9180 base mode (DHKEM-X25519-HKDF-SHA256 +
// ChaCha20-Poly1305) via Cloudflare CIRCL; the payload is AES-256-GCM with an AAD that
// binds the workload identity. The ASTIS edge never sees plaintext or the bare DEK.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/circl/hpke"
)

const (
	defaultAPIURL  = "https://api.astis.io"
	envelopePrefix = "ASTIS:v2:"

	apiKeyPath  = "/etc/astis/api-key"
	saTokenPath = "/var/run/secrets/astis-audience/token"
)

// Client performs the RFC-020 unwrap flow. One workload session (DPoP + KEM keypair) is
// established per pod and reused for every secret — RFC-020 pins a single credential per
// pod UID, so a second session/init would be rejected.
type Client struct {
	apiURL  string
	apiKey  string
	idToken string
	http    *http.Client

	sigPriv   ed25519.PrivateKey
	kemPriv   *ecdh.PrivateKey
	sessionID string
}

// FromKubernetes builds a Client from in-pod mounts: the bound API key and the projected
// SA token. The client declares NO identity (RFC-020 §12.2) — the gateway resolves
// cluster from the API-key binding and namespace/serviceaccount/pod from the verified
// SA JWT.
func FromKubernetes(apiURL string) (*Client, error) {
	read := func(p string) (string, error) {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", p, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	apiKey, err := read(apiKeyPath)
	if err != nil {
		return nil, err
	}
	token, err := read(saTokenPath)
	if err != nil {
		return nil, err
	}
	if apiURL == "" {
		apiURL = defaultAPIURL
	}
	return &Client{
		apiURL:  strings.TrimRight(apiURL, "/"),
		apiKey:  apiKey,
		idToken: token,
		http:    &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// OpenSecret runs the unwrap flow for one envelope and returns the decrypted bytes.
func (c *Client) OpenSecret(envelopeWire string) ([]byte, error) {
	env, err := parseEnvelope(envelopeWire)
	if err != nil {
		return nil, err
	}
	if err := c.ensureSession(); err != nil {
		return nil, err
	}

	rewrap, err := c.unwrap(env)
	if err != nil {
		return nil, err
	}
	info := []byte("astis-rfc020|" + env.RequestID + "|" + env.KekRef)
	dek, err := hpkeOpen(b64d(rewrap.KemEncapsulatedKeyB64), b64d(rewrap.KemCiphertextB64), c.kemPriv.Bytes(), info)
	if err != nil {
		return nil, fmt.Errorf("hpke open: %w", err)
	}
	return aesGCMDecrypt(env, dek)
}

// ensureSession establishes the pod's single workload session once (ephemeral Ed25519
// DPoP + X25519 KEM keypair, then POST /v1/workload/session/init); reused for all unwraps.
func (c *Client) ensureSession() error {
	if c.sessionID != "" {
		return nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	c.sigPriv = priv
	kemPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	c.kemPriv = kemPriv

	sigPubB64 := b64(priv.Public().(ed25519.PublicKey))
	kemPubB64 := b64(kemPriv.PublicKey().Bytes())
	id, err := c.sessionInit(sigPubB64, kemPubB64)
	if err != nil {
		return err
	}
	c.sessionID = id
	return nil
}

func (c *Client) sessionInit(sigPubB64, kemPubB64 string) (string, error) {
	// RFC-020 §12.2: the client declares NO identity — send only the ephemeral pubkeys.
	body := map[string]string{
		"podPubkey":    sigPubB64,
		"podKemPubkey": kemPubB64,
	}
	raw, _ := json.Marshal(body)
	status, resp, err := c.post("/v1/workload/session/init", raw, map[string]string{
		"Authorization": "Bearer " + c.apiKey, "X-Workload-Proof": c.idToken})
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("session/init failed: HTTP %d %s", status, resp)
	}
	var out struct {
		SessionID string `json:"session_id"`
	}
	json.Unmarshal(resp, &out)
	return out.SessionID, nil
}

type rewrapResp struct {
	KemEncapsulatedKeyB64 string `json:"kemEncapsulatedKeyB64"`
	KemCiphertextB64      string `json:"kemCiphertextB64"`
}

func (c *Client) unwrap(env *envelope) (*rewrapResp, error) {
	// Send only the DEK wrap material + binding; ciphertext/iv/tag never leave the pod.
	body := map[string]any{
		"encap_b64":        env.EncapB64,
		"wrapped_dek_b64":  env.WrappedDekB64,
		"kek_ref":          env.KekRef,
		"request_id":       env.RequestID,
		"workload_binding": env.WorkloadBinding,
	}
	raw, _ := json.Marshal(body)

	ts := fmt.Sprintf("%d", time.Now().Unix())
	nonceBytes := make([]byte, 9)
	rand.Read(nonceBytes)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	bodyHash := fmt.Sprintf("%x", sha256.Sum256(raw))
	canonical := "POST\n/v1/workload/unwrap\n" + bodyHash + "\n" + ts + "\n" + nonce
	sig := b64(ed25519.Sign(c.sigPriv, []byte(canonical)))

	status, resp, err := c.post("/v1/workload/unwrap", raw, map[string]string{
		"Authorization":    "Bearer " + c.apiKey,
		"X-Workload-Proof": c.idToken,
		"X-Astis-Session":  c.sessionID,
		"X-Pod-Signature":  sig,
		"X-Pod-Timestamp":  ts,
		"X-Pod-Nonce":      nonce,
	})
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("unwrap failed: HTTP %d %s", status, resp)
	}
	var out rewrapResp
	json.Unmarshal(resp, &out)
	return &out, nil
}

func (c *Client) post(path string, body []byte, headers map[string]string) (int, []byte, error) {
	req, _ := http.NewRequest("POST", c.apiURL+path, bytes.NewReader(body))
	req.Header.Set("User-Agent", "astis-workload-go/1.0")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("cannot reach %s: %w", c.apiURL+path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

// ----- crypto (exported for the KAT test) -----

// hpkeOpen is RFC 9180 base-mode open (DHKEM-X25519 + ChaCha20-Poly1305) via CIRCL.
// AAD is empty by contract — identity binds through info in the key schedule.
func hpkeOpen(enc, ciphertext, recipientPrivRaw, info []byte) ([]byte, error) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	priv, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(recipientPrivRaw)
	if err != nil {
		return nil, err
	}
	recv, err := suite.NewReceiver(priv, info)
	if err != nil {
		return nil, err
	}
	opener, err := recv.Setup(enc)
	if err != nil {
		return nil, err
	}
	return opener.Open(ciphertext, nil)
}

// aesGCMDecrypt decrypts the envelope payload with the identity-binding AAD.
func aesGCMDecrypt(env *envelope, dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	b := env.WorkloadBinding
	aad := []byte(strings.Join([]string{env.RequestID, env.KekRef,
		b["cluster_id"], b["namespace"], b["serviceaccount"]}, "|"))
	return gcm.Open(nil, b64d(env.IV), append(b64d(env.Ciphertext), b64d(env.Tag)...), aad)
}

type envelope struct {
	Alg             string            `json:"alg"`
	KekRef          string            `json:"kek_ref"`
	EncapB64        string            `json:"encap_b64"`
	WrappedDekB64   string            `json:"wrapped_dek_b64"`
	RequestID       string            `json:"request_id"`
	WorkloadBinding map[string]string `json:"workload_binding"`
	Ciphertext      string            `json:"ciphertext"`
	IV              string            `json:"iv"`
	Tag             string            `json:"tag"`
}

func parseEnvelope(wire string) (*envelope, error) {
	if !strings.HasPrefix(wire, envelopePrefix) {
		return nil, fmt.Errorf("envelope missing %s prefix", envelopePrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(wire[len(envelopePrefix):], "="))
	if err != nil {
		return nil, fmt.Errorf("malformed sealed envelope: %w", err)
	}
	var e envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("malformed sealed envelope: %w", err)
	}
	return &e, nil
}

func b64(b []byte) string  { return base64.StdEncoding.EncodeToString(b) }
func b64d(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
