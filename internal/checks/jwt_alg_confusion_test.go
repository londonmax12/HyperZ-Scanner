package checks

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

// jwksHandlerForRSAKey serves a JWKS document at /.well-known/jwks.json
// containing one RSA public key derived from pub. The kid is fixed at
// "rsa-key-1" so test assertions can pin the value.
func jwksHandlerForRSAKey(t *testing.T, pub *rsa.PublicKey) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	doc := struct {
		Keys []map[string]string `json:"keys"`
	}{
		Keys: []map[string]string{{
			"kty": "RSA",
			"kid": "rsa-key-1",
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	return mux
}

// hostFromURL returns the scheme+host of a URL string so tests can
// rebase JWKS responses and oracle probes onto a single httptest
// server. Fails the test rather than returning ambiguous fallbacks
// because every caller depends on a well-formed URL.
func hostFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Scheme + "://" + u.Host
}

// mustGenRSAKey returns a fresh 2048-bit RSA keypair. Generated per-
// test rather than embedded as a constant so a coverage run does not
// have the literal modulus in source - keeps grep noise low.
func mustGenRSAKey(t *testing.T) (*rsa.PublicKey, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &priv.PublicKey, priv
}

func TestJWTVulnsAlgConfusionRS256ToHS256(t *testing.T) {
	// Vulnerable validator: pins NO algorithm. If the incoming alg is
	// HS256 it verifies HMAC against the PEM SPKI bytes of the public
	// key it would otherwise use for RSA verification. This is the
	// textbook RS256 -> HS256 confusion attack, and the probe is
	// expected to forge a token under that exact bug.
	pub, _ := mustGenRSAKey(t)
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	spkiPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiDER})

	// Build the original token under the RSA key. The token's
	// signature does not need to verify for this test, because the
	// vulnerable validator branch we are testing trusts whichever
	// algorithm the header advertises - the original signature is
	// only sent to seed the oracle's authenticated baseline.
	origHeaderJSON, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "rsa-key-1"})
	origPayloadJSON, _ := json.Marshal(map[string]any{"sub": "alice"})
	origHeaderEnc := base64.RawURLEncoding.EncodeToString(origHeaderJSON)
	origPayloadEnc := base64.RawURLEncoding.EncodeToString(origPayloadJSON)
	originalToken := origHeaderEnc + "." + origPayloadEnc + ".dGVzdC1zaWc"

	mux := http.NewServeMux()
	mux.Handle("/.well-known/jwks.json", jwksHandlerForRSAKey(t, pub).(*http.ServeMux))
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie("session")
		if err != nil {
			w.Header().Set("Set-Cookie", "session="+originalToken+"; Path=/")
			http.Error(w, "please log in", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(ck.Value, ".")
		if len(parts) != 3 {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var hdr map[string]any
		_ = json.Unmarshal(hb, &hdr)
		alg, _ := hdr["alg"].(string)
		switch alg {
		case "HS256":
			// Vulnerable: HMAC over the PEM SPKI of the public key.
			mac := hmac.New(sha256.New, spkiPEM)
			mac.Write([]byte(parts[0] + "." + parts[1]))
			want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			if want != parts[2] {
				http.Error(w, "bad sig", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte("welcome admin dashboard"))
		case "RS256":
			// Treat the original token as authenticated so the oracle
			// has a positive baseline to compare against. The signature
			// is faked - we don't verify it here because doing so would
			// require regenerating a real RS256 signature in the test
			// just to feed the oracle a positive sample. The probe
			// won't fire on the original token; it fires on the HS256
			// forgery, which we DO verify above.
			w.WriteHeader(200)
			_, _ = w.Write([]byte("welcome admin dashboard"))
		default:
			http.Error(w, "alg pinned", http.StatusUnauthorized)
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/me")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	p := page.Page{
		URL:     srv.URL + "/me",
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Fetched: true,
	}
	findings, err := (&JWTVulns{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !findingsContainTitle(findings, "algorithm confusion") {
		t.Fatalf("expected alg-confusion finding, got: %+v", titles(findings))
	}
	f := findingByTitle(findings, "algorithm confusion")
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if !strings.Contains(f.Detail, "rsa-key-1") {
		t.Errorf("Detail should name the JWKS kid: %q", f.Detail)
	}
	if !strings.Contains(hostFromURL(t, f.URL), strings.TrimPrefix(srv.URL, "http://")) {
		t.Errorf("Finding URL should be on the same origin as the target: %q", f.URL)
	}
}

func TestJWTVulnsAlgConfusionNoFindingWhenAlgPinned(t *testing.T) {
	// Hardened validator: strictly RS256 only, rejects any HS-shaped
	// token. The probe must not fire even though a JWKS is reachable.
	pub, priv := mustGenRSAKey(t)

	headerJSON, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "rsa-key-1"})
	payloadJSON, _ := json.Marshal(map[string]any{"sub": "alice"})
	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signing := headerEnc + "." + payloadEnc
	hashed := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("sign rsa: %v", err)
	}
	originalToken := signing + "." + base64.RawURLEncoding.EncodeToString(sig)

	mux := http.NewServeMux()
	mux.Handle("/.well-known/jwks.json", jwksHandlerForRSAKey(t, pub).(*http.ServeMux))
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie("session")
		if err != nil {
			w.Header().Set("Set-Cookie", "session="+originalToken+"; Path=/")
			http.Error(w, "please log in", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(ck.Value, ".")
		if len(parts) != 3 {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var hdr map[string]any
		_ = json.Unmarshal(hb, &hdr)
		alg, _ := hdr["alg"].(string)
		if alg != "RS256" {
			http.Error(w, "alg pinned", http.StatusUnauthorized)
			return
		}
		s, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			http.Error(w, "bad sig encoding", http.StatusUnauthorized)
			return
		}
		hashed := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], s); err != nil {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("welcome admin dashboard"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/me")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	p := page.Page{
		URL:     srv.URL + "/me",
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Fetched: true,
	}
	findings, err := (&JWTVulns{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findingsContainTitle(findings, "algorithm confusion") {
		t.Fatalf("did not expect alg-confusion finding on hardened validator: %+v", titles(findings))
	}
}

func TestJWTVulnsAlgConfusionNoJWKSNoFinding(t *testing.T) {
	// Validator's protected URL exists but no JWKS is reachable on the
	// origin. The probe must back off rather than fire a false
	// positive against a key it never observed.
	headerJSON, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT"})
	payloadJSON, _ := json.Marshal(map[string]any{"sub": "alice"})
	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)
	originalToken := headerEnc + "." + payloadEnc + ".dGVzdC1zaWc"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") || strings.HasPrefix(r.URL.Path, "/jwks") {
			http.NotFound(w, r)
			return
		}
		ck, err := r.Cookie("session")
		if err != nil {
			w.Header().Set("Set-Cookie", "session="+originalToken+"; Path=/")
			http.Error(w, "please log in", http.StatusUnauthorized)
			return
		}
		if ck.Value != originalToken {
			http.Error(w, "rejected", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("welcome"))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	p := page.Page{
		URL:     srv.URL,
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Fetched: true,
	}
	findings, err := (&JWTVulns{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findingsContainTitle(findings, "algorithm confusion") {
		t.Fatalf("did not expect alg-confusion finding when no JWKS reachable: %+v", titles(findings))
	}
}

func TestJWKKeyVariantsRSAProducesPemAndDer(t *testing.T) {
	pub, _ := mustGenRSAKey(t)
	k := jwkKey{
		Kty: "RSA",
		Kid: "k1",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	got := publicKeyVariantsFor(k)
	if len(got) == 0 {
		t.Fatalf("expected variants for RSA key, got 0")
	}
	names := map[string]bool{}
	for _, v := range got {
		names[v.name] = true
		if len(v.bytes) == 0 {
			t.Errorf("variant %q has empty bytes", v.name)
		}
	}
	for _, required := range []string{"pem-spki", "der-spki", "pem-pkcs1", "modulus-bytes", "jwk-json"} {
		if !names[required] {
			t.Errorf("expected variant %q in RSA variants, got %v", required, names)
		}
	}
}

func TestParseAlgConfusionKeysIndirectsThroughOIDCConfig(t *testing.T) {
	// An OIDC discovery document points at jwks_uri but carries no keys
	// directly. parseAlgConfusionKeys should surface the indirect URL
	// with an empty keys slice so the caller can refetch.
	body := []byte(`{"issuer":"https://example.com","jwks_uri":"https://example.com/jwks.json"}`)
	keys, indirect := parseAlgConfusionKeys("https://example.com/.well-known/openid-configuration", body)
	if len(keys) != 0 {
		t.Errorf("expected no direct keys from OIDC discovery doc, got %d", len(keys))
	}
	if indirect != "https://example.com/jwks.json" {
		t.Errorf("indirect = %q, want https://example.com/jwks.json", indirect)
	}
}
