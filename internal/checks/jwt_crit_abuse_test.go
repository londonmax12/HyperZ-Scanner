package checks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestJWTVulnsCritAbuseWithWeakSecret(t *testing.T) {
	// Validator uses a weak HMAC secret AND ignores crit. Two findings
	// expected: the weak-secret finding (which exposes the sign path
	// the crit probe will re-use) and the crit-abuse finding.
	secret := "secret"
	originalToken := mintJWT(t, nil, map[string]any{"sub": "alice"}, secret)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if alg != "HS256" {
			http.Error(w, "alg pinned", http.StatusUnauthorized)
			return
		}
		// Vulnerable: ignore crit entirely and verify HS256 against the
		// known weak secret. A compliant validator would have rejected
		// the moment it saw a crit list naming an unknown extension.
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if want != parts[2] {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("welcome admin dashboard"))
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
	if !findingsContainTitle(findings, "ignores crit header") {
		t.Fatalf("expected crit-abuse finding, got: %+v", titles(findings))
	}
	f := findingByTitle(findings, "ignores crit header")
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if !strings.Contains(f.Detail, critProbeExtensionName) {
		t.Errorf("Detail should name the synthetic critical extension: %q", f.Detail)
	}
}

func TestJWTVulnsCritAbuseNoFindingWhenCritEnforced(t *testing.T) {
	// Compliant validator: rejects any token whose crit list names an
	// extension it does not understand, even if the signature is valid.
	// Weak-secret finding still fires; crit finding does not.
	secret := "secret"
	originalToken := mintJWT(t, nil, map[string]any{"sub": "alice"}, secret)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if alg != "HS256" {
			http.Error(w, "alg pinned", http.StatusUnauthorized)
			return
		}
		if crit, ok := hdr["crit"].([]any); ok && len(crit) > 0 {
			// Reject - we don't recognise any extension in the list.
			http.Error(w, "crit rejected", http.StatusUnauthorized)
			return
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if want != parts[2] {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("welcome admin dashboard"))
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
	if findingsContainTitle(findings, "ignores crit header") {
		t.Fatalf("did not expect crit finding on compliant validator: %+v", titles(findings))
	}
	if !findingsContainTitle(findings, "weak HMAC secret") {
		t.Fatalf("expected weak-secret finding, got: %+v", titles(findings))
	}
}
