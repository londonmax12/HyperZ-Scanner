package checks_lua

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

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findJWTVulns(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "jwt-vulns" {
			return c
		}
	}
	t.Fatal("jwt-vulns Lua check not found")
	return nil
}

// mintJWTLua mints an HS256 JWT under secret with the supplied
// claims. Duplicates the Go-side helper so the Lua parity test does
// not depend on internal/checks's test binary.
func mintJWTLua(t *testing.T, header map[string]any, claims map[string]any, secret string) string {
	t.Helper()
	if header == nil {
		header = map[string]any{}
	}
	if _, ok := header["alg"]; !ok {
		header["alg"] = "HS256"
	}
	if _, ok := header["typ"]; !ok {
		header["typ"] = "JWT"
	}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	hEnc := base64.RawURLEncoding.EncodeToString(hb)
	cEnc := base64.RawURLEncoding.EncodeToString(cb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(hEnc + "." + cEnc))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hEnc + "." + cEnc + "." + sig
}

func TestLuaJWTVulnsMetadata(t *testing.T) {
	c := findJWTVulns(t)
	if c.Name() != "jwt-vulns" {
		t.Errorf("Name = %q, want jwt-vulns", c.Name())
	}
	if c.Level() != checks.LevelAggressive {
		t.Errorf("Level = %v, want aggressive", c.Level())
	}
}

// TestLuaJWTVulnsNoTokenNoOpParity asserts both impls dispatch
// silently when the page has no JWT to harvest. Bridge wiring would
// not produce a finding here regardless of the Lua composer's
// behaviour, but the parity test pins the no-op shape so a future
// edit that accidentally emits an empty finding gets caught.
func TestLuaJWTVulnsNoTokenNoOpParity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>no jwt here</html>"))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	resp.Body.Close()

	p := page.Page{
		URL:     srv.URL,
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Body:    body[:n],
		Fetched: true,
	}

	goFs, err := (&checks.JWTVulns{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findJWTVulns(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != 0 || len(luaFs) != 0 {
		t.Errorf("no-token page: go=%d lua=%d findings, want 0/0", len(goFs), len(luaFs))
	}
}

// algNoneVulnHandlerLua duplicates the vulnerable-validator fixture
// from the Go test: returns "welcome" when the cookie carries any
// token whose header alg matches "none" (case-insensitive) OR
// validates as HS256 under the real secret. The Set-Cookie response
// seeds the JWT into the page artifact.
func algNoneVulnHandlerLua(secret, originalToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		hb, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			http.Error(w, "bad header", http.StatusUnauthorized)
			return
		}
		var hdr map[string]any
		_ = json.Unmarshal(hb, &hdr)
		alg, _ := hdr["alg"].(string)
		if strings.EqualFold(alg, "none") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("welcome admin dashboard"))
			return
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if want == parts[2] {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("welcome admin dashboard"))
			return
		}
		http.Error(w, "bad sig", http.StatusUnauthorized)
	})
}

// TestLuaJWTVulnsAlgNoneAcceptedFiresFindingParity locks in the
// signal alg=none acceptance produces on both impls: at least one
// Critical finding whose CWE is CWE-347 and whose title carries the
// alg=none substring. The Lua composer passes the Go-side text and
// severity through verbatim by design (RFC-grounded prose), so this
// is a single-side parity assertion that lets the future split do
// surface checks if Lua starts customising.
func TestLuaJWTVulnsAlgNoneAcceptedFiresFindingParity(t *testing.T) {
	secret := "rotated-but-still-pinned"
	originalToken := mintJWTLua(t, nil, map[string]any{"sub": "alice"}, secret)

	mk := func() *httptest.Server {
		return httptest.NewServer(algNoneVulnHandlerLua(secret, originalToken))
	}

	goSrv := mk()
	defer goSrv.Close()
	luaSrv := mk()
	defer luaSrv.Close()

	bootstrap := func(t *testing.T, srv *httptest.Server) page.Page {
		t.Helper()
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
		return page.Page{
			URL:     srv.URL,
			Status:  resp.StatusCode,
			Headers: resp.Header,
			Fetched: true,
		}
	}

	goFs, err := (&checks.JWTVulns{}).Run(context.Background(), newTestClient(t), nil, bootstrap(t, goSrv))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findJWTVulns(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, bootstrap(t, luaSrv))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}

	pickByTitle := func(fs []checks.Finding, needle string) *checks.Finding {
		for i := range fs {
			if strings.Contains(fs[i].Title, needle) {
				return &fs[i]
			}
		}
		return nil
	}

	goHit := pickByTitle(goFs, "alg=none")
	luaHit := pickByTitle(luaFs, "alg=none")
	if goHit == nil {
		t.Fatalf("go: expected alg=none finding, got %d findings: %v", len(goFs), goFs)
	}
	if luaHit == nil {
		t.Fatalf("lua: expected alg=none finding, got %d findings: %v", len(luaFs), luaFs)
	}
	if goHit.Severity != luaHit.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goHit.Severity, luaHit.Severity)
	}
	if goHit.CWE != luaHit.CWE {
		t.Errorf("CWE drift: go=%q lua=%q", goHit.CWE, luaHit.CWE)
	}
	if goHit.OWASP != luaHit.OWASP {
		t.Errorf("OWASP drift: go=%q lua=%q", goHit.OWASP, luaHit.OWASP)
	}
	if luaHit.Severity != checks.SeverityCritical {
		t.Errorf("lua: alg=none must be Critical, got %q", luaHit.Severity)
	}
	if luaHit.CWE != "CWE-347" {
		t.Errorf("lua: CWE = %q, want CWE-347", luaHit.CWE)
	}
}

// TestLuaJWTVulnsWeakSecretParity confirms the offline HS256 brute
// arm produces a Critical weak-secret finding on both impls when the
// signing key is from the curated wordlist. No network probe is
// needed - the math proved the secret offline - so the test fixture
// can leave the server completely unimplemented; harvestJWTs lifts
// the token off the page artifact and the rest is local.
func TestLuaJWTVulnsWeakSecretParity(t *testing.T) {
	// "secret" is the first entry in the Go check's curated wordlist;
	// the offline brute hits on the first attempt.
	token := mintJWTLua(t, nil, map[string]any{"sub": "alice"}, "secret")
	p := page.Page{
		URL:     "https://example.test/login",
		Status:  200,
		Headers: http.Header{"Set-Cookie": []string{"session=" + token + "; Path=/"}},
		Fetched: true,
	}

	goFs, err := (&checks.JWTVulns{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findJWTVulns(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}

	pickWeak := func(fs []checks.Finding) *checks.Finding {
		for i := range fs {
			if strings.Contains(strings.ToLower(fs[i].Title), "weak hmac secret") {
				return &fs[i]
			}
		}
		return nil
	}
	goHit := pickWeak(goFs)
	luaHit := pickWeak(luaFs)
	if goHit == nil {
		t.Fatalf("go: expected weak-secret finding, got %d findings", len(goFs))
	}
	if luaHit == nil {
		t.Fatalf("lua: expected weak-secret finding, got %d findings", len(luaFs))
	}
	if goHit.Severity != luaHit.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goHit.Severity, luaHit.Severity)
	}
	if luaHit.Severity != checks.SeverityCritical {
		t.Errorf("lua: weak-secret must be Critical, got %q", luaHit.Severity)
	}
}
