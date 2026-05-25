package checks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestJWTVulnsName(t *testing.T) {
	if got := (&JWTVulns{}).Name(); got != "jwt-vulns" {
		t.Fatalf("Name = %q, want jwt-vulns", got)
	}
}

func TestJWTVulnsLevel(t *testing.T) {
	if got := (&JWTVulns{}).Level(); got != LevelAggressive {
		t.Fatalf("Level = %v, want aggressive", got)
	}
}

// mintJWT mints an HS256 JWT under secret with the supplied claims.
// Used by tests that want a real signed token to plant in fake server
// responses and then have the check probe back.
func mintJWT(t *testing.T, header map[string]any, claims map[string]any, secret string) string {
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

func TestJWTVulnsNoTokenNoOp(t *testing.T) {
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
	findings, err := (&JWTVulns{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for page without JWT, got %d: %+v", len(findings), findings)
	}
}

func TestJWTVulnsHarvestFromCookie(t *testing.T) {
	token := mintJWT(t, nil, map[string]any{"sub": "alice"}, "secret")
	p := page.Page{
		URL:     "https://example.com/login",
		Status:  200,
		Headers: http.Header{"Set-Cookie": []string{"session=" + token + "; Path=/; HttpOnly"}},
		Fetched: true,
	}
	sources := harvestJWTs(p)
	if len(sources) != 1 {
		t.Fatalf("expected 1 harvested token, got %d", len(sources))
	}
	if sources[0].cookieName != "session" {
		t.Fatalf("cookieName = %q, want session", sources[0].cookieName)
	}
	if sources[0].raw != token {
		t.Fatalf("raw token mismatch")
	}
}

func TestJWTVulnsHarvestFromBody(t *testing.T) {
	token := mintJWT(t, nil, map[string]any{"sub": "alice"}, "secret")
	body := []byte(fmt.Sprintf(`{"access_token": "%s"}`, token))
	p := page.Page{
		URL:     "https://example.com/auth",
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    body,
		Fetched: true,
	}
	sources := harvestJWTs(p)
	if len(sources) != 1 {
		t.Fatalf("expected 1 harvested token, got %d", len(sources))
	}
	if !sources[0].fromBody {
		t.Fatalf("source not marked as fromBody")
	}
}

func TestJWTVulnsHarvestFromBearerHeader(t *testing.T) {
	token := mintJWT(t, nil, map[string]any{"sub": "alice"}, "secret")
	p := page.Page{
		URL:     "https://example.com/me",
		Status:  200,
		Headers: http.Header{"X-Auth-Token": []string{"Bearer " + token}},
		Fetched: true,
	}
	sources := harvestJWTs(p)
	if len(sources) != 1 {
		t.Fatalf("expected 1 harvested token, got %d", len(sources))
	}
	if sources[0].headerName != "X-Auth-Token" {
		t.Fatalf("headerName = %q, want X-Auth-Token", sources[0].headerName)
	}
	if sources[0].raw != token {
		t.Fatalf("raw token = %q, want %q", sources[0].raw, token)
	}
}

func TestJWTVulnsWeakHMACSecretCrackedOffline(t *testing.T) {
	// Mint a real HS256 token under a wordlist secret; the offline
	// brute should recover it without any network traffic. Use a
	// handler that never returns any token of its own so the only
	// signal can be the offline crack.
	token := mintJWT(t, nil, map[string]any{"sub": "alice", "role": "admin"}, "secret")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session="+token+"; Path=/; HttpOnly")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("logged in"))
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
	if !findingsContainTitle(findings, "weak HMAC secret") {
		t.Fatalf("expected a weak HMAC secret finding, got: %+v", titles(findings))
	}
	weak := findingByTitle(findings, "weak HMAC secret")
	if weak.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", weak.Severity)
	}
	if !strings.Contains(weak.Detail, `"secret"`) {
		t.Errorf("Detail should quote the recovered secret: %q", weak.Detail)
	}
}

func TestJWTVulnsAlgNoneAcceptedFiresFinding(t *testing.T) {
	// Server accepts any JWT whose alg is "none" - the canonical bug.
	// Returns "welcome" with the token cookie set; without it,
	// returns 401 unauthenticated.
	secret := "rotated-but-still-pinned"
	originalToken := mintJWT(t, nil, map[string]any{"sub": "alice"}, secret)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie("session")
		if err != nil {
			w.Header().Set("Set-Cookie", "session="+originalToken+"; Path=/")
			http.Error(w, "please log in", http.StatusUnauthorized)
			return
		}
		// Vulnerable validator: trust whatever alg the header advertises,
		// including "none", and skip signature verification when it does.
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
		// Verify HS256 against the real secret for the original token.
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if want == parts[2] {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("welcome admin dashboard"))
			return
		}
		http.Error(w, "bad sig", http.StatusUnauthorized)
	}))
	defer srv.Close()

	// First fetch picks up the Set-Cookie that carries the JWT.
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
	if !findingsContainTitle(findings, "alg=none") {
		t.Fatalf("expected alg=none finding, got: %+v", titles(findings))
	}
	algNone := findingByTitle(findings, "alg=none")
	if algNone.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", algNone.Severity)
	}
	if algNone.CWE != "CWE-347" {
		t.Errorf("CWE = %q, want CWE-347", algNone.CWE)
	}
}

func TestJWTVulnsAlgNoneRejectedNoFinding(t *testing.T) {
	// Hardened server: pins HS256, never accepts alg=none. The check
	// must not fire alg=none here. The secret is outside the wordlist
	// so no offline finding fires either.
	hardSecret := "qLY7Wm9aXdNyV3xPbZ8KsR2u" // not in the wordlist
	originalToken := mintJWT(t, nil, map[string]any{"sub": "alice"}, hardSecret)
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
		mac := hmac.New(sha256.New, []byte(hardSecret))
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
	if findingsContainTitle(findings, "alg=none") {
		t.Fatalf("did not expect alg=none finding on a hardened validator: %+v", titles(findings))
	}
}

func TestJWTVulnsKidPathTraversalAcceptedFiresFinding(t *testing.T) {
	// Vulnerable server: splices kid into a "filesystem" map. When kid
	// resolves to /dev/null, the file is empty so the key is empty
	// bytes - which is what the JWT check's probe re-signs with.
	keyFiles := map[string]string{
		"/keys/main": "real-rotated-key-not-in-wordlist-XYZ",
		"/dev/null":  "",
	}
	originalToken := mintJWT(t, map[string]any{"kid": "/keys/main"}, map[string]any{"sub": "alice"}, keyFiles["/keys/main"])
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
		kid, _ := hdr["kid"].(string)
		key, ok := keyFiles[kid]
		if !ok {
			// Vulnerable lookup: if kid is unknown but the path exists,
			// the implementation reads it and returns its bytes. For
			// this test, /dev/null is the only synthetic "file" outside
			// the registered set; treat anything else as not-found.
			if kid == "/dev/null" {
				key = ""
			} else {
				http.Error(w, "kid unknown", http.StatusUnauthorized)
				return
			}
		}
		if alg != "HS256" {
			http.Error(w, "alg pinned", http.StatusUnauthorized)
			return
		}
		mac := hmac.New(sha256.New, []byte(key))
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
	if !findingsContainTitle(findings, "filesystem path") {
		t.Fatalf("expected kid filesystem-path finding, got: %+v", titles(findings))
	}
	f := findingByTitle(findings, "filesystem path")
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
}

func TestJWTVulnsKidSQLiErrorFiresFinding(t *testing.T) {
	// Vulnerable server: concatenates kid into a SQL string and leaks
	// the driver error on a parse failure. Detection rides on the SQL
	// error pattern showing up in the response body after the probe.
	hardSecret := "qLY7Wm9aXdNyV3xPbZ8KsR2u"
	originalToken := mintJWT(t, map[string]any{"kid": "main"}, map[string]any{"sub": "alice"}, hardSecret)
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
		kid, _ := hdr["kid"].(string)
		if strings.ContainsAny(kid, "'\"") {
			// Stub the SQL driver leak: surface a MySQL-shaped parse
			// error containing exactly one SQLErrorPatterns substring.
			w.WriteHeader(500)
			_, _ = fmt.Fprintf(w, "You have an error in your SQL syntax near %q", kid)
			return
		}
		if kid != "main" {
			http.Error(w, "kid unknown", http.StatusUnauthorized)
			return
		}
		mac := hmac.New(sha256.New, []byte(hardSecret))
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
	if !findingsContainTitle(findings, "SQL key lookup") {
		t.Fatalf("expected kid SQL key lookup finding, got: %+v", titles(findings))
	}
}

func TestJWTVulnsJKUPassiveAdvisory(t *testing.T) {
	// Token carries jku; the check must emit a Medium advisory without
	// any active jku probe (the scanner does not host OOB).
	token := mintJWT(t,
		map[string]any{"alg": "RS256", "jku": "https://attacker.example/jwks.json", "kid": "k1"},
		map[string]any{"sub": "alice"},
		"unused-because-RS256-sig-is-fake",
	)
	p := page.Page{
		URL:     "https://example.com/me",
		Status:  200,
		Headers: http.Header{"Set-Cookie": []string{"session=" + token + "; Path=/"}},
		Fetched: true,
	}
	findings, err := (&JWTVulns{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !findingsContainTitle(findings, "jku header") {
		t.Fatalf("expected jku advisory finding, got: %+v", titles(findings))
	}
	f := findingByTitle(findings, "jku header")
	if f.Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
}

func TestJWTVulnsJKUOOBDetection(t *testing.T) {
	// Vulnerable target: any incoming JWT with a jku header triggers a
	// synchronous fetch of that URL before signature verification. The
	// OOB probe should mint a canary, plant it in jku, and the Drain
	// pass should surface a Critical finding once the callback lands.
	oobSrv := startOOB(t)
	srv := newOOBHostWrapper(oobSrv)

	hardSecret := "qLY7Wm9aXdNyV3xPbZ8KsR2u"
	originalToken := mintJWT(t, nil, map[string]any{"sub": "alice"}, hardSecret)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if jku, ok := hdr["jku"].(string); ok && jku != "" {
			resp, err := http.Get(jku)
			if err == nil {
				resp.Body.Close()
			}
		}
		http.Error(w, "bad sig", http.StatusUnauthorized)
	}))
	defer target.Close()

	resp, err := http.Get(target.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	p := page.Page{
		URL:     target.URL,
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Fetched: true,
	}

	check := &JWTVulns{}
	ctx := WithOOB(context.Background(), srv)
	if _, err := check.Run(ctx, newTestClient(t), nil, p); err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings := check.Drain(ctx)
	if !findingsContainTitle(findings, "OOB-confirmed") {
		t.Fatalf("expected OOB-confirmed jku finding, got: %+v", titles(findings))
	}
	f := findingByTitle(findings, "OOB-confirmed")
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if !strings.Contains(f.Title, "jku") {
		t.Errorf("Title = %q, want it to name the jku field", f.Title)
	}
}

func TestJWTVulnsJKUOOBNoHitNoFinding(t *testing.T) {
	// OOB attached but the validator never fetches jku/x5u. Drain must
	// not synthesise a finding from registrations alone - only hits
	// count.
	oobSrv := startOOB(t)
	srv := newOOBHostWrapper(oobSrv)

	hardSecret := "qLY7Wm9aXdNyV3xPbZ8KsR2u"
	token := mintJWT(t, nil, map[string]any{"sub": "alice"}, hardSecret)
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session="+token+"; Path=/")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("homepage"))
	}))
	defer httpSrv.Close()

	resp, err := http.Get(httpSrv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	p := page.Page{
		URL:     httpSrv.URL,
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Fetched: true,
	}

	check := &JWTVulns{}
	ctx := WithOOB(context.Background(), srv)
	if _, err := check.Run(ctx, newTestClient(t), nil, p); err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings := check.Drain(ctx)
	for _, f := range findings {
		if strings.Contains(f.Title, "OOB-confirmed") {
			t.Fatalf("did not expect OOB finding when no canary was hit: %q", f.Title)
		}
	}
}

func TestJWTVulnsDrainWithoutOOB(t *testing.T) {
	// Drain must be a no-op when no OOB server is attached. The check
	// is registered in the scanner regardless of --oob, and the scanner
	// calls Drain unconditionally on every OOBCheck.
	check := &JWTVulns{}
	if got := check.Drain(context.Background()); len(got) != 0 {
		t.Fatalf("Drain without OOB = %d findings, want 0", len(got))
	}
}

func TestJWTVulnsDedupesAcrossPages(t *testing.T) {
	// Same token observed on two pages must only produce findings on
	// the first Run call; the per-token fingerprint cache suppresses
	// the second. The weak-secret finding is the cheapest one to
	// assert against (purely offline so no network behaviour to mock).
	token := mintJWT(t, nil, map[string]any{"sub": "alice"}, "secret")
	p1 := page.Page{
		URL:     "https://example.com/a",
		Headers: http.Header{"Set-Cookie": []string{"session=" + token + "; Path=/"}},
		Fetched: true,
	}
	p2 := page.Page{
		URL:     "https://example.com/b",
		Headers: http.Header{"Set-Cookie": []string{"session=" + token + "; Path=/"}},
		Fetched: true,
	}
	check := &JWTVulns{}
	first, err := check.Run(context.Background(), newTestClient(t), nil, p1)
	if err != nil {
		t.Fatalf("Run p1: %v", err)
	}
	if !findingsContainTitle(first, "weak HMAC secret") {
		t.Fatalf("expected weak HMAC secret on first run, got: %+v", titles(first))
	}
	second, err := check.Run(context.Background(), newTestClient(t), nil, p2)
	if err != nil {
		t.Fatalf("Run p2: %v", err)
	}
	if findingsContainTitle(second, "weak HMAC secret") {
		t.Fatalf("expected dedupe to suppress repeat finding, got: %+v", titles(second))
	}
}

func TestJWTVulnsOracleUnusableSkipsActiveProbes(t *testing.T) {
	// Server returns identical responses with or without the JWT, so
	// the oracle is unusable. The check must skip the alg=none /
	// kid probes (they have no signal). The token's secret here is
	// hardened, so no offline finding should fire either.
	hardSecret := "qLY7Wm9aXdNyV3xPbZ8KsR2u"
	token := mintJWT(t, nil, map[string]any{"sub": "alice"}, hardSecret)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session="+token+"; Path=/")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("public homepage, same for everyone"))
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
	for _, f := range findings {
		if strings.Contains(f.Title, "alg=none") || strings.Contains(f.Title, "filesystem path") {
			t.Errorf("did not expect active-probe finding on inert oracle: %q", f.Title)
		}
	}
}

func TestTryWeakHMACSecretRecoversKnownSecret(t *testing.T) {
	token := mintJWT(t, nil, map[string]any{"sub": "alice"}, "secret")
	parsed, err := parseJWT(token)
	if err != nil {
		t.Fatalf("parseJWT: %v", err)
	}
	got, ok := tryWeakHMACSecret(parsed, "HS256")
	if !ok {
		t.Fatalf("expected to recover weak secret")
	}
	if got != "secret" {
		t.Fatalf("got = %q, want secret", got)
	}
}

func TestTryWeakHMACSecretRejectsStrongSecret(t *testing.T) {
	token := mintJWT(t, nil, map[string]any{"sub": "alice"}, "qLY7Wm9aXdNyV3xPbZ8KsR2u")
	parsed, err := parseJWT(token)
	if err != nil {
		t.Fatalf("parseJWT: %v", err)
	}
	if _, ok := tryWeakHMACSecret(parsed, "HS256"); ok {
		t.Fatalf("expected no recovery for strong secret")
	}
}

func TestIsJWTShapeRejectsNonJWT(t *testing.T) {
	realToken := mintJWT(t, nil, map[string]any{"sub": "alice"}, "secret")
	cases := map[string]bool{
		"":                                false,
		"not.a.token":                     false,
		"eyJ.eyJ.sig":                     false, // segments too short
		"eyJabcd.eyJabcd":                 false, // only 2 segments
		"AKIAIOSFODNN7EXAMPLE":            false,
		"eyJhbGciOi.eyJzdWIiOi.signature": false, // header segment too short to be base64-decodable JSON
		realToken:                         true,
	}
	for in, want := range cases {
		got := isJWTShape(in)
		if got != want {
			t.Errorf("isJWTShape(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestJWTVulnsKidAsURLPassiveAdvisory(t *testing.T) {
	// Token's kid is structured as a URL. The check must emit a Low
	// passive advisory without any active fetch (the active fetch path
	// is the OOB-confirmed jku/x5u case, not this one).
	token := mintJWT(t,
		map[string]any{"alg": "HS256", "kid": "https://attacker.example/key.pem"},
		map[string]any{"sub": "alice"},
		"a-key-not-in-wordlist-QZX7",
	)
	p := page.Page{
		URL:     "https://example.com/me",
		Status:  200,
		Headers: http.Header{"Set-Cookie": []string{"session=" + token + "; Path=/"}},
		Fetched: true,
	}
	findings, err := (&JWTVulns{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !findingsContainTitle(findings, "kid header is a URL") {
		t.Fatalf("expected kid-as-URL advisory, got: %+v", titles(findings))
	}
	f := findingByTitle(findings, "kid header is a URL")
	if f.Severity != SeverityLow {
		t.Errorf("Severity = %q, want low", f.Severity)
	}
}

func TestJWTVulnsKidAsURLNotFiredForOpaqueKid(t *testing.T) {
	// Opaque kid (no URL shape) must not trigger the advisory.
	token := mintJWT(t,
		map[string]any{"alg": "HS256", "kid": "key-2024-04"},
		map[string]any{"sub": "alice"},
		"another-key-not-in-wordlist-XYZ",
	)
	p := page.Page{
		URL:     "https://example.com/me",
		Status:  200,
		Headers: http.Header{"Set-Cookie": []string{"session=" + token + "; Path=/"}},
		Fetched: true,
	}
	findings, err := (&JWTVulns{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findingsContainTitle(findings, "kid header is a URL") {
		t.Fatalf("did not expect kid-as-URL advisory on opaque kid: %+v", titles(findings))
	}
}

func TestKidLooksLikeURLDetectsCommonForms(t *testing.T) {
	cases := map[string]bool{
		"https://attacker.example/key.pem": true,
		"http://k.example/jwks":            true,
		"//k.example/jwks":                 true,
		"key-2024-01":                      false,
		"":                                 false,
		"main":                             false,
		"ftp://k/key":                      false,
	}
	for in, want := range cases {
		if got := kidLooksLikeURL(in); got != want {
			t.Errorf("kidLooksLikeURL(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestJWTVulnsJKUOOBSplitPerFieldRegistersTwoCanaries(t *testing.T) {
	// The OOB probe should mint one canary per field (jku and x5u),
	// in their own tokens. Even when no callback ever lands, the
	// listener's per-check Registrations list should have two entries
	// - one tagged field=jku and one tagged field=x5u - so the
	// attribution path covers each header in isolation.
	oobSrv := startOOB(t)
	srv := newOOBHostWrapper(oobSrv)

	hardSecret := "qLY7Wm9aXdNyV3xPbZ8KsR2u"
	token := mintJWT(t, nil, map[string]any{"sub": "alice"}, hardSecret)
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session="+token+"; Path=/")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("homepage"))
	}))
	defer httpSrv.Close()

	resp, err := http.Get(httpSrv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	p := page.Page{
		URL:     httpSrv.URL,
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Fetched: true,
	}

	check := &JWTVulns{}
	ctx := WithOOB(context.Background(), srv)
	if _, err := check.Run(ctx, newTestClient(t), nil, p); err != nil {
		t.Fatalf("Run: %v", err)
	}

	regs := srv.Registrations((&JWTVulns{}).Name())
	fields := map[string]int{}
	for _, r := range regs {
		fields[r.Extra["field"]]++
	}
	if fields["jku"] != 1 {
		t.Errorf("expected exactly 1 jku registration, got %d (all=%+v)", fields["jku"], fields)
	}
	if fields["x5u"] != 1 {
		t.Errorf("expected exactly 1 x5u registration, got %d (all=%+v)", fields["x5u"], fields)
	}
}

// findingsContainTitle reports whether any finding's Title contains
// substr. Tests assert against substring rather than full title so a
// future title tweak doesn't break the suite.
func findingsContainTitle(findings []Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Title, substr) {
			return true
		}
	}
	return false
}

func findingByTitle(findings []Finding, substr string) Finding {
	for _, f := range findings {
		if strings.Contains(f.Title, substr) {
			return f
		}
	}
	return Finding{}
}

func titles(findings []Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.Title
	}
	return out
}
