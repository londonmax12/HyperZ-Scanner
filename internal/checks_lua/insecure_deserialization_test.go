package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findInsecureDeserial(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "insecure-deserialization" {
			return c
		}
	}
	t.Fatal("insecure-deserialization Lua check not found")
	return nil
}

// TestLuaInsecureDeserializationFingerprintCookie asserts both
// implementations flag a Set-Cookie value whose shape matches the
// Java ObjectInputStream base64 prefix. Cookie hits fire HIGH and
// share an identical dedupe key across implementations.
func TestLuaInsecureDeserializationFingerprintCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=rO0ABXNyAAA1234567890abcdefghij; Path=/")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	pageURL := srv.URL + "/"
	p := page.FromURL(pageURL)
	resp, err := http.Get(pageURL)
	if err != nil {
		t.Fatalf("prefetch: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 1<<16)
	n, _ := resp.Body.Read(buf)
	p.Body = buf[:n]
	p.Headers = resp.Header
	p.Status = resp.StatusCode
	p.Fetched = true

	client := newTestClient(t)
	goFs, err := (checks.InsecureDeserialization{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findInsecureDeserial(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) == 0 {
		t.Fatalf("go: expected at least one fingerprint finding, got 0")
	}
	if len(luaFs) == 0 {
		t.Fatalf("lua: expected at least one fingerprint finding, got 0")
	}

	// Find the cookie-fingerprint finding from each side. The probe arm
	// may add findings if the synthetic sinks happen to reflect an
	// error pattern; we compare apples-to-apples by matching the
	// Set-Cookie marker in the title.
	const titleNeedle = "Serialized Java ObjectInputStream data carried in Set-Cookie session"
	var goCookie, luaCookie *checks.Finding
	for i := range goFs {
		if goFs[i].Title == titleNeedle {
			goCookie = &goFs[i]
			break
		}
	}
	for i := range luaFs {
		if luaFs[i].Title == titleNeedle {
			luaCookie = &luaFs[i]
			break
		}
	}
	if goCookie == nil || luaCookie == nil {
		t.Fatalf("missing cookie fingerprint finding\ngo=%+v\nlua=%+v", goFs, luaFs)
	}

	if goCookie.Severity != luaCookie.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goCookie.Severity, luaCookie.Severity)
	}
	if goCookie.Title != luaCookie.Title {
		t.Errorf("title drift:\n go=%q\nlua=%q", goCookie.Title, luaCookie.Title)
	}
	if goCookie.CWE != luaCookie.CWE {
		t.Errorf("CWE drift: go=%q lua=%q", goCookie.CWE, luaCookie.CWE)
	}
	if goCookie.OWASP != luaCookie.OWASP {
		t.Errorf("OWASP drift: go=%q lua=%q", goCookie.OWASP, luaCookie.OWASP)
	}
	if goCookie.DedupeKey != luaCookie.DedupeKey {
		t.Errorf("dedupe drift:\n go=%q\nlua=%q", goCookie.DedupeKey, luaCookie.DedupeKey)
	}
}

// TestLuaInsecureDeserializationCleanPage asserts both implementations
// emit zero findings when the page has no serialized data shapes in
// cookies / query / form-inputs / body, and the sinks produce no
// deserializer error signatures.
func TestLuaInsecureDeserializationCleanPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hello world, no secrets here</body></html>"))
	}))
	defer srv.Close()

	pageURL := srv.URL + "/"
	p := page.FromURL(pageURL)
	resp, _ := http.Get(pageURL)
	defer resp.Body.Close()
	buf := make([]byte, 1<<16)
	n, _ := resp.Body.Read(buf)
	p.Body = buf[:n]
	p.Headers = resp.Header
	p.Status = resp.StatusCode
	p.Fetched = true

	client := newTestClient(t)
	goFs, err := (checks.InsecureDeserialization{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %+v", goFs)
	}
	luaC := findInsecureDeserial(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %+v", luaFs)
	}
}
