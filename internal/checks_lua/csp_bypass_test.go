package checks_lua

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findCSPBypass(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "csp-bypass" {
			return c
		}
	}
	t.Fatal("csp-bypass Lua check not found")
	return nil
}

// staticNonceCSPHandler reuses a single hardcoded nonce on every
// response - the bug the nonce-reuse probe exists to surface.
func staticNonceCSPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"script-src 'self' 'nonce-baked-in-at-deploy'")
		w.WriteHeader(http.StatusOK)
	}
}

// rotatingNonceCSPHandler emits a fresh nonce on every response.
// The probe must NOT fire against it.
func rotatingNonceCSPHandler() http.HandlerFunc {
	var counter atomic.Uint64
	return func(w http.ResponseWriter, r *http.Request) {
		n := counter.Add(1)
		w.Header().Set("Content-Security-Policy",
			fmt.Sprintf("script-src 'self' 'nonce-%d-rotating'", n))
		w.WriteHeader(http.StatusOK)
	}
}

// TestLuaCSPBypassNonceReuseParity locks in the nonce-reuse arm: both
// implementations must fire one High finding when the server reuses a
// nonce across responses, with identical Severity / Title / DedupeKey /
// CWE / OWASP.
func TestLuaCSPBypassNonceReuseParity(t *testing.T) {
	srv := httptest.NewServer(staticNonceCSPHandler())
	defer srv.Close()

	goFs, err := (checks.CSPBypass{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findCSPBypass(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}

	goHit := pickByTitleSubstr(goFs, "nonce reused")
	luaHit := pickByTitleSubstr(luaFs, "nonce reused")
	if goHit == nil || luaHit == nil {
		t.Fatalf("nonce-reuse must fire on both impls: go=%+v lua=%+v", goFs, luaFs)
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
	if goHit.DedupeKey != luaHit.DedupeKey {
		t.Errorf("dedupe drift: go=%q lua=%q", goHit.DedupeKey, luaHit.DedupeKey)
	}
	if !strings.Contains(luaHit.Detail, "baked-in-at-deploy") {
		t.Errorf("lua Detail should quote the reused nonce value: %s", luaHit.Detail)
	}
}

// TestLuaCSPBypassNonceRotationParity asserts both implementations
// stay quiet when the server rotates nonces per response.
func TestLuaCSPBypassNonceRotationParity(t *testing.T) {
	srv := httptest.NewServer(rotatingNonceCSPHandler())
	defer srv.Close()

	luaC := findCSPBypass(t)
	goFs, err := (checks.CSPBypass{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if pickByTitleSubstr(goFs, "nonce reused") != nil {
		t.Errorf("go: nonce-reuse must not fire under rotation: %+v", goFs)
	}
	if pickByTitleSubstr(luaFs, "nonce reused") != nil {
		t.Errorf("lua: nonce-reuse must not fire under rotation: %+v", luaFs)
	}
}

// TestLuaCSPBypassNoCSPParity asserts both implementations are quiet
// on a page that has no CSP header at all (csp-weak's territory).
func TestLuaCSPBypassNoCSPParity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	goFs, err := (checks.CSPBypass{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findCSPBypass(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != 0 || len(luaFs) != 0 {
		t.Errorf("no-CSP page must produce 0 findings on both: go=%d lua=%d", len(goFs), len(luaFs))
	}
}

// TestLuaCSPBypassJSONPParity locks in the JSONP arm: with the probe
// table swapped to a test endpoint, both implementations must fire
// one High finding with identical Severity / DedupeKey when the CSP
// allowlists the JSONP host and the endpoint echoes the callback as
// a function call.
func TestLuaCSPBypassJSONPParity(t *testing.T) {
	jsonpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cb := r.URL.Query().Get("callback")
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, "/**/%s({\"data\":\"ok\"});", cb)
	}))
	defer jsonpSrv.Close()
	jsonpURL, _ := url.Parse(jsonpSrv.URL)
	jsonpHost := jsonpURL.Hostname()

	restore := checks.OverrideCSPBypassJSONPProbesForTest([]checks.CSPBypassJSONPProbeLua{{
		Host:    jsonpHost,
		URLTmpl: jsonpSrv.URL + "/jsonp?callback=",
	}})
	defer restore()

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self' "+jsonpSrv.URL+
				"; base-uri 'none'")
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	goFs, err := (checks.CSPBypass{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(targetSrv.URL))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findCSPBypass(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, page.FromURL(targetSrv.URL))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}

	goHit := pickByTitleSubstr(goFs, "JSONP bypass")
	luaHit := pickByTitleSubstr(luaFs, "JSONP bypass")
	if goHit == nil || luaHit == nil {
		t.Fatalf("JSONP bypass must fire on both: go=%+v lua=%+v", goFs, luaFs)
	}
	if goHit.Severity != luaHit.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goHit.Severity, luaHit.Severity)
	}
	if goHit.DedupeKey != luaHit.DedupeKey {
		t.Errorf("dedupe drift: go=%q lua=%q", goHit.DedupeKey, luaHit.DedupeKey)
	}
	if !strings.Contains(luaHit.Detail, jsonpHost) {
		t.Errorf("lua Detail should reference the JSONP host: %s", luaHit.Detail)
	}
}

// TestLuaCSPBypassBaseURIParity locks in the base-uri-hijack arm:
// missing base-uri on a page with relative <script src> tags must
// fire one Medium finding on both impls with identical DedupeKey.
func TestLuaCSPBypassBaseURIParity(t *testing.T) {
	body := []byte(`<!doctype html><html><head>
<script src="/static/app.js"></script>
<script src="vendor.js"></script>
<script src="https://cdn.example.com/sdk.js"></script>
<script src="//cdn.example.com/sdk2.js"></script>
</head><body></body></html>`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html")
		w.Write(body)
	}))
	defer srv.Close()

	goFs, err := (checks.CSPBypass{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findCSPBypass(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}

	goHit := pickByTitleSubstr(goFs, "Base-URI hijack")
	luaHit := pickByTitleSubstr(luaFs, "Base-URI hijack")
	if goHit == nil || luaHit == nil {
		t.Fatalf("base-uri hijack must fire on both: go=%+v lua=%+v", goFs, luaFs)
	}
	if goHit.Severity != luaHit.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goHit.Severity, luaHit.Severity)
	}
	if goHit.DedupeKey != luaHit.DedupeKey {
		t.Errorf("dedupe drift: go=%q lua=%q", goHit.DedupeKey, luaHit.DedupeKey)
	}
	if !strings.Contains(luaHit.Detail, "/static/app.js") || !strings.Contains(luaHit.Detail, "vendor.js") {
		t.Errorf("lua Detail should list the relative srcs: %s", luaHit.Detail)
	}
	if strings.Contains(luaHit.Detail, "https://cdn.example.com/sdk.js") {
		t.Errorf("lua Detail must NOT include absolute srcs: %s", luaHit.Detail)
	}
}

// TestLuaCSPBypassBaseURIConstrainedParity asserts the base-uri arm
// stays quiet when base-uri 'none' is set, on both impls.
func TestLuaCSPBypassBaseURIConstrainedParity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<script src="/static/app.js"></script>`))
	}))
	defer srv.Close()

	goFs, err := (checks.CSPBypass{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findCSPBypass(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if pickByTitleSubstr(goFs, "Base-URI hijack") != nil {
		t.Errorf("go: base-uri must be quiet with 'none': %+v", goFs)
	}
	if pickByTitleSubstr(luaFs, "Base-URI hijack") != nil {
		t.Errorf("lua: base-uri must be quiet with 'none': %+v", luaFs)
	}
}

// TestLuaCSPBypassDedupePerHostParity asserts the nonce-reuse and
// jsonp findings collapse to the same per-host dedupe key across two
// crawled pages of the same host - parity with the Go check's
// ScopeHost dedupe scope.
func TestLuaCSPBypassDedupePerHostParity(t *testing.T) {
	srv := httptest.NewServer(staticNonceCSPHandler())
	defer srv.Close()

	luaC := findCSPBypass(t)
	collect := func(suffix string) (checks.Finding, checks.Finding) {
		goFs, err := (checks.CSPBypass{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+suffix))
		if err != nil {
			t.Fatalf("go %s: %v", suffix, err)
		}
		luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+suffix))
		if err != nil {
			t.Fatalf("lua %s: %v", suffix, err)
		}
		goHit := pickByTitleSubstr(goFs, "nonce reused")
		luaHit := pickByTitleSubstr(luaFs, "nonce reused")
		if goHit == nil || luaHit == nil {
			t.Fatalf("nonce-reuse missing on %s: go=%v lua=%v", suffix, goFs, luaFs)
		}
		return *goHit, *luaHit
	}
	goA, luaA := collect("/a")
	goB, luaB := collect("/b")
	if goA.DedupeKey != goB.DedupeKey {
		t.Errorf("go: nonce-reuse DedupeKey should collapse per host: %q vs %q", goA.DedupeKey, goB.DedupeKey)
	}
	if luaA.DedupeKey != luaB.DedupeKey {
		t.Errorf("lua: nonce-reuse DedupeKey should collapse per host: %q vs %q", luaA.DedupeKey, luaB.DedupeKey)
	}
}

// pickByTitleSubstr returns the first finding whose Title contains the
// substring. Used so per-test assertions focus on one technique and
// are unaffected by other arms' findings (which may share the same
// page response).
func pickByTitleSubstr(fs []checks.Finding, substr string) *checks.Finding {
	for i := range fs {
		if strings.Contains(fs[i].Title, substr) {
			return &fs[i]
		}
	}
	return nil
}

