package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestCSPBypassName(t *testing.T) {
	if got := (CSPBypass{}).Name(); got != "csp-bypass" {
		t.Fatalf("Name = %q, want csp-bypass", got)
	}
}

func TestCSPBypassLevel(t *testing.T) {
	if got := (CSPBypass{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// rotatingNonceHandler emits a fresh, monotonically-incrementing nonce on
// every response. A correctly-implemented server would behave like this
// (modulo using a CSPRNG instead of a counter), so the nonce-reuse probe
// must NOT fire against it.
func rotatingNonceHandler(extraCSP string) http.HandlerFunc {
	var counter atomic.Uint64
	return func(w http.ResponseWriter, r *http.Request) {
		n := counter.Add(1)
		policy := fmt.Sprintf("script-src 'self' 'nonce-%d-rotating'", n)
		if extraCSP != "" {
			policy += "; " + extraCSP
		}
		w.Header().Set("Content-Security-Policy", policy)
		w.WriteHeader(http.StatusOK)
	}
}

// staticNonceHandler reuses a single hardcoded nonce on every response.
// This is the bug nonce-reuse exists to surface: a value baked into the
// deploy or derived from a session that does not rotate per request.
func staticNonceHandler(extraCSP string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		policy := "script-src 'self' 'nonce-baked-in-at-deploy'"
		if extraCSP != "" {
			policy += "; " + extraCSP
		}
		w.Header().Set("Content-Security-Policy", policy)
		w.WriteHeader(http.StatusOK)
	}
}

func TestCSPBypassNonceReuseFires(t *testing.T) {
	srv := httptest.NewServer(staticNonceHandler(""))
	defer srv.Close()

	findings, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected nonce-reuse finding, got none")
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "nonce reused") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("no nonce-reuse finding among %d: %+v", len(findings), findings)
	}
	if hit.Severity != SeverityHigh {
		t.Errorf("nonce-reuse Severity = %q, want high", hit.Severity)
	}
	if !strings.Contains(hit.Detail, "baked-in-at-deploy") {
		t.Errorf("Detail should quote reused nonce value, got:\n%s", hit.Detail)
	}
}

func TestCSPBypassNonceRotationClean(t *testing.T) {
	srv := httptest.NewServer(rotatingNonceHandler(""))
	defer srv.Close()

	findings, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "nonce reused") {
			t.Errorf("nonce-reuse must not fire when server rotates per response: %+v", f)
		}
	}
}

func TestCSPBypassNoCSPSkips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on a no-CSP page, got %d: %+v", len(findings), findings)
	}
}

func TestCSPBypassNoNoncesNoProbe(t *testing.T) {
	// A nonce-free CSP gives the probe nothing to compare.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "nonce reused") {
			t.Errorf("nonce-reuse must not fire when policy has no nonces: %+v", f)
		}
	}
}

// TestCSPBypassJSONPDetectsCallbackEcho runs the JSONP probe against a
// test server that mimics a JSONP CDN. The package-level jsonpProbes
// table is swapped to point at the test server's host for the duration
// of the test so the probe matches the CSP allowlist without contacting
// the real google/youtube endpoints.
func TestCSPBypassJSONPDetectsCallbackEcho(t *testing.T) {
	jsonpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cb := r.URL.Query().Get("callback")
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, "/**/%s({\"data\":\"ok\"});", cb)
	}))
	defer jsonpSrv.Close()
	jsonpHost := mustHost(t, jsonpSrv.URL)

	restore := overrideJSONPProbes([]jsonpProbe{{
		host:    jsonpHost,
		urlTmpl: jsonpSrv.URL + "/jsonp?callback=",
	}})
	defer restore()

	// Target server: CSP allowlists the JSONP server's origin in
	// script-src. The probe must walk the allowlist, recognize the
	// JSONP host, fetch the callback endpoint, and confirm the bypass.
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self' "+jsonpSrv.URL+
				"; base-uri 'none'")
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	findings, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(targetSrv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "JSONP bypass") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected JSONP bypass finding, got %d findings: %+v", len(findings), findings)
	}
	if hit.Severity != SeverityHigh {
		t.Errorf("JSONP bypass Severity = %q, want high", hit.Severity)
	}
	if !strings.Contains(hit.Detail, jsonpHost) {
		t.Errorf("Detail should reference the JSONP host %q, got:\n%s", jsonpHost, hit.Detail)
	}
}

func TestCSPBypassJSONPSkipsWhenContentTypeNotJS(t *testing.T) {
	// Endpoint echoes the callback but advertises text/html. Loading it
	// as <script src> would not parse as JavaScript, so the bypass does
	// not actually work and the probe must not fire.
	jsonpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cb := r.URL.Query().Get("callback")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "%s({\"data\":\"ok\"});", cb)
	}))
	defer jsonpSrv.Close()
	jsonpHost := mustHost(t, jsonpSrv.URL)

	restore := overrideJSONPProbes([]jsonpProbe{{
		host:    jsonpHost,
		urlTmpl: jsonpSrv.URL + "/jsonp?callback=",
	}})
	defer restore()

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self' "+jsonpSrv.URL+"; base-uri 'none'")
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	findings, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(targetSrv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "JSONP bypass") {
			t.Errorf("JSONP probe must not fire on non-JS content type: %+v", f)
		}
	}
}

func TestCSPBypassJSONPSkipsWhenHostNotInAllowlist(t *testing.T) {
	jsonpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, "%s({});", r.URL.Query().Get("callback"))
	}))
	defer jsonpSrv.Close()
	jsonpHost := mustHost(t, jsonpSrv.URL)

	restore := overrideJSONPProbes([]jsonpProbe{{
		host:    jsonpHost,
		urlTmpl: jsonpSrv.URL + "/jsonp?callback=",
	}})
	defer restore()

	// Target's CSP does NOT allowlist the JSONP host - script-src only
	// permits 'self'. The probe must not even fetch the endpoint.
	var probeFired atomic.Bool
	jsonpSrvProbed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeFired.Store(true)
	}))
	defer jsonpSrvProbed.Close()

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; base-uri 'none'")
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	findings, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(targetSrv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "JSONP bypass") {
			t.Errorf("JSONP probe must skip hosts the CSP does not allowlist: %+v", f)
		}
	}
}

func TestCSPBypassBaseURIHijackWithRelativeScripts(t *testing.T) {
	body := []byte(`<!doctype html><html><head>
<script src="/static/app.js"></script>
<script src="vendor.js"></script>
<script src="https://cdn.example.com/sdk.js"></script>
<script src="//cdn.example.com/sdk2.js"></script>
</head><body></body></html>`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Missing base-uri: the bypass precondition. Strict default-src
		// is not enough because base-uri does NOT inherit from default-src.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html")
		w.Write(body)
	}))
	defer srv.Close()

	findings, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "Base-URI hijack") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected base-uri hijack finding, got %d findings: %+v", len(findings), findings)
	}
	if hit.Severity != SeverityMedium {
		t.Errorf("base-uri hijack Severity = %q, want medium", hit.Severity)
	}
	// Should mention the relative scripts; should NOT mention absolute
	// or protocol-relative ones (those are not hijackable).
	if !strings.Contains(hit.Detail, "/static/app.js") {
		t.Errorf("Detail should list host-relative script: %s", hit.Detail)
	}
	if !strings.Contains(hit.Detail, "vendor.js") {
		t.Errorf("Detail should list path-relative script: %s", hit.Detail)
	}
	if strings.Contains(hit.Detail, "https://cdn.example.com/sdk.js") {
		t.Errorf("Detail should NOT list absolute script: %s", hit.Detail)
	}
	if strings.Contains(hit.Detail, "//cdn.example.com/sdk2.js") {
		t.Errorf("Detail should NOT list protocol-relative script: %s", hit.Detail)
	}
}

func TestCSPBypassBaseURISkipsWhenConstrained(t *testing.T) {
	body := []byte(`<script src="/static/app.js"></script>`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html")
		w.Write(body)
	}))
	defer srv.Close()

	findings, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "Base-URI hijack") {
			t.Errorf("base-uri hijack must not fire when base-uri 'none' is set: %+v", f)
		}
	}
}

func TestCSPBypassBaseURISkipsWhenNoRelativeScripts(t *testing.T) {
	body := []byte(`<script src="https://cdn.example.com/sdk.js"></script>`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html")
		w.Write(body)
	}))
	defer srv.Close()

	findings, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "Base-URI hijack") {
			t.Errorf("base-uri hijack must not fire without relative scripts: %+v", f)
		}
	}
}

func TestCSPScriptSrcAllowsHost(t *testing.T) {
	cases := []struct {
		name      string
		sources   []string
		candidate string
		want      bool
	}{
		{"exact host", []string{"ajax.googleapis.com"}, "ajax.googleapis.com", true},
		{"scheme + host", []string{"https://ajax.googleapis.com"}, "ajax.googleapis.com", true},
		{"scheme + host + port", []string{"https://ajax.googleapis.com:443"}, "ajax.googleapis.com", true},
		{"scheme + host + path", []string{"https://ajax.googleapis.com/ajax/"}, "ajax.googleapis.com", true},
		{"wildcard subdomain matches", []string{"*.googleapis.com"}, "ajax.googleapis.com", true},
		{"wildcard subdomain matches apex", []string{"*.googleapis.com"}, "googleapis.com", true},
		{"wildcard subdomain misses", []string{"*.googleapis.com"}, "googleapi.com", false},
		{"bare wildcard", []string{"*"}, "ajax.googleapis.com", true},
		{"scheme only https", []string{"https:"}, "ajax.googleapis.com", true},
		{"keyword self ignored", []string{"'self'", "'nonce-abc'"}, "ajax.googleapis.com", false},
		{"non-matching host", []string{"cdn.example.com"}, "ajax.googleapis.com", false},
		{"case insensitive", []string{"AJAX.GoogleAPIs.com"}, "ajax.googleapis.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := cspScriptSrcAllowsHost(tc.sources, tc.candidate)
			if ok != tc.want {
				t.Errorf("cspScriptSrcAllowsHost(%v, %q) = %v, want %v", tc.sources, tc.candidate, ok, tc.want)
			}
		})
	}
}

func TestConfirmsJSONP(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		body string
		want bool
	}{
		{"javascript content type with call", "application/javascript", "hyperzCspBypassCb({})", true},
		{"text/javascript with comment prefix", "text/javascript; charset=utf-8", "/**/hyperzCspBypassCb({})", true},
		{"x-javascript", "application/x-javascript", "try{hyperzCspBypassCb({});}catch(e){}", true},
		{"json content type rejected", "application/json", "hyperzCspBypassCb({})", false},
		{"html content type rejected", "text/html", "hyperzCspBypassCb({})", false},
		{"name in error string rejected", "application/javascript", "{\"error\":\"bad callback hyperzCspBypassCb name\"}", false},
		{"empty body", "application/javascript", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := confirmsJSONP(tc.ct, []byte(tc.body), cspBypassCallbackCanary)
			if got != tc.want {
				t.Errorf("confirmsJSONP(%q, %q) = %v, want %v", tc.ct, tc.body, got, tc.want)
			}
		})
	}
}

func TestIsAbsoluteOrProtocolRelative(t *testing.T) {
	cases := map[string]bool{
		"https://cdn.example.com/x.js": true,
		"http://cdn.example.com/x.js":  true,
		"//cdn.example.com/x.js":       true,
		"data:text/javascript,foo":     true,
		"/static/app.js":               false,
		"vendor.js":                    false,
		"../foo.js":                    false,
		"./foo.js":                     false,
		"":                             false,
	}
	for in, want := range cases {
		if got := isAbsoluteOrProtocolRelative(in); got != want {
			t.Errorf("isAbsoluteOrProtocolRelative(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCSPBypassDedupeKeyPerHost(t *testing.T) {
	// Same defect on two crawled pages of the same host collapses to one
	// DedupeKey per technique.
	srv := httptest.NewServer(staticNonceHandler(""))
	defer srv.Close()
	a, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/a"))
	if err != nil {
		t.Fatalf("Run a: %v", err)
	}
	b, err := CSPBypass{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/b"))
	if err != nil {
		t.Fatalf("Run b: %v", err)
	}
	if len(a) == 0 || len(b) == 0 {
		t.Fatalf("expected findings on both pages, got %d and %d", len(a), len(b))
	}
	keyOf := func(fs []Finding, want string) string {
		for _, f := range fs {
			if strings.Contains(f.Title, want) {
				return f.DedupeKey
			}
		}
		return ""
	}
	ak := keyOf(a, "nonce reused")
	bk := keyOf(b, "nonce reused")
	if ak == "" || bk == "" {
		t.Fatalf("nonce-reuse missing on a or b: %q, %q", ak, bk)
	}
	if ak != bk {
		t.Errorf("nonce-reuse DedupeKey should match per host, got %q vs %q", ak, bk)
	}
}

// overrideJSONPProbes swaps the package jsonpProbes table for the
// duration of a test and returns a restore func the test defers.
// Letting tests inject httptest URLs is the only way to exercise the
// JSONP probe end-to-end without depending on real third-party CDNs
// (whose JSONP support has been disappearing for years).
func overrideJSONPProbes(probes []jsonpProbe) func() {
	saved := jsonpProbes
	jsonpProbes = probes
	return func() { jsonpProbes = saved }
}

// mustHost returns the portless hostname for rawurl. The JSONP probe
// table is curated with hostnames (no port), and the host matcher in
// cspScriptSrcAllowsHost strips the CSP source's port before comparing,
// so tests must register their httptest hosts portless to match.
func mustHost(t *testing.T, rawurl string) string {
	t.Helper()
	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatalf("parse %q: %v", rawurl, err)
	}
	return u.Hostname()
}
