package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
)

func newTestClient(t *testing.T) *httpclient.Client {
	t.Helper()
	return httpclient.New(httpclient.Config{
		Timeout:   5 * time.Second,
		UserAgent: "test",
	})
}

func TestSecurityHeadersAllPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := SecurityHeaders{}
	findings, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestSecurityHeadersAllMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// All five missing headers collapse into a single finding so the report
	// shows one row per endpoint, not one per defect facet.
	if len(findings) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Check != "security-headers" {
		t.Errorf("unexpected check %q", f.Check)
	}
	if f.Target != srv.URL {
		t.Errorf("target = %q, want %q", f.Target, srv.URL)
	}
	if f.Title != "missing 5 security headers" {
		t.Errorf("title = %q, want %q", f.Title, "missing 5 security headers")
	}
	// Highest severity among the five rules is Medium (CSP/HSTS).
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	for _, h := range []string{
		"Content-Security-Policy",
		"Referrer-Policy",
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
	} {
		if !strings.Contains(f.Detail, h) {
			t.Errorf("detail missing %q: %q", h, f.Detail)
		}
		if !strings.Contains(f.Remediation, h+": ") {
			t.Errorf("remediation missing per-header entry for %q: %q", h, f.Remediation)
		}
	}
	for _, c := range []string{"CWE-693", "CWE-319", "CWE-1021", "CWE-200"} {
		if !strings.Contains(f.CWE, c) {
			t.Errorf("CWE field missing %q: %q", c, f.CWE)
		}
	}
}

func TestSecurityHeadersSeverityMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only CSP and HSTS missing â†’ both Medium, so the consolidated
		// finding inherits Medium too.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 consolidated", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	if f.Title != "missing 2 security headers" {
		t.Errorf("title = %q, want %q", f.Title, "missing 2 security headers")
	}
	for _, h := range []string{"Content-Security-Policy", "Strict-Transport-Security"} {
		if !strings.Contains(f.Detail, h) {
			t.Errorf("detail missing %q: %q", h, f.Detail)
		}
	}
}

func TestSecurityHeadersConsolidatedSeverityIsMaxOfMissing(t *testing.T) {
	// CSP missing (Medium) plus X-Frame-Options missing (Low). The
	// consolidated finding must take the worst severity so the report
	// surfaces the right priority for triage.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium (max of Medium+Low)", findings[0].Severity)
	}
}

func TestSecurityHeadersReturnsErrorOnNetworkFailure(t *testing.T) {
	// Use a URL that won't resolve. The default client honors timeout, so this
	// returns quickly on DNS failure.
	c := httpclient.New(httpclient.Config{
		Timeout:   1 * time.Second,
		UserAgent: "test",
	})
	_, err := SecurityHeaders{}.Run(context.Background(), c, nil, page.FromURL("http://hyperz-test-no-such-host.invalid"))
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
}

func TestSecurityHeadersSkipsNon200(t *testing.T) {
	// A 404 page with HTML body should not produce findings: browser-rendering
	// headers are not the security control for error responses, and crawls of
	// non-existent paths would otherwise flood the report.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on 404, got %d: %+v", len(findings), findings)
	}
}

func TestSecurityHeadersSkipsNonHTMLContentType(t *testing.T) {
	cases := map[string]string{
		"json":    "application/json",
		"image":   "image/png",
		"missing": "",
	}
	for name, ct := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if ct != "" {
					w.Header().Set("Content-Type", ct)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("expected 0 findings for Content-Type %q, got %d: %+v", ct, len(findings), findings)
			}
		})
	}
}

func TestSecurityHeadersAcceptsXHTML(t *testing.T) {
	// application/xhtml+xml is the served-as-XML variant of HTML; browsers
	// render it the same way, so the same header expectations apply.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xhtml+xml")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 consolidated finding on xhtml response, got %d: %+v", len(findings), findings)
	}
	if findings[0].Title != "missing 5 security headers" {
		t.Errorf("title = %q, want %q", findings[0].Title, "missing 5 security headers")
	}
}

func TestSecurityHeadersName(t *testing.T) {
	if got := (SecurityHeaders{}).Name(); got != "security-headers" {
		t.Fatalf("Name = %q, want security-headers", got)
	}
}

func TestSecurityHeadersPopulatesEnrichedFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send back a couple of headers so Evidence isn't empty, but omit CSP.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "nginx")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (only CSP missing)", len(findings))
	}
	f := findings[0]
	if f.CWE != "CWE-693" {
		t.Errorf("CWE = %q, want CWE-693", f.CWE)
	}
	if f.OWASP == "" {
		t.Errorf("OWASP empty")
	}
	if f.Remediation == "" {
		t.Errorf("Remediation empty")
	}
	if f.URL == "" {
		t.Errorf("URL empty - should be the observed request URL")
	}
	if f.DedupeKey == "" {
		t.Errorf("DedupeKey empty")
	}
	if f.Evidence == nil {
		t.Fatalf("Evidence is nil")
	}
	if f.Evidence.Method != "GET" || f.Evidence.Status != 200 {
		t.Errorf("Evidence method/status = %q/%d", f.Evidence.Method, f.Evidence.Status)
	}
	if !strings.Contains(f.Evidence.Snippet, "Server") {
		t.Errorf("Evidence snippet should contain observed headers; got %q", f.Evidence.Snippet)
	}
}

func TestSecurityHeadersDedupeKeyIsStableAndPerHost(t *testing.T) {
	// The consolidated finding's dedupe key must be deterministic across
	// runs for the same host (site-wide dedupe collapses repeated crawls
	// of the same host to one row), and must not vary with which subset
	// of headers happens to be missing on a particular page.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	run := func() string {
		findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].DedupeKey == "" {
			t.Fatal("DedupeKey empty")
		}
		return findings[0].DedupeKey
	}
	a, b := run(), run()
	if a != b {
		t.Errorf("dedupe key drifted across runs: %q vs %q", a, b)
	}
}

func TestMakeDedupeKeySeparatorAvoidsCollision(t *testing.T) {
	if MakeDedupeKey("ab", "c") == MakeDedupeKey("a", "bc") {
		t.Fatal("MakeDedupeKey must not collide on adjacent-part fusion")
	}
}

func TestHostScope(t *testing.T) {
	cases := map[string]string{
		"https://example.com/path?q=1": "https://example.com",
		"http://example.com:8080/x":    "http://example.com:8080",
		"not a url":                    "not a url",
	}
	for in, want := range cases {
		if got := HostScope(in); got != want {
			t.Errorf("HostScope(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMakeKeyScopesProduceDistinctKeys(t *testing.T) {
	const check = "demo"
	const target = "https://example.com/login?next=/"
	host := MakeKey(check, ScopeHost, target, "rule:x")
	page := MakeKey(check, ScopePage, target, "rule:x")
	param := MakeKey(check, ScopeParam, target, "rule:x")
	// Same (check, parts) at different scopes must not collide, even though
	// ScopePage and ScopeParam derive the same URL component - the scope
	// tag in the hash keeps the keyspaces separate.
	if host == page || page == param || host == param {
		t.Fatalf("scopes collapsed: host=%q page=%q param=%q", host, page, param)
	}
}

func TestMakeKeyScopeHostStableAcrossPaths(t *testing.T) {
	// ScopeHost ignores path and query: the same site-wide misconfig hit on
	// every crawled page must produce one key.
	a := MakeKey("hdr", ScopeHost, "https://example.com/login", "missing-header:CSP")
	b := MakeKey("hdr", ScopeHost, "https://example.com/admin?x=1", "missing-header:CSP")
	if a != b {
		t.Errorf("ScopeHost should ignore path/query: %q vs %q", a, b)
	}
}

func TestMakeKeyScopePageIgnoresQuery(t *testing.T) {
	// Probes typically rewrite the query string; the key shouldn't fragment
	// just because the probe URL has a different ?foo= than the page URL.
	a := MakeKey("redir", ScopePage, "https://example.com/login", "param:next")
	b := MakeKey("redir", ScopePage, "https://example.com/login?next=evil", "param:next")
	if a != b {
		t.Errorf("ScopePage should ignore query: %q vs %q", a, b)
	}
}

func TestMakeKeyFallsBackToRawTargetWhenUnparseable(t *testing.T) {
	// Two distinct garbage inputs must not collapse to the same hash.
	a := MakeKey("c", ScopeHost, "garbage-one", "x")
	b := MakeKey("c", ScopeHost, "garbage-two", "x")
	if a == b {
		t.Fatalf("unparseable targets collapsed to one key: %q", a)
	}
}
