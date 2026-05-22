package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/page"
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
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d: %+v", len(findings), findings)
	}
	gotHeaders := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Check != "security-headers" {
			t.Errorf("unexpected check %q", f.Check)
		}
		if f.Target != srv.URL {
			t.Errorf("target = %q, want %q", f.Target, srv.URL)
		}
		if !strings.HasPrefix(f.Title, "missing security header: ") {
			t.Errorf("title %q missing prefix", f.Title)
		}
		gotHeaders = append(gotHeaders, strings.TrimPrefix(f.Title, "missing security header: "))
	}
	sort.Strings(gotHeaders)
	want := []string{
		"Content-Security-Policy",
		"Referrer-Policy",
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
	}
	for i, h := range want {
		if gotHeaders[i] != h {
			t.Errorf("header %d = %q, want %q", i, gotHeaders[i], h)
		}
	}
}

func TestSecurityHeadersSeverityMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only CSP and HSTS missing → both Medium.
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
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		if f.Severity != SeverityMedium {
			t.Errorf("%q: severity = %q, want medium", f.Title, f.Severity)
		}
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

func TestSecurityHeadersName(t *testing.T) {
	if got := (SecurityHeaders{}).Name(); got != "security-headers" {
		t.Fatalf("Name = %q, want security-headers", got)
	}
}

func TestSecurityHeadersPopulatesEnrichedFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send back a couple of headers so Evidence isn't empty, but omit CSP.
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

func TestSecurityHeadersDedupeKeysAreStableAndPerHeader(t *testing.T) {
	// Two requests to the same host must produce the same dedupe key for the
	// same missing header (that's the whole point - site-wide dedupe). And
	// keys for different missing headers must differ.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	run := func() map[string]string {
		findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		out := map[string]string{}
		for _, f := range findings {
			out[strings.TrimPrefix(f.Title, "missing security header: ")] = f.DedupeKey
		}
		return out
	}
	a, b := run(), run()
	if len(a) != 5 || len(b) != 5 {
		t.Fatalf("expected 5 findings each; got %d / %d", len(a), len(b))
	}
	for header, key := range a {
		if b[header] != key {
			t.Errorf("dedupe key for %q drifted: %q vs %q", header, key, b[header])
		}
	}
	seen := map[string]string{}
	for header, key := range a {
		if other, dup := seen[key]; dup {
			t.Errorf("headers %q and %q share dedupe key %q", other, header, key)
		}
		seen[key] = header
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
