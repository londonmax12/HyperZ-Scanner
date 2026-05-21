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
	findings, err := c.Run(context.Background(), newTestClient(t), srv.URL)
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

	findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), srv.URL)
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

	findings, err := SecurityHeaders{}.Run(context.Background(), newTestClient(t), srv.URL)
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
	_, err := SecurityHeaders{}.Run(context.Background(), c, "http://hyperz-test-no-such-host.invalid")
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
}

func TestSecurityHeadersName(t *testing.T) {
	if got := (SecurityHeaders{}).Name(); got != "security-headers" {
		t.Fatalf("Name = %q, want security-headers", got)
	}
}
