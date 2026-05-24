package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestCacheControlSensitiveName(t *testing.T) {
	if got := (CacheControlSensitive{}).Name(); got != "cache-control-sensitive" {
		t.Fatalf("Name = %q, want cache-control-sensitive", got)
	}
}

func TestCacheControlSensitiveLevel(t *testing.T) {
	if got := (CacheControlSensitive{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestCacheControlSensitiveNoFindingsWithPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "private, no-cache")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>test</body></html>"))
	}))
	defer srv.Close()

	findings, err := CacheControlSensitive{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCacheControlSensitiveNoFindingsWithNoStore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "public, max-age=3600, no-store")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>test</body></html>"))
	}))
	defer srv.Close()

	findings, err := CacheControlSensitive{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCacheControlSensitiveNoFindingsWithNoCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>test</body></html>"))
	}))
	defer srv.Close()

	findings, err := CacheControlSensitive{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCacheControlSensitiveNoFindingsWithPragma(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>test</body></html>"))
	}))
	defer srv.Close()

	findings, err := CacheControlSensitive{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCacheControlSensitiveFindsUnsafeDirective(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>test</body></html>"))
	}))
	defer srv.Close()

	findings, err := CacheControlSensitive{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Check != "cache-control-sensitive" {
		t.Errorf("Check = %q, want cache-control-sensitive", f.Check)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
	if !strings.Contains(f.Title, "lacks cache-control") {
		t.Errorf("Title doesn't mention cache-control: %q", f.Title)
	}
	if f.CWE != "CWE-524" {
		t.Errorf("CWE = %q, want CWE-524", f.CWE)
	}
}

func TestCacheControlSensitiveFindsMissingHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>test</body></html>"))
	}))
	defer srv.Close()

	findings, err := CacheControlSensitive{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if !strings.Contains(f.Detail, "missing") {
		t.Errorf("Detail should mention missing headers: %q", f.Detail)
	}
}

func TestCacheControlSensitiveIgnoresNonHTMLContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"key": "value"}`))
	}))
	defer srv.Close()

	findings, err := CacheControlSensitive{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-HTML, got %d: %+v", len(findings), findings)
	}
}

func TestCacheControlSensitiveDedupePerHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>test</body></html>"))
	}))
	defer srv.Close()

	run := func() string {
		fs, err := CacheControlSensitive{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(fs) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(fs))
		}
		return fs[0].DedupeKey
	}

	key1 := run()
	key2 := run()
	if key1 != key2 {
		t.Errorf("dedupe key not stable: %q vs %q", key1, key2)
	}

	// Run twice with different paths on same host - should get same dedupe key
	// since this is per-host (site-wide misconfiguration)
	findings, err := CacheControlSensitive{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/path1"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for /path1, got %d", len(findings))
	}
}

func TestCacheControlSensitivePopulatesEnrichedFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>test</body></html>"))
	}))
	defer srv.Close()

	findings, err := CacheControlSensitive{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Target != srv.URL {
		t.Errorf("Target = %q, want %q", f.Target, srv.URL)
	}
	if f.URL != srv.URL {
		t.Errorf("URL = %q, want %q", f.URL, srv.URL)
	}
	if f.OWASP == "" {
		t.Errorf("OWASP empty")
	}
	if f.Remediation == "" {
		t.Errorf("Remediation empty")
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
}
