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

func TestCORSConfigName(t *testing.T) {
	if got := (CORSConfig{}).Name(); got != "cors-config" {
		t.Fatalf("Name = %q, want cors-config", got)
	}
}

func TestCORSConfigLevel(t *testing.T) {
	if got := (CORSConfig{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestCORSConfigNoHeadersNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CORSConfig{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCORSConfigWildcardWithoutCredentialsIsSilent(t *testing.T) {
	// `ACAO: *` alone is the standard public-API marker; do not alert on it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CORSConfig{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCORSConfigWildcardWithCredentialsIsHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CORSConfig{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.CWE != "CWE-942" {
		t.Errorf("CWE = %q, want CWE-942", f.CWE)
	}
	if !strings.Contains(f.Title, "any origin with credentials") {
		t.Errorf("title = %q, want wildcard-with-credentials phrasing", f.Title)
	}
}

func TestCORSConfigNullOriginIsMedium(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "null")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CORSConfig{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	if f.CWE != "CWE-942" {
		t.Errorf("CWE = %q, want CWE-942", f.CWE)
	}
	if !strings.Contains(f.Title, "null origin") {
		t.Errorf("title = %q, want null-origin phrasing", f.Title)
	}
	// Without credentials the qualifier suffix must not appear.
	if strings.Contains(f.Detail, "compounds the impact") {
		t.Errorf("detail must not mention credentials when ACAC is absent: %q", f.Detail)
	}
}

func TestCORSConfigNullOriginWithCredentialsAddsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "null")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CORSConfig{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium (per spec, null-origin stays medium even with credentials)", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Detail, "compounds the impact") {
		t.Errorf("detail should call out credentials: %q", findings[0].Detail)
	}
}

func TestCORSConfigForeignOriginWithCredentialsIsHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://attacker.example")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CORSConfig{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.CWE != "CWE-942" {
		t.Errorf("CWE = %q, want CWE-942", f.CWE)
	}
	if !strings.Contains(f.Detail, "https://attacker.example") {
		t.Errorf("detail should include the foreign origin: %q", f.Detail)
	}
}

func TestCORSConfigForeignOriginWithoutCredentialsIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://partner.example")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CORSConfig{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("foreign origin without credentials should not fire; got %d findings: %+v", len(findings), findings)
	}
}

func TestCORSConfigSelfOriginIsSilent(t *testing.T) {
	// When ACAO echoes the page's own origin, the server is just
	// normalizing or echoing the trivial self case - no cross-origin
	// trust to flag.
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", serverURL)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	serverURL = srv.URL

	findings, err := CORSConfig{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("self-origin ACAO should not fire; got %d findings: %+v", len(findings), findings)
	}
}

func TestCORSConfigCredentialsFalseIsTreatedAsAbsent(t *testing.T) {
	// `ACAC: false` is the explicit "no credentials" answer; the
	// wildcard-with-credentials rule must not fire just because the header
	// is present with a non-true value.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "false")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CORSConfig{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("ACAC: false should not enable the wildcard rule; got %d findings: %+v", len(findings), findings)
	}
}

func TestCORSConfigPopulatesEnrichedFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CORSConfig{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Target != srv.URL || f.URL != srv.URL {
		t.Errorf("Target/URL = %q/%q, want %q", f.Target, f.URL, srv.URL)
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
	if !strings.Contains(f.Evidence.Snippet, "Access-Control-Allow-Origin") {
		t.Errorf("Evidence snippet should contain ACAO header; got %q", f.Evidence.Snippet)
	}
}

func TestCORSConfigDedupeKeyIsStableAndPerHost(t *testing.T) {
	// The same misconfig observed twice on the same host must produce the
	// same key; different rule branches must produce different keys.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	run := func() string {
		fs, err := CORSConfig{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(fs) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(fs))
		}
		return fs[0].DedupeKey
	}
	a, b := run(), run()
	if a != b {
		t.Errorf("dedupe key drifted across runs: %q vs %q", a, b)
	}

	// Different rule should produce a different key against the same host.
	srvNull := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "null")
		w.WriteHeader(http.StatusOK)
	}))
	defer srvNull.Close()
	fs, err := CORSConfig{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srvNull.URL))
	if err != nil {
		t.Fatalf("Run (null): %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected 1 null-origin finding, got %d", len(fs))
	}
	if fs[0].DedupeKey == a {
		t.Errorf("wildcard-with-credentials and null-origin must not collide on the same key: %q", a)
	}
}

func TestCORSConfigReturnsErrorOnNetworkFailure(t *testing.T) {
	c := httpclient.New(httpclient.Config{
		Timeout:   1 * time.Second,
		UserAgent: "test",
	})
	_, err := CORSConfig{}.Run(context.Background(), c, nil, page.FromURL("http://hyperz-test-no-such-host.invalid"))
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
}
