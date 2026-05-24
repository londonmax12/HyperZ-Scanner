package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestHostHeaderInjectionName(t *testing.T) {
	if got := (HostHeaderInjection{}).Name(); got != "host-header-injection" {
		t.Fatalf("Name = %q, want host-header-injection", got)
	}
}

func TestHostHeaderInjectionLevel(t *testing.T) {
	// Default level: probe is a crafted request, must not run at passive.
	if got := (HostHeaderInjection{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// vulnHostHeaderHandler echoes the Host header into the response body -
// the canonical host header injection bug.
func vulnHostHeaderHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("Host")
		if host == "" {
			host = r.Host
		}
		// Simulate a canonical URL or absolute URL generation that uses the Host header
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head>
<link rel="canonical" href="https://%s/page">
</head><body>
Visit us at https://%s for more info.
</body></html>`, host, host)
	})
}

func TestHostHeaderInjectionDetectsReflection(t *testing.T) {
	srv := httptest.NewServer(vulnHostHeaderHandler(t))
	defer srv.Close()

	findings, err := HostHeaderInjection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.CWE != "CWE-74" {
		t.Errorf("CWE = %q, want CWE-74", f.CWE)
	}
	if !strings.Contains(strings.ToLower(f.Title), "host header") {
		t.Errorf("Title should mention host header: %q", f.Title)
	}
	if !strings.Contains(strings.ToLower(f.Detail), "cache poisoning") {
		t.Errorf("Detail should mention cache poisoning: %q", f.Detail)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
}

func TestHostHeaderInjectionNoFalsePositives(t *testing.T) {
	// Safe handler that doesn't use the Host header
	safeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body>Hello, this is a safe page.</body></html>`)
	})

	srv := httptest.NewServer(safeHandler)
	defer srv.Close()

	findings, err := HostHeaderInjection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe page, got %d: %+v", len(findings), findings)
	}
}

func TestHostHeaderInjectionEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(vulnHostHeaderHandler(t))
	defer srv.Close()

	findings, err := HostHeaderInjection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings")
	}
	f := findings[0]
	if f.Evidence == nil {
		t.Errorf("Evidence is nil")
		return
	}
	if f.Evidence.Exchange == nil {
		t.Errorf("Exchange is nil")
		return
	}
	if f.Evidence.Exchange.ResponseBody == "" {
		t.Errorf("Response body must be captured in exchange")
	}
	// Verify the canary host is in the exchange evidence
	if !strings.Contains(strings.ToLower(f.Evidence.Exchange.ResponseBody), "evil.example") {
		t.Errorf("Response should contain canary host: %q", f.Evidence.Exchange.ResponseBody)
	}
}
