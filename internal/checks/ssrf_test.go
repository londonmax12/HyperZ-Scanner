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

func TestSSRFName(t *testing.T) {
	if got := (SSRF{}).Name(); got != "ssrf" {
		t.Fatalf("Name = %q, want ssrf", got)
	}
}

func TestSSRFLevel(t *testing.T) {
	// Default level: probe is a crafted request, must not run at passive.
	if got := (SSRF{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// vulnSSRFHandler attempts to fetch a URL from the query param and echoes
// connection errors into the response body - the canonical SSRF bug.
func vulnSSRFHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if urlParam == "" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "no url param")
			return
		}

		// Simulate a fetch attempt by trying to parse the URL.
		// In a real app, this would be an http.Get or similar.
		// For testing, we'll just echo a generic error if the URL looks wrong.
		if !strings.Contains(urlParam, "example") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "fetched: %s", urlParam)
			return
		}

		// When given the .example domain, simulate a connection error
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Error: Connection refused when attempting to fetch %s", urlParam)
	})
}

func TestSSRFDetectsVulnerableURLParam(t *testing.T) {
	srv := httptest.NewServer(vulnSSRFHandler(t))
	defer srv.Close()

	findings, err := SSRF{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/api/proxy"))
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
	if f.CWE != "CWE-918" {
		t.Errorf("CWE = %q, want CWE-918", f.CWE)
	}
	if !strings.Contains(f.Title, "url") {
		t.Errorf("Title should name the param: %q", f.Title)
	}
	if !strings.Contains(f.URL, "url=") {
		t.Errorf("URL should include the probe param: %q", f.URL)
	}
	if !strings.Contains(f.URL, "internal.example") {
		t.Errorf("URL should include the canary host: %q", f.URL)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
}

func TestSSRFEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(vulnSSRFHandler(t))
	defer srv.Close()

	findings, err := SSRF{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/api/proxy"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	if ev == nil || ev.Exchange == nil {
		t.Fatalf("Evidence/Exchange missing: %+v", ev)
	}
	if ev.Exchange.Method != http.MethodGet {
		t.Errorf("Exchange.Method = %q, want GET", ev.Exchange.Method)
	}
	if !strings.Contains(ev.Exchange.ResponseBody, "Connection refused") {
		t.Errorf("Exchange body should contain error marker, got: %q", ev.Exchange.ResponseBody)
	}
	if !strings.Contains(ev.Exchange.URL, "internal.example") {
		t.Errorf("Exchange.URL should include the probe param: %q", ev.Exchange.URL)
	}
}

func TestSSRFNoFindingOnSafeRequest(t *testing.T) {
	// Server doesn't try to fetch the parameter
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "safe response - no fetch attempted")
	}))
	defer srv.Close()

	findings, err := SSRF{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/api/proxy"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on safe response, got %d: %+v", len(findings), findings)
	}
}

func TestSSRFNoFindingWithoutErrorMarker(t *testing.T) {
	// Server echoes the param but without an error marker
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Processing request with: %s", urlParam)
	}))
	defer srv.Close()

	findings, err := SSRF{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/api/proxy"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without error marker, got %d: %+v", len(findings), findings)
	}
}

func TestSSRFDetectsMultipleVulnerableParams(t *testing.T) {
	// Handler that echoes multiple different URL params with error markers
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if url := r.URL.Query().Get("url"); url != "" && strings.Contains(url, "example") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Connection refused: %s", url)
			return
		}
		if endpoint := r.URL.Query().Get("endpoint"); endpoint != "" && strings.Contains(endpoint, "example") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Failed to fetch endpoint: %s", endpoint)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	findings, err := SSRF{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/api/proxy"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Should find at least the "url" and "endpoint" params
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d: %+v", len(findings), findings)
	}
	paramNames := make(map[string]bool)
	for _, f := range findings {
		// Extract param name from title like "Server-Side Request Forgery via query ?url="
		if strings.Contains(f.Title, "?url=") {
			paramNames["url"] = true
		}
		if strings.Contains(f.Title, "?endpoint=") {
			paramNames["endpoint"] = true
		}
	}
	if !paramNames["url"] {
		t.Errorf("expected to find 'url' param vulnerability")
	}
	if !paramNames["endpoint"] {
		t.Errorf("expected to find 'endpoint' param vulnerability")
	}
}

func TestSSRFErrorPatternMatching(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"connection refused", "Error: connection refused", true},
		{"dns failure", "getaddrinfo failed: No address associated with hostname", true},
		{"timeout", "Operation timed out", true},
		{"connection reset", "Connection reset by peer", true},
		{"python requests", "requests.exceptions.ConnectionError", true},
		{"node timeout", "socket timeout", true},
		{"java unknown host", "java.net.UnknownHostException", true},
		{"safe response", "Successfully processed request", false},
		{"generic error", "Error occurred", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ssrfMatchesError([]byte(tt.body))
			if (got != "") != tt.wantErr {
				t.Errorf("ssrfMatchesError(%q) = %q, wantErr %v", tt.body, got, tt.wantErr)
			}
		})
	}
}

func TestSSRFPathKeywordDetection(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/api/proxy", true},
		{"/image/avatar", true},
		{"/fetch", true},
		{"/webhook/receiver", true},
		{"/api/download", true},
		{"/screenshot/generate", true},
		{"/normal/api/endpoint", false},
		{"/api/users", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := looksProxyish(tt.path)
			if got != tt.want {
				t.Errorf("looksProxyish(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
