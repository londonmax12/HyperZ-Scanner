package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestJSLibsKnownVulnName(t *testing.T) {
	if got := (JSLibsKnownVuln{}).Name(); got != "js-libs-known-vuln" {
		t.Fatalf("Name = %q, want js-libs-known-vuln", got)
	}
}

func TestJSLibsKnownVulnLevel(t *testing.T) {
	if got := (JSLibsKnownVuln{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestJSLibsKnownVulnNoScriptsNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Test</title></head><body>No scripts</body></html>`))
	}))
	defer srv.Close()

	findings, err := JSLibsKnownVuln{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestJSLibsKnownVulnDetectJQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
	<script src="https://code.jquery.com/jquery-1.6.0.min.js"></script>
</head>
<body></body>
</html>`))
	}))
	defer srv.Close()

	findings, err := JSLibsKnownVuln{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Check != "js-libs-known-vuln" {
		t.Errorf("Check = %q, want js-libs-known-vuln", f.Check)
	}
	if !strings.Contains(f.Title, "jQuery") {
		t.Errorf("Title should mention jQuery: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "1.6.0") {
		t.Errorf("Detail should contain version 1.6.0: %q", f.Detail)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
}

func TestJSLibsKnownVulnDetectMultipleLibraries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
	<script src="https://code.jquery.com/jquery-1.7.0.min.js"></script>
	<script src="https://cdn.jsdelivr.net/npm/bootstrap@2.3.2/dist/js/bootstrap.min.js"></script>
</head>
<body></body>
</html>`))
	}))
	defer srv.Close()

	findings, err := JSLibsKnownVuln{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}

	libs := map[string]bool{}
	for _, f := range findings {
		if strings.Contains(f.Title, "jQuery") {
			libs["jQuery"] = true
		} else if strings.Contains(f.Title, "Bootstrap") {
			libs["Bootstrap"] = true
		}
	}

	if !libs["jQuery"] || !libs["Bootstrap"] {
		t.Fatalf("expected both jQuery and Bootstrap detections; got %v", libs)
	}
}

func TestJSLibsKnownVulnIgnoresNonHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": "no scripts here"}`))
	}))
	defer srv.Close()

	findings, err := JSLibsKnownVuln{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for JSON response, got %d", len(findings))
	}
}

func TestJSLibsKnownVulnEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := JSLibsKnownVuln{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty body, got %d", len(findings))
	}
}

func TestJSLibsKnownVulnDetectReactNoKnownVuln(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
	<script src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script>
</head>
<body></body>
</html>`))
	}))
	defer srv.Close()

	findings, err := JSLibsKnownVuln{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityInfo {
		t.Errorf("Severity = %q, want info for non-vulnerable version", f.Severity)
	}
	if !strings.Contains(f.Detail, "no known vulnerabilities") {
		t.Errorf("Detail should mention no vulnerabilities: %q", f.Detail)
	}
}

func TestJSLibsKnownVulnEvidencePopulated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
	<script src="https://code.jquery.com/jquery-1.6.0.min.js"></script>
</head>
<body></body>
</html>`))
	}))
	defer srv.Close()

	findings, err := JSLibsKnownVuln{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Target == "" {
		t.Error("Target empty")
	}
	if f.URL == "" {
		t.Error("URL empty")
	}
	if f.OWASP == "" {
		t.Error("OWASP empty")
	}
	if f.Remediation == "" {
		t.Error("Remediation empty")
	}
	if f.DedupeKey == "" {
		t.Error("DedupeKey empty")
	}
	if f.Evidence == nil {
		t.Fatal("Evidence is nil")
	}
	if f.Evidence.Status != 200 {
		t.Errorf("Evidence Status = %d, want 200", f.Evidence.Status)
	}
}

func TestJSLibsKnownVulnDedupeStable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
	<script src="https://code.jquery.com/jquery-1.6.0.min.js"></script>
</head>
<body></body>
</html>`))
	}))
	defer srv.Close()

	run := func() string {
		fs, err := JSLibsKnownVuln{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
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
		t.Errorf("dedupe key drifted: %q vs %q", key1, key2)
	}
}
