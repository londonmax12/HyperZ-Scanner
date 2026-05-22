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

func TestServerLeakName(t *testing.T) {
	if got := (ServerLeak{}).Name(); got != "server-leak" {
		t.Fatalf("Name = %q, want server-leak", got)
	}
}

func TestServerLeakLevel(t *testing.T) {
	if got := (ServerLeak{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestServerLeakNoHeadersNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// httptest defaults include nothing that triggers the check. Belt and
		// braces: explicitly clear the Server header that Go injects on some
		// paths to ensure a clean baseline.
		w.Header()["Server"] = nil
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := ServerLeak{}.Run(context.Background(), newTestClient(t), nil, srv.URL)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestServerLeakBothHeadersPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := ServerLeak{}.Run(context.Background(), newTestClient(t), nil, srv.URL)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	gotHeaders := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Check != "server-leak" {
			t.Errorf("unexpected check %q", f.Check)
		}
		if f.Severity != SeverityInfo {
			t.Errorf("%q severity = %q, want info", f.Title, f.Severity)
		}
		if f.CWE != "CWE-200" {
			t.Errorf("%q CWE = %q, want CWE-200", f.Title, f.CWE)
		}
		switch {
		case strings.Contains(f.Title, "Server"):
			gotHeaders = append(gotHeaders, "Server")
			if !strings.Contains(f.Detail, "nginx/1.18.0") {
				t.Errorf("Server detail missing value: %q", f.Detail)
			}
		case strings.Contains(f.Title, "X-Powered-By"):
			gotHeaders = append(gotHeaders, "X-Powered-By")
			if !strings.Contains(f.Detail, "PHP/7.4") {
				t.Errorf("X-Powered-By detail missing value: %q", f.Detail)
			}
		}
	}
	sort.Strings(gotHeaders)
	want := []string{"Server", "X-Powered-By"}
	for i, h := range want {
		if gotHeaders[i] != h {
			t.Fatalf("headers = %v, want %v", gotHeaders, want)
		}
	}
}

func TestServerLeakPopulatesEnrichedFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := ServerLeak{}.Run(context.Background(), newTestClient(t), nil, srv.URL)
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
	if f.URL == "" {
		t.Errorf("URL empty - should be the observed request URL")
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
	if !strings.Contains(f.Evidence.Snippet, "Server") {
		t.Errorf("Evidence snippet should contain observed headers; got %q", f.Evidence.Snippet)
	}
}

func TestServerLeakDedupeStableAndPerHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	run := func() map[string]string {
		fs, err := ServerLeak{}.Run(context.Background(), newTestClient(t), nil, srv.URL)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		out := make(map[string]string, len(fs))
		for _, f := range fs {
			out[f.Title] = f.DedupeKey
		}
		return out
	}
	a, b := run(), run()
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("expected 2 findings each; got %d / %d", len(a), len(b))
	}
	for title, key := range a {
		if b[title] != key {
			t.Errorf("dedupe key for %q drifted: %q vs %q", title, key, b[title])
		}
	}
	seen := map[string]string{}
	for title, key := range a {
		if other, dup := seen[key]; dup {
			t.Errorf("%q and %q share dedupe key %q", other, title, key)
		}
		seen[key] = title
	}
}

func TestServerLeakReturnsErrorOnNetworkFailure(t *testing.T) {
	c := httpclient.New(httpclient.Config{
		Timeout:   1 * time.Second,
		UserAgent: "test",
	})
	_, err := ServerLeak{}.Run(context.Background(), c, nil, "http://hyperz-test-no-such-host.invalid")
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
}
