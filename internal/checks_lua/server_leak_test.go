package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
)

// findServerLeak pulls the loaded server-leak check out of the
// embedded catalog. Tests assert against the same name the registry
// will use, so a typo in the .lua name fails here rather than at
// scan time.
func findServerLeak(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "server-leak" {
			return c
		}
	}
	t.Fatal("server-leak Lua check not found in embedded catalog")
	return nil
}

func newTestClient(t *testing.T) *httpclient.Client {
	t.Helper()
	return httpclient.New(httpclient.Config{
		Timeout:   5 * time.Second,
		UserAgent: "test",
	})
}

func TestLuaServerLeakName(t *testing.T) {
	c := findServerLeak(t)
	if c.Name() != "server-leak" {
		t.Fatalf("Name = %q, want server-leak", c.Name())
	}
	if c.Level() != checks.LevelPassive {
		t.Fatalf("Level = %v, want passive", c.Level())
	}
}

func TestLuaServerLeakNoHeadersNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Server"] = nil
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := findServerLeak(t).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestLuaServerLeakBothHeadersPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := findServerLeak(t).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
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
		if f.Severity != checks.SeverityInfo {
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

func TestLuaServerLeakPopulatesEnrichedFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := findServerLeak(t).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
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

// TestLuaServerLeakDedupeMatchesGo locks in the parity contract
// between the Lua port and the Go original: same response, same
// dedupe key. If a port drift creeps in (different scope, different
// part composition), this assertion catches it before findings
// silently start re-firing across crawled pages.
func TestLuaServerLeakDedupeMatchesGo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	goFs, err := (checks.ServerLeak{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Go check Run: %v", err)
	}
	luaFs, err := findServerLeak(t).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Lua check Run: %v", err)
	}
	if len(goFs) != len(luaFs) {
		t.Fatalf("finding count mismatch: go=%d lua=%d", len(goFs), len(luaFs))
	}
	goKeys := map[string]string{}
	for _, f := range goFs {
		goKeys[f.Title] = f.DedupeKey
	}
	for _, f := range luaFs {
		if got, want := f.DedupeKey, goKeys[f.Title]; got != want {
			t.Errorf("%q dedupe key drift: lua=%q go=%q", f.Title, got, want)
		}
	}
}

func TestLuaServerLeakReturnsErrorOnNetworkFailure(t *testing.T) {
	c := httpclient.New(httpclient.Config{
		Timeout:   1 * time.Second,
		UserAgent: "test",
	})
	_, err := findServerLeak(t).Run(context.Background(), c, nil, page.FromURL("http://hyperz-test-no-such-host.invalid"))
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
}
