package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// findOpenRedirect locates the Lua open-redirect check in the
// embedded catalog. Tests assert against the same name the registry
// will use, so a typo in the .lua name fails here rather than at
// scan time.
func findOpenRedirect(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "open-redirect" {
			return c
		}
	}
	t.Fatal("open-redirect Lua check not found in embedded catalog")
	return nil
}

// vulnRedirectHandler echoes the `next` query into Location verbatim,
// the canonical open-redirect bug. Cloned from the Go test so the
// Lua port runs against the exact same target shape.
func vulnRedirectHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", next)
		w.WriteHeader(http.StatusFound)
	})
}

func TestLuaOpenRedirectMetadata(t *testing.T) {
	c := findOpenRedirect(t)
	if c.Name() != "open-redirect" {
		t.Fatalf("Name = %q, want open-redirect", c.Name())
	}
	if c.Level() != checks.LevelDefault {
		t.Fatalf("Level = %v, want default", c.Level())
	}
}

func TestLuaOpenRedirectDetectsVulnerableNextParam(t *testing.T) {
	srv := httptest.NewServer(vulnRedirectHandler(t))
	defer srv.Close()

	findings, err := findOpenRedirect(t).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != checks.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.CWE != "CWE-601" {
		t.Errorf("CWE = %q, want CWE-601", f.CWE)
	}
	if !strings.Contains(f.Title, "next") {
		t.Errorf("Title should name the param: %q", f.Title)
	}
	if !strings.Contains(f.URL, "next=") {
		t.Errorf("URL should include the probe param: %q", f.URL)
	}
	if !strings.Contains(f.URL, "evil.example") {
		t.Errorf("URL should include the canary host: %q", f.URL)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
}

func TestLuaOpenRedirectEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(vulnRedirectHandler(t))
	defer srv.Close()

	findings, err := findOpenRedirect(t).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
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
	if ev.Exchange.Status != http.StatusFound {
		t.Errorf("Exchange.Status = %d, want 302", ev.Exchange.Status)
	}
	if got := ev.Exchange.ResponseHeaders.Get("Location"); !strings.Contains(got, "evil.example") {
		t.Errorf("Exchange Location = %q, want canary host", got)
	}
}

func TestLuaOpenRedirectNoFindingOnSafeRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := findOpenRedirect(t).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on same-origin redirect, got %d: %+v", len(findings), findings)
	}
}

func TestLuaOpenRedirectRespectsScope(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc, err := scope.New(scope.Config{Hosts: []string{"only-this-host.invalid"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	findings, err := findOpenRedirect(t).Run(context.Background(), newTestClient(t), sc, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings out of scope, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; out-of-scope check must not probe", got)
	}
}

func TestLuaOpenRedirectMultipleVulnerableParamsDistinctFindings(t *testing.T) {
	reflect := []string{"next", "redirect", "goto"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range reflect {
			if v := r.URL.Query().Get(name); v != "" {
				w.Header().Set("Location", v)
				w.WriteHeader(http.StatusFound)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := findOpenRedirect(t).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != len(reflect) {
		t.Fatalf("expected %d findings (one per vulnerable param), got %d: %+v", len(reflect), len(findings), findings)
	}
	keys := make(map[string]string, len(findings))
	for _, f := range findings {
		if other, dup := keys[f.DedupeKey]; dup {
			t.Errorf("dedupe collision: %q and %q share key %q", other, f.Title, f.DedupeKey)
		}
		keys[f.DedupeKey] = f.Title
	}
}

// TestLuaOpenRedirectParityWithGo locks in identical detection
// behavior on the canonical vulnerable target: same finding count,
// same dedupe keys, same severity. A divergence here is the signal
// the Lua port has drifted from its Go reference.
func TestLuaOpenRedirectParityWithGo(t *testing.T) {
	srv := httptest.NewServer(vulnRedirectHandler(t))
	defer srv.Close()

	goFs, err := (checks.OpenRedirect{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Go check Run: %v", err)
	}
	luaFs, err := findOpenRedirect(t).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Lua check Run: %v", err)
	}
	if len(goFs) != len(luaFs) {
		t.Fatalf("finding count mismatch: go=%d lua=%d", len(goFs), len(luaFs))
	}
	goByTitle := map[string]checks.Finding{}
	for _, f := range goFs {
		goByTitle[f.Title] = f
	}
	for _, f := range luaFs {
		g, ok := goByTitle[f.Title]
		if !ok {
			t.Errorf("Lua produced unmatched finding %q", f.Title)
			continue
		}
		if f.DedupeKey != g.DedupeKey {
			t.Errorf("%q dedupe key drift: lua=%q go=%q", f.Title, f.DedupeKey, g.DedupeKey)
		}
		if f.Severity != g.Severity {
			t.Errorf("%q severity drift: lua=%q go=%q", f.Title, f.Severity, g.Severity)
		}
		if f.CWE != g.CWE {
			t.Errorf("%q CWE drift: lua=%q go=%q", f.Title, f.CWE, g.CWE)
		}
	}
}
