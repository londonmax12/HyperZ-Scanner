package checks_lua

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/browser"
	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findDOMXSS(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "dom-xss" {
			return c
		}
	}
	t.Fatal("dom-xss Lua check not found")
	return nil
}

// fakeBrowserPool is the same test double the Go-side dom_xss_test.go
// uses, restated here so the Lua parity tests do not depend on the
// internal/checks test binary. Records every Visit call and fires the
// canary binding whenever the probe URL satisfies fireOn / visitFn.
type fakeBrowserPool struct {
	mu      sync.Mutex
	visits  []string
	fireOn  []string
	visitFn func(url, token string) bool
}

func (p *fakeBrowserPool) Visit(_ context.Context, url, token string, _ time.Duration) (bool, error) {
	p.mu.Lock()
	p.visits = append(p.visits, url)
	p.mu.Unlock()
	if p.visitFn != nil {
		return p.visitFn(url, token), nil
	}
	for _, needle := range p.fireOn {
		if strings.Contains(url, needle) {
			return true, nil
		}
	}
	return false, nil
}

func (p *fakeBrowserPool) Close() {}

func (p *fakeBrowserPool) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.visits))
	copy(out, p.visits)
	return out
}

// TestLuaDOMXSSSkipsWhenNoBrowserAttached asserts both implementations
// return zero findings (and no error) when the operator did not opt
// into --js, i.e. no browser pool is attached to ctx.
func TestLuaDOMXSSSkipsWhenNoBrowserAttached(t *testing.T) {
	p := page.FromURL("https://example.com/?q=1")

	goFs, err := checks.DOMXSS{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %d", len(goFs))
	}
	luaC := findDOMXSS(t)
	luaFs, err := luaC.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %d", len(luaFs))
	}
}

// TestLuaDOMXSSFragmentSinkParity asserts both implementations emit
// one High-severity location.hash finding with byte-aligned severity /
// CWE / OWASP / title source / DedupeKey when the fake pool fires on
// the fragment probe.
func TestLuaDOMXSSFragmentSinkParity(t *testing.T) {
	p := page.FromURL("https://example.com/profile")

	goPool := &fakeBrowserPool{fireOn: []string{"#"}}
	goCtx := checks.WithBrowser(context.Background(), goPool)
	goFs, err := checks.DOMXSS{}.Run(goCtx, nil, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 1 {
		t.Fatalf("go: expected 1 finding, got %d: %+v", len(goFs), goFs)
	}

	luaPool := &fakeBrowserPool{fireOn: []string{"#"}}
	luaCtx := checks.WithBrowser(context.Background(), luaPool)
	luaC := findDOMXSS(t)
	luaFs, err := luaC.Run(luaCtx, nil, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 1 {
		t.Fatalf("lua: expected 1 finding, got %d: %+v", len(luaFs), luaFs)
	}

	goF := goFs[0]
	luaF := luaFs[0]
	if goF.Severity != luaF.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goF.Severity, luaF.Severity)
	}
	if goF.CWE != luaF.CWE {
		t.Errorf("CWE drift: go=%q lua=%q", goF.CWE, luaF.CWE)
	}
	if goF.OWASP != luaF.OWASP {
		t.Errorf("OWASP drift: go=%q lua=%q", goF.OWASP, luaF.OWASP)
	}
	if !strings.Contains(goF.Title, "location.hash") || !strings.Contains(luaF.Title, "location.hash") {
		t.Errorf("title should mention location.hash\n go=%q\nlua=%q", goF.Title, luaF.Title)
	}
	if goF.DedupeKey != luaF.DedupeKey {
		t.Errorf("dedupe drift:\n go=%q\nlua=%q", goF.DedupeKey, luaF.DedupeKey)
	}
}

// TestLuaDOMXSSQueryParamSinkParity asserts both implementations emit
// one location.search finding scoped to the vulnerable param "q" when
// the fake pool fires only on probes that land the binding in q.
// Severity / CWE / OWASP / title source / DedupeKey must match.
func TestLuaDOMXSSQueryParamSinkParity(t *testing.T) {
	p := page.FromURL("https://example.com/search?q=hi&lang=en")

	visitFn := func(rawurl, _ string) bool {
		u, err := url.Parse(rawurl)
		if err != nil {
			return false
		}
		return strings.Contains(u.Query().Get("q"), browser.BindingName)
	}

	goPool := &fakeBrowserPool{visitFn: visitFn}
	goCtx := checks.WithBrowser(context.Background(), goPool)
	goFs, err := checks.DOMXSS{}.Run(goCtx, nil, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 1 {
		t.Fatalf("go: expected 1 finding for q, got %d: %+v", len(goFs), goFs)
	}

	luaPool := &fakeBrowserPool{visitFn: visitFn}
	luaCtx := checks.WithBrowser(context.Background(), luaPool)
	luaC := findDOMXSS(t)
	luaFs, err := luaC.Run(luaCtx, nil, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 1 {
		t.Fatalf("lua: expected 1 finding for q, got %d: %+v", len(luaFs), luaFs)
	}

	goF := goFs[0]
	luaF := luaFs[0]
	if goF.Severity != luaF.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goF.Severity, luaF.Severity)
	}
	if goF.CWE != luaF.CWE {
		t.Errorf("CWE drift: go=%q lua=%q", goF.CWE, luaF.CWE)
	}
	if goF.OWASP != luaF.OWASP {
		t.Errorf("OWASP drift: go=%q lua=%q", goF.OWASP, luaF.OWASP)
	}
	if !strings.Contains(goF.Title, `"q"`) || !strings.Contains(luaF.Title, `"q"`) {
		t.Errorf("title should name the vulnerable param\n go=%q\nlua=%q", goF.Title, luaF.Title)
	}
	if !strings.Contains(goF.Title, "location.search") || !strings.Contains(luaF.Title, "location.search") {
		t.Errorf("title should name the source\n go=%q\nlua=%q", goF.Title, luaF.Title)
	}
	if goF.DedupeKey != luaF.DedupeKey {
		t.Errorf("dedupe drift:\n go=%q\nlua=%q", goF.DedupeKey, luaF.DedupeKey)
	}
}

// TestLuaDOMXSSCleanPageParity asserts both implementations issue
// fragment probes (so the pool sees Visit calls) but produce zero
// findings when nothing fires.
func TestLuaDOMXSSCleanPageParity(t *testing.T) {
	p := page.FromURL("https://example.com/static")

	goPool := &fakeBrowserPool{}
	goCtx := checks.WithBrowser(context.Background(), goPool)
	goFs, err := checks.DOMXSS{}.Run(goCtx, nil, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %d", len(goFs))
	}
	if len(goPool.calls()) == 0 {
		t.Fatalf("go: expected fragment probes, got 0 visits")
	}

	luaPool := &fakeBrowserPool{}
	luaCtx := checks.WithBrowser(context.Background(), luaPool)
	luaC := findDOMXSS(t)
	luaFs, err := luaC.Run(luaCtx, nil, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %d", len(luaFs))
	}
	if len(luaPool.calls()) == 0 {
		t.Fatalf("lua: expected fragment probes, got 0 visits")
	}

	// Fragment probes are url + "#" + payload, one Visit per payload.
	// The Go check and the Lua check must agree on the probe count so
	// authoring drift (added/removed payloads) shows up here, not later
	// at scan time.
	if len(goPool.calls()) != len(luaPool.calls()) {
		t.Errorf("visit count drift: go=%d lua=%d", len(goPool.calls()), len(luaPool.calls()))
	}
}
