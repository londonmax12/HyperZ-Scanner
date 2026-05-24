package checks

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/browser"
	"github.com/londonmax12/hyperz/internal/page"
)

// fakePool is the test double for browser.Pool. It records every Visit
// call and fires the canary binding whenever the probe URL matches one
// of the substrings in fireOn. This lets a test simulate "the page
// executed our payload" without launching a real headless browser.
type fakePool struct {
	mu      sync.Mutex
	visits  []string
	fireOn  []string
	visitFn func(url, token string) bool
}

func (p *fakePool) Visit(_ context.Context, url, token string, _ time.Duration) (bool, error) {
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

func (p *fakePool) Close() {}

func (p *fakePool) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.visits))
	copy(out, p.visits)
	return out
}

func TestDOMXSSName(t *testing.T) {
	if got := (DOMXSS{}).Name(); got != "dom-xss" {
		t.Fatalf("Name = %q, want dom-xss", got)
	}
}

func TestDOMXSSLevel(t *testing.T) {
	if got := (DOMXSS{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// Without a Pool in ctx the check must produce no findings AND no error -
// a scan without --js should not light up dom-xss on every page.
func TestDOMXSSSkipsWhenNoBrowserAttached(t *testing.T) {
	findings, err := DOMXSS{}.Run(context.Background(), nil, nil,
		page.FromURL("https://example.com/?q=1"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without --js, got %d", len(findings))
	}
}

// When the fake pool reports "fired" for a fragment probe, the check
// must emit a finding scoped to the location.hash source.
func TestDOMXSSDetectsFragmentSink(t *testing.T) {
	pool := &fakePool{fireOn: []string{"#"}}
	ctx := WithBrowser(context.Background(), pool)

	findings, err := DOMXSS{}.Run(ctx, nil, nil,
		page.FromURL("https://example.com/profile"))
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
	if f.CWE != "CWE-79" {
		t.Errorf("CWE = %q, want CWE-79", f.CWE)
	}
	if !strings.Contains(f.Title, "location.hash") {
		t.Errorf("Title should name the source: %q", f.Title)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
}

// Query-param sinks fire when the fake pool sees the param in the URL.
// The check should report the parameter name in the title and dedupe
// per-param so two distinct params produce two findings.
func TestDOMXSSDetectsQueryParamSink(t *testing.T) {
	// Fire only when the payload landed in the `q` param specifically -
	// not on the fragment probe (no payload-in-q) and not on the `lang`
	// probe (payload-in-lang, q stays "hi"). Decoding via url.Parse
	// matches the real-pool contract: the browser sees decoded values,
	// not the percent-encoded wire form.
	pool := &fakePool{
		visitFn: func(rawurl, _ string) bool {
			u, err := url.Parse(rawurl)
			if err != nil {
				return false
			}
			return strings.Contains(u.Query().Get("q"), browser.BindingName)
		},
	}
	ctx := WithBrowser(context.Background(), pool)

	findings, err := DOMXSS{}.Run(ctx, nil, nil,
		page.FromURL("https://example.com/search?q=hi&lang=en"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for q, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if !strings.Contains(f.Title, `"q"`) {
		t.Errorf("Title should name the vulnerable param: %q", f.Title)
	}
	if !strings.Contains(f.Title, "location.search") {
		t.Errorf("Title should name the source: %q", f.Title)
	}
}

// A page with no query params and no fragment fire still issues fragment
// probes (those don't depend on existing params). When nothing fires the
// check returns empty without erroring.
func TestDOMXSSCleanPageProducesNoFindings(t *testing.T) {
	pool := &fakePool{} // fireOn empty - never fires
	ctx := WithBrowser(context.Background(), pool)

	findings, err := DOMXSS{}.Run(ctx, nil, nil,
		page.FromURL("https://example.com/static"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	// Sanity: the check actually exercised the pool (one Visit per
	// fragment payload).
	if len(pool.calls()) == 0 {
		t.Fatalf("expected fragment probes to call the pool, got 0 calls")
	}
}

// Cancelling ctx mid-run should bail out of the probe loop without
// producing findings or panicking.
func TestDOMXSSHonoursContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done before Run starts

	pool := &fakePool{fireOn: []string{"#"}}
	ctx = WithBrowser(ctx, pool)

	findings, err := DOMXSS{}.Run(ctx, nil, nil,
		page.FromURL("https://example.com/profile"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings after cancel, got %d", len(findings))
	}
}
