package checks_lua

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func findSubdomainTakeover(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "subdomain-takeover" {
			return c
		}
	}
	t.Fatal("subdomain-takeover Lua check not found")
	return nil
}

// TestLuaSubdomainTakeoverParity injects fake DNS resolvers and a fake
// SaaS edge so both implementations evaluate the same target. The Go
// check is the parity oracle: it runs first to populate the per-host
// cache, then the Lua port runs against the same evaluator (the
// bridge shares the package-level evaluator instance) and must emit
// an identical finding shape.
func TestLuaSubdomainTakeoverParity(t *testing.T) {
	// Fake GitHub Pages edge: status 404 + the canonical "no site
	// here" body so the CNAME-confirmed path fires.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	// Swap the package-level DNS resolvers so the test does not depend
	// on real network state. Re-installed for the duration of the run
	// and restored on cleanup.
	prevCNAME := checks.SubdomainTakeoverLookupCNAMEForTest()
	checks.SetSubdomainTakeoverLookupCNAMEForTest(func(_ context.Context, host string) (string, error) {
		if strings.EqualFold(host, u.Hostname()) {
			return "abandoned-user.github.io.", nil
		}
		return host + ".", nil
	})
	defer checks.SetSubdomainTakeoverLookupCNAMEForTest(prevCNAME)

	prevHost := checks.SubdomainTakeoverLookupHostForTest()
	checks.SetSubdomainTakeoverLookupHostForTest(func(_ context.Context, host string) ([]string, error) {
		_ = (&net.DNSError{})
		return []string{"127.0.0.1"}, nil
	})
	defer checks.SetSubdomainTakeoverLookupHostForTest(prevHost)

	luaC := findSubdomainTakeover(t)
	client := newTestClient(t)
	var sc *scope.Scope

	// Each All() call constructs fresh LuaChecks (their aux map - which
	// owns the Lua-side evaluator's per-host DNS cache - starts empty),
	// so the Lua port sees a cold-cache first pass without a manual
	// reset. The Go check below gets its own fresh evaluator the same
	// way (a brand-new &checks.SubdomainTakeover{} per assertion).
	goFs, err := (&checks.SubdomainTakeover{}).Run(context.Background(), client, sc, page.FromURL(srv.URL+"/some/page"))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaFs, err := luaC.Run(context.Background(), client, sc, page.FromURL(srv.URL+"/some/page"))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != len(luaFs) {
		t.Fatalf("count: go=%d lua=%d", len(goFs), len(luaFs))
	}
	for i := range goFs {
		if goFs[i].Severity != luaFs[i].Severity {
			t.Errorf("severity drift: go=%q lua=%q", goFs[i].Severity, luaFs[i].Severity)
		}
		if goFs[i].Title != luaFs[i].Title {
			t.Errorf("title drift: go=%q lua=%q", goFs[i].Title, luaFs[i].Title)
		}
		if goFs[i].DedupeKey != luaFs[i].DedupeKey {
			t.Errorf("dedupe drift: go=%q lua=%q", goFs[i].DedupeKey, luaFs[i].DedupeKey)
		}
		if goFs[i].CWE != luaFs[i].CWE {
			t.Errorf("CWE drift: go=%q lua=%q", goFs[i].CWE, luaFs[i].CWE)
		}
	}
}
