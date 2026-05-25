package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestCachePoisoningName(t *testing.T) {
	if got := (CachePoisoning{}).Name(); got != "cache-poisoning" {
		t.Fatalf("Name = %q, want cache-poisoning", got)
	}
}

func TestCachePoisoningLevel(t *testing.T) {
	if got := (CachePoisoning{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// vulnUnkeyedHostHandler simulates a back-end that echoes X-Forwarded-Host
// into a canonical link tag and advertises itself as cacheable but does
// NOT list the header in Vary - the textbook poisoning primitive.
func vulnUnkeyedHostHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Age", "0")
		w.Header().Set("X-Cache", "MISS")
		// Deliberately omit Vary so the canary host folds into the cache key.
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><head><link rel=\"canonical\" href=\"https://%s/\"></head><body>ok</body></html>", host)
	})
}

func TestCachePoisoningDetectsUnkeyedXForwardedHost(t *testing.T) {
	srv := httptest.NewServer(vulnUnkeyedHostHandler())
	defer srv.Close()

	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected at least one finding, got 0")
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "X-Forwarded-Host") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected X-Forwarded-Host finding, got: %+v", findings)
	}
	if hit.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", hit.Severity)
	}
	if hit.CWE != "CWE-444" {
		t.Errorf("CWE = %q, want CWE-444", hit.CWE)
	}
	if !strings.Contains(hit.Detail, "response body") {
		t.Errorf("Detail should locate the reflection: %q", hit.Detail)
	}
	if hit.Evidence == nil || hit.Evidence.Exchange == nil {
		t.Fatalf("Evidence/Exchange must be set: %+v", hit.Evidence)
	}
	if hit.DedupeKey == "" {
		t.Errorf("DedupeKey must be set")
	}
}

func TestCachePoisoningSuppressedByVary(t *testing.T) {
	// Same vulnerable echo but the response correctly lists the header
	// in Vary, so a cache partitions per-Host and the poisoning primitive
	// is neutralized. No finding should fire for X-Forwarded-Host.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Age", "0")
		w.Header().Set("Vary", "X-Forwarded-Host")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>host=%s</body></html>", host)
	}))
	defer srv.Close()

	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "X-Forwarded-Host") {
			t.Fatalf("X-Forwarded-Host should be suppressed by Vary entry: %+v", f)
		}
	}
}

func TestCachePoisoningSuppressedByVaryStar(t *testing.T) {
	// Vary: * tells every cache the response is fundamentally not
	// cacheable - the poisoning primitive can't land.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Age", "0")
		w.Header().Set("Vary", "*")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>host=%s</body></html>", host)
	}))
	defer srv.Close()

	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "Web cache poisoning") {
			t.Fatalf("Vary: * should suppress every header probe: %+v", f)
		}
	}
}

func TestCachePoisoningSkipsWithoutCacheHints(t *testing.T) {
	// Echoes the header (a host-header-injection bug) but the response
	// carries no cache markers and no public Cache-Control. The cache-
	// poisoning arm must defer to host-header-injection rather than
	// claim a stored-poisoning finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "private, no-store")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>host=%s</body></html>", host)
	}))
	defer srv.Close()

	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "Web cache poisoning") {
			t.Fatalf("should not flag poisoning without cache hints: %+v", f)
		}
	}
}

func TestCachePoisoningDetectsXOriginalURL(t *testing.T) {
	// Back-end honours X-Original-URL to route to a different
	// controller without rechecking authorization. The probe canary
	// path produces a meaningfully different response (404 -> divergence
	// flag, or the body returns the canary path verbatim).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if v := r.Header.Get("X-Original-URL"); v != "" {
			path = v
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Age", "0")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>routed=%s</body></html>", path)
	}))
	defer srv.Close()

	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "X-Original-URL") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected X-Original-URL finding, got: %+v", findings)
	}
	if hit.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", hit.Severity)
	}
	if !strings.Contains(hit.Detail, "X-Original-URL") {
		t.Errorf("Detail should mention X-Original-URL: %q", hit.Detail)
	}
}

func TestCachePoisoningRespectsScope(t *testing.T) {
	// Out-of-scope target: probes must not fire even when reachable.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc, err := scope.New(scope.Config{Hosts: []string{"only-this-host.invalid"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), sc, page.FromURL(srv.URL))
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

func TestCachePoisoningCacheDeceptionOnAuthPath(t *testing.T) {
	// Authenticated-looking path that the server treats as suffix-
	// agnostic: /account and /account/anything.css both return the
	// same HTML body. A CDN with extension rules will cache the second
	// URL and serve the victim's account page to the attacker.
	bodyHTML := "<html><head><title>Account</title></head><body>welcome user-123</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// No explicit private/no-store directive - the textbook unsafe
		// configuration where the cache decides based on extension.
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, bodyHTML)
	}))
	defer srv.Close()

	target := srv.URL + "/account"
	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if findings[i].Check == "cache-poisoning" && strings.Contains(findings[i].Title, "deception") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected cache-deception finding, got: %+v", findings)
	}
	if hit.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", hit.Severity)
	}
	if hit.CWE != "CWE-525" {
		t.Errorf("CWE = %q, want CWE-525", hit.CWE)
	}
	if !strings.Contains(hit.URL, ".css") {
		t.Errorf("URL should point at the .css deception variant: %q", hit.URL)
	}
}

func TestCachePoisoningCacheDeceptionDowngradesWithNoStore(t *testing.T) {
	// Same suffix-confusion routing bug, but the upstream sends
	// Cache-Control: no-store on the deception URL. A well-behaved
	// cache will not store the response; severity drops to Medium.
	bodyHTML := "<html><body>private account data</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, bodyHTML)
	}))
	defer srv.Close()

	target := srv.URL + "/profile"
	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if findings[i].Check == "cache-poisoning" && strings.Contains(findings[i].Title, "deception") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected cache-deception finding, got: %+v", findings)
	}
	if hit.Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium (no-store softens impact)", hit.Severity)
	}
}

func TestCachePoisoningCacheDeceptionNotOnNonAuthPath(t *testing.T) {
	// Same suffix-confused server, but the path is not authentication-
	// bearing. At LevelDefault the deception arm doesn't probe and the
	// finding is suppressed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>public landing page</body></html>")
	}))
	defer srv.Close()

	target := srv.URL + "/about"
	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "deception") {
			t.Fatalf("deception arm should skip non-auth paths at LevelDefault: %+v", f)
		}
	}
}

func TestCachePoisoningCacheDeceptionAggressiveProbesAll(t *testing.T) {
	// At LevelAggressive the deception arm runs on every path,
	// including ones that don't match the auth keyword list.
	bodyHTML := "<html><body>some page content</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, bodyHTML)
	}))
	defer srv.Close()

	target := srv.URL + "/widgets/list"
	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := CachePoisoning{}.Run(ctx, newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "deception") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected deception finding at aggressive level: %+v", findings)
	}
}

func TestCachePoisoningCacheDeceptionRejectsDifferingBody(t *testing.T) {
	// Server returns a generic 404-style "static asset not found" body
	// for the .css path but a real account page for /account. Bodies
	// differ - the deception arm must NOT flag this.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if strings.HasSuffix(r.URL.Path, ".css") {
			fmt.Fprint(w, "<html><body>asset not found</body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>welcome user-123 to your account</body></html>")
	}))
	defer srv.Close()

	target := srv.URL + "/account"
	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "deception") {
			t.Fatalf("differing body should not produce a deception finding: %+v", f)
		}
	}
}

func TestCachePoisoningCacheDeceptionRejectsCSSContentType(t *testing.T) {
	// A correctly-routed handler would return text/css for /account.css
	// (or a 404). The deception arm requires the response Content-Type
	// to be HTML - that's the signal the server didn't dispatch to a
	// real static handler.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "body{color:red}")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>account</body></html>")
	}))
	defer srv.Close()

	target := srv.URL + "/account"
	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "deception") {
			t.Fatalf("CSS content-type should suppress deception finding: %+v", f)
		}
	}
}

func TestCachePoisoningIgnoresNonHTTPTargets(t *testing.T) {
	findings, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL("not-a-url"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("malformed URL should produce 0 findings, got %+v", findings)
	}
}

func TestCachePoisoningDedupeKeyStableAcrossProbes(t *testing.T) {
	srv := httptest.NewServer(vulnUnkeyedHostHandler())
	defer srv.Close()

	run := func() string {
		fs, err := CachePoisoning{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		for _, f := range fs {
			if strings.Contains(f.Title, "X-Forwarded-Host") {
				return f.DedupeKey
			}
		}
		t.Fatalf("expected X-Forwarded-Host finding")
		return ""
	}
	if a, b := run(), run(); a != b {
		t.Errorf("dedupe key not stable: %q vs %q", a, b)
	}
}

func TestParseVary(t *testing.T) {
	got := parseVary("X-Forwarded-Host, Accept-Encoding,  cookie ,")
	for _, want := range []string{"x-forwarded-host", "accept-encoding", "cookie"} {
		if _, ok := got[want]; !ok {
			t.Errorf("parseVary missing %q: %v", want, got)
		}
	}
	if _, ok := got[""]; ok {
		t.Errorf("parseVary should not retain empty entries: %v", got)
	}
}

func TestCacheHintsPresent(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		want bool
	}{
		{"empty", http.Header{}, false},
		{"private", http.Header{"Cache-Control": []string{"private, no-store"}}, false},
		{"public", http.Header{"Cache-Control": []string{"public, max-age=300"}}, true},
		{"s-maxage", http.Header{"Cache-Control": []string{"s-maxage=60"}}, true},
		{"max-age no private", http.Header{"Cache-Control": []string{"max-age=600"}}, true},
		{"age header", http.Header{"Age": []string{"42"}}, true},
		{"cf cache status", http.Header{"Cf-Cache-Status": []string{"HIT"}}, true},
		{"varnish", http.Header{"X-Varnish": []string{"123 456"}}, true},
		{"via", http.Header{"Via": []string{"1.1 squid"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cacheHintsPresent(tc.h); got != tc.want {
				t.Errorf("cacheHintsPresent = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsAuthLikelyPath(t *testing.T) {
	hits := []string{
		"/account",
		"/api/v1/profile",
		"/users/me",
		"/admin/dashboard",
		"/billing/invoices",
		"/settings/security",
		"/my-orders",
		"/secure/inbox",
	}
	for _, p := range hits {
		if !isAuthLikelyPath(p) {
			t.Errorf("isAuthLikelyPath(%q) = false, want true", p)
		}
	}
	misses := []string{
		"/",
		"/about",
		"/blog/post-1",
		"/contact",
	}
	for _, p := range misses {
		if isAuthLikelyPath(p) {
			t.Errorf("isAuthLikelyPath(%q) = true, want false", p)
		}
	}
}

func TestDeceptionURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://x.test/account", "https://x.test/account" + cacheDeceptionSuffix},
		{"https://x.test/account/", "https://x.test/account" + cacheDeceptionSuffix},
		{"https://x.test/", "https://x.test" + cacheDeceptionSuffix},
		{"https://x.test", "https://x.test" + cacheDeceptionSuffix},
	}
	for _, tc := range cases {
		u, err := url.Parse(tc.in)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.in, err)
		}
		got, err := deceptionURL(u)
		if err != nil {
			t.Fatalf("deceptionURL(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("deceptionURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Already-suffixed URL should return empty so we don't re-probe.
	u, _ := url.Parse("https://x.test/account" + cacheDeceptionSuffix)
	got, _ := deceptionURL(u)
	if got != "" {
		t.Errorf("already-suffixed URL should produce empty target, got %q", got)
	}
}

func TestBodiesMatch(t *testing.T) {
	long := strings.Repeat("a", 1024)
	sharedShell := strings.Repeat("<header/>", 100)  // 900 bytes of identical template
	sharedFooter := strings.Repeat("<footer/>", 100) // 900 bytes of identical template
	pageA := sharedShell + strings.Repeat("alice-data ", 50) + sharedFooter
	pageB := sharedShell + strings.Repeat("bob-data!! ", 50) + sharedFooter
	cases := []struct {
		name   string
		a, b   string
		expect bool
	}{
		{"empty-a", "", "x", false},
		{"empty-b", "x", "", false},
		{"identical", long, long, true},
		{"length-drift-within-tolerance", long, long + "abcd", true},
		{"length-drift-out-of-tolerance", long, long + strings.Repeat("x", 256), false},
		{"prefix-mismatch", "alpha" + long, "beta" + long, false},
		// Shared shell, different dynamic middle, identical footer: the
		// prefix-only check would have matched these; the middle anchor
		// must catch the divergence in the dynamic region.
		{"shared-shell-different-middle", pageA, pageB, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bodiesMatch([]byte(tc.a), []byte(tc.b)); got != tc.expect {
				t.Errorf("bodiesMatch = %v, want %v", got, tc.expect)
			}
		})
	}
}

func TestCacheControlForbidsStorage(t *testing.T) {
	cases := map[string]bool{
		"":                    false,
		"public, max-age=300": false,
		"no-store":            true,
		"private":             true,
		"PRIVATE, max-age=0":  true,
	}
	for in, want := range cases {
		if got := cacheControlForbidsStorage(in); got != want {
			t.Errorf("cacheControlForbidsStorage(%q) = %v, want %v", in, got, want)
		}
	}
}
