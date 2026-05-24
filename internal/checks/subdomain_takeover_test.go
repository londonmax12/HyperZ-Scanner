package checks

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestSubdomainTakeoverName(t *testing.T) {
	if got := (&SubdomainTakeover{}).Name(); got != "subdomain-takeover" {
		t.Fatalf("Name = %q, want subdomain-takeover", got)
	}
}

func TestSubdomainTakeoverLevel(t *testing.T) {
	if got := (&SubdomainTakeover{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

// withFakeCNAME / withFakeLookupHost swap the package-level resolver
// indirection so a test can declare exactly what DNS would return for
// each hostname. The closures restore the previous values on cleanup
// to keep tests order-independent.
func withFakeCNAME(t *testing.T, m map[string]string) {
	t.Helper()
	prev := subdomainTakeoverLookupCNAME
	subdomainTakeoverLookupCNAME = func(_ context.Context, host string) (string, error) {
		if v, ok := m[strings.ToLower(host)]; ok {
			return v, nil
		}
		return host + ".", nil
	}
	t.Cleanup(func() { subdomainTakeoverLookupCNAME = prev })
}

func withFakeLookupHost(t *testing.T, nxdomains map[string]bool) {
	t.Helper()
	prev := subdomainTakeoverLookupHost
	subdomainTakeoverLookupHost = func(_ context.Context, host string) ([]string, error) {
		if nxdomains[strings.ToLower(host)] {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []string{"127.0.0.1"}, nil
	}
	t.Cleanup(func() { subdomainTakeoverLookupHost = prev })
}

// fakeEdge stands in for a SaaS provider's edge: status + body are
// returned verbatim regardless of path so the check sees the canonical
// "claim this" page the real edge would serve. The test directs the
// check at the fakeEdge by giving the page URL the same host:port and
// then injecting a CNAME that points the hostname at the provider's
// suffix.
func fakeEdge(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSubdomainTakeoverGitHubPagesConfirmed(t *testing.T) {
	srv := fakeEdge(t, http.StatusNotFound, "There isn't a GitHub Pages site here.")
	u, _ := url.Parse(srv.URL)

	withFakeCNAME(t, map[string]string{u.Hostname(): "abandoned-user.github.io."})
	withFakeLookupHost(t, nil)

	c := &SubdomainTakeover{}
	findings, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/some/page"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if !strings.Contains(f.Title, "GitHub Pages") {
		t.Errorf("title = %q, want it to mention GitHub Pages", f.Title)
	}
	if f.DedupeKey == "" {
		t.Errorf("DedupeKey empty")
	}
}

func TestSubdomainTakeoverHerokuConfirmed(t *testing.T) {
	srv := fakeEdge(t, http.StatusNotFound, "There's nothing here, yet.")
	u, _ := url.Parse(srv.URL)

	withFakeCNAME(t, map[string]string{u.Hostname(): "dead-app.herokuapp.com."})
	withFakeLookupHost(t, nil)

	c := &SubdomainTakeover{}
	findings, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "Heroku") {
		t.Errorf("title = %q, want it to mention Heroku", findings[0].Title)
	}
}

func TestSubdomainTakeoverNoCNAMENoFinding(t *testing.T) {
	srv := fakeEdge(t, http.StatusOK, "<html>working site</html>")
	u, _ := url.Parse(srv.URL)

	// LookupCNAME with no record returns the input host with a trailing
	// dot - the check treats this as "no CNAME" and bails before any
	// fingerprint work.
	withFakeCNAME(t, map[string]string{u.Hostname(): u.Hostname() + "."})
	withFakeLookupHost(t, nil)

	c := &SubdomainTakeover{}
	findings, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("want 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestSubdomainTakeoverCNAMEToUnknownProvider(t *testing.T) {
	srv := fakeEdge(t, http.StatusOK, "<html>working site</html>")
	u, _ := url.Parse(srv.URL)

	// CNAME points at an internal name that does not match any known
	// SaaS provider - the check should not fire.
	withFakeCNAME(t, map[string]string{u.Hostname(): "internal.example.com."})
	withFakeLookupHost(t, nil)

	c := &SubdomainTakeover{}
	findings, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("want 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestSubdomainTakeoverCNAMEMatchButFingerprintMissing(t *testing.T) {
	// Hostname's CNAME matches a provider suffix but the edge returns a
	// healthy page - this is a normal claimed deployment. No finding.
	srv := fakeEdge(t, http.StatusOK, "<html>Welcome to my GitHub Pages site</html>")
	u, _ := url.Parse(srv.URL)

	withFakeCNAME(t, map[string]string{u.Hostname(): "alive-user.github.io."})
	withFakeLookupHost(t, nil)

	c := &SubdomainTakeover{}
	findings, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("want 0 findings on claimed deployment, got %d: %+v", len(findings), findings)
	}
}

func TestSubdomainTakeoverNXDOMAINOnCNAMETarget(t *testing.T) {
	// CNAME resolves to a provider name that itself NXDOMAINs - the
	// upstream resource has been released. The check fires without
	// needing the edge probe to also confirm.
	srv := fakeEdge(t, http.StatusOK, "")
	u, _ := url.Parse(srv.URL)

	withFakeCNAME(t, map[string]string{u.Hostname(): "gone-bucket.s3.amazonaws.com."})
	withFakeLookupHost(t, map[string]bool{"gone-bucket.s3.amazonaws.com": true})

	c := &SubdomainTakeover{}
	findings, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(strings.Join(findings[0].Details, "\n"), "NXDOMAIN") {
		t.Errorf("expected NXDOMAIN note in details, got: %+v", findings[0].Details)
	}
}

func TestSubdomainTakeoverSkipsIPLiteral(t *testing.T) {
	// An IP literal has no real CNAME; the fake resolver returns the
	// input back (the same shape Go's resolver uses for "no record")
	// and the check must bail without false-positiving.
	withFakeCNAME(t, nil)
	c := &SubdomainTakeover{}
	findings, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL("http://192.0.2.1/some/path"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("want 0 findings on IP literal, got %d: %+v", len(findings), findings)
	}
}

func TestSubdomainTakeoverSkipsProviderCanonicalHost(t *testing.T) {
	// Scan target IS user.github.io directly - this is canonical
	// hosting, not a CNAME chain, so we must not fire even if a stale
	// resolver entry would otherwise match.
	c := &SubdomainTakeover{}
	findings, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL("https://someuser.github.io/repo/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("want 0 findings on provider canonical host, got %d: %+v", len(findings), findings)
	}
}

func TestSubdomainTakeoverCachesPerHost(t *testing.T) {
	// Two crawled pages on the same host: the second call must reuse
	// the cached result without re-resolving or re-probing. We assert
	// by counting probe hits on the edge server.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	t.Cleanup(srv.Close)

	u, _ := url.Parse(srv.URL)
	withFakeCNAME(t, map[string]string{u.Hostname(): "abandoned.github.io."})
	withFakeLookupHost(t, nil)

	c := &SubdomainTakeover{}
	p1 := page.FromURL(srv.URL + "/a")
	p2 := page.FromURL(srv.URL + "/b")

	if _, err := c.Run(context.Background(), newTestClient(t), nil, p1); err != nil {
		t.Fatalf("Run p1: %v", err)
	}
	if _, err := c.Run(context.Background(), newTestClient(t), nil, p2); err != nil {
		t.Fatalf("Run p2: %v", err)
	}
	if hits != 1 {
		t.Fatalf("edge hits = %d, want 1 (second call should hit cache)", hits)
	}
}

func TestSubdomainTakeoverRespectsScope(t *testing.T) {
	srv := fakeEdge(t, http.StatusNotFound, "There isn't a GitHub Pages site here.")
	u, _ := url.Parse(srv.URL)

	withFakeCNAME(t, map[string]string{u.Hostname(): "abandoned.github.io."})
	withFakeLookupHost(t, nil)

	// Scope allows only some-other-host: the probe URL is the page
	// host's root, which falls outside this scope, so we must not fire.
	sc, err := scope.New(scope.Config{Hosts: []string{"other.example.com"}, MaxDepth: -1})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	c := &SubdomainTakeover{}
	findings, err := c.Run(context.Background(), newTestClient(t), sc, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("want 0 findings under out-of-scope, got %d: %+v", len(findings), findings)
	}
}

func TestSubdomainTakeoverMatchProvider(t *testing.T) {
	tests := []struct {
		cname string
		want  string // provider name or "" for no match
	}{
		{"abandoned.github.io", "GitHub Pages"},
		{"deep.user.github.io", "GitHub Pages"},
		{"imitatorgithub.io", ""}, // suffix match must not bleed past the dot
		{"bucket.s3.amazonaws.com", "AWS S3"},
		{"app.herokuapp.com", "Heroku"},
		{"site.azurewebsites.net", "Microsoft Azure"},
		{"edge.fastly.net", "Fastly"},
		{"store.myshopify.com", "Shopify"},
		{"sitename.pantheonsite.io", "Pantheon"},
		{"domains.tumblr.com", "Tumblr"},
		{"notdomains.tumblr.com", ""}, // exact-host entry must not bleed via plain suffix
		{"blog.domains.tumblr.com", ""},
		{"page.unbouncepages.com", "Unbounce"},
		{"project.surge.sh", "Surge.sh"},
		{"team.bitbucket.io", "Bitbucket"},
		{"docs.helpjuice.com", "Helpjuice"},
		{"docs.readme.io", "Readme.io"},
		{"help.helpscoutdocs.com", "HelpScout"},
		{"example.com", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.cname, func(t *testing.T) {
			got := matchProvider(tt.cname)
			if tt.want == "" {
				if got != nil {
					t.Fatalf("matchProvider(%q) = %q, want no match", tt.cname, got.name)
				}
				return
			}
			if got == nil {
				t.Fatalf("matchProvider(%q) = nil, want %q", tt.cname, tt.want)
			}
			if got.name != tt.want {
				t.Errorf("matchProvider(%q).name = %q, want %q", tt.cname, got.name, tt.want)
			}
		})
	}
}

func TestSubdomainTakeoverMatchesFingerprint(t *testing.T) {
	provider := &takeoverProvider{
		name:         "Test",
		fingerprints: []string{"hello world", "hola mundo"},
		statuses:     []int{http.StatusNotFound},
	}
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"matches first fingerprint at correct status", 404, "<html>hello world</html>", true},
		{"matches second fingerprint at correct status", 404, "hola mundo here", true},
		{"wrong status code", 200, "hello world", false},
		{"correct status, no fingerprint", 404, "everything is fine", false},
		{"empty body", 404, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesFingerprint(tt.status, []byte(tt.body), provider); got != tt.want {
				t.Errorf("matchesFingerprint(%d, %q) = %v, want %v", tt.status, tt.body, got, tt.want)
			}
		})
	}
}

func TestSubdomainTakeoverWrongStatusWithFingerprintBody(t *testing.T) {
	// Fastly's edge can serve the "unknown domain" body verbatim on a
	// 502 in some misrouted configs. The provider's status gate is
	// [500, 404], so a 502 must NOT fire even though the body matches.
	srv := fakeEdge(t, http.StatusBadGateway, "Fastly error: unknown domain")
	u, _ := url.Parse(srv.URL)

	withFakeCNAME(t, map[string]string{u.Hostname(): "abandoned.fastly.net."})
	withFakeLookupHost(t, nil)

	c := &SubdomainTakeover{}
	findings, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("want 0 findings (502 not in Fastly's status list), got %d: %+v", len(findings), findings)
	}
}

func TestSubdomainTakeoverCachedFindingRewritesPageURL(t *testing.T) {
	// First call confirms a takeover and caches the finding. A second
	// crawled page on the same host must re-emit that finding rewritten
	// to the new page URL so the report ties each finding to the URL
	// the crawler actually visited.
	srv := fakeEdge(t, http.StatusNotFound, "There isn't a GitHub Pages site here.")
	u, _ := url.Parse(srv.URL)

	withFakeCNAME(t, map[string]string{u.Hostname(): "abandoned.github.io."})
	withFakeLookupHost(t, nil)

	c := &SubdomainTakeover{}
	first := srv.URL + "/first"
	second := srv.URL + "/second/deeper"

	f1, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(first))
	if err != nil {
		t.Fatalf("Run first: %v", err)
	}
	if len(f1) != 1 {
		t.Fatalf("first run: want 1 finding, got %d", len(f1))
	}
	if f1[0].URL != first || f1[0].Target != first {
		t.Errorf("first run URL/Target = %q/%q, want %q", f1[0].URL, f1[0].Target, first)
	}

	f2, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(second))
	if err != nil {
		t.Fatalf("Run second: %v", err)
	}
	if len(f2) != 1 {
		t.Fatalf("second run: want 1 cached finding, got %d", len(f2))
	}
	if f2[0].URL != second {
		t.Errorf("cached URL = %q, want rewritten to %q", f2[0].URL, second)
	}
	if f2[0].Target != second {
		t.Errorf("cached Target = %q, want rewritten to %q", f2[0].Target, second)
	}
}

func TestSubdomainTakeoverProbeConnectionErrorSwallowed(t *testing.T) {
	// CNAME matches a known provider and the CNAME target resolves (no
	// NXDOMAIN), but the edge probe fails to connect. Bare connection
	// errors are too noisy to fire on across flaky networks, so the
	// check must return no findings and no scan error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	pageURL := srv.URL + "/x"
	u, _ := url.Parse(srv.URL)
	srv.Close() // probe target is now unreachable

	withFakeCNAME(t, map[string]string{u.Hostname(): "abandoned.github.io."})
	withFakeLookupHost(t, nil)

	c := &SubdomainTakeover{}
	findings, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(pageURL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("want 0 findings on probe connection error, got %d: %+v", len(findings), findings)
	}
}

func TestSubdomainTakeoverMatchesFingerprintAnyStatus(t *testing.T) {
	// When statuses is empty, any status passes the gate as long as
	// the body fingerprint matches.
	provider := &takeoverProvider{
		name:         "Test",
		fingerprints: []string{"shop unavailable"},
	}
	if !matchesFingerprint(200, []byte("...shop unavailable..."), provider) {
		t.Errorf("expected match with empty statuses list and 200")
	}
	if !matchesFingerprint(500, []byte("shop unavailable"), provider) {
		t.Errorf("expected match with empty statuses list and 500")
	}
}
