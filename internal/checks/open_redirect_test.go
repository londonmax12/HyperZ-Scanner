package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestOpenRedirectName(t *testing.T) {
	if got := (OpenRedirect{}).Name(); got != "open-redirect" {
		t.Fatalf("Name = %q, want open-redirect", got)
	}
}

func TestOpenRedirectLevel(t *testing.T) {
	// Default level: probe is a crafted request, must not run at passive.
	if got := (OpenRedirect{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// vulnRedirectHandler echoes the `next` query param into Location verbatim -
// the canonical open redirect bug.
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

func TestOpenRedirectDetectsVulnerableNextParam(t *testing.T) {
	srv := httptest.NewServer(vulnRedirectHandler(t))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
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

func TestOpenRedirectEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(vulnRedirectHandler(t))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
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
	if !strings.Contains(ev.Exchange.URL, "evil.example") {
		t.Errorf("Exchange.URL should include the probe param: %q", ev.Exchange.URL)
	}
}

func TestOpenRedirectMatchesProtocolRelative(t *testing.T) {
	// Some apps strip the scheme and reflect "//host/...". Browsers treat
	// this as a same-scheme cross-host redirect; the probe must catch it.
	// Path is redirect-ish so the canonical `next` probe fires at default level.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		// Strip "https:" prefix to produce a protocol-relative Location.
		if strings.HasPrefix(next, "https:") {
			next = strings.TrimPrefix(next, "https:")
		}
		w.Header().Set("Location", next)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for protocol-relative reflection, got %d", len(findings))
	}
}

func TestOpenRedirectNoFindingOnSafeRedirect(t *testing.T) {
	// Server validates: any non-allowlisted target collapses to "/".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on same-origin redirect, got %d: %+v", len(findings), findings)
	}
}

func TestOpenRedirectNoFindingWhenNo3xx(t *testing.T) {
	// Path is redirect-ish so the canonical sweep actually fires and exercises
	// the 200-response rejection branch - without that, candidates would be
	// empty for / and the test would trivially pass by skipping all probes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on 200 OK, got %d", len(findings))
	}
}

func TestOpenRedirectNoFindingOnDifferentExternalHost(t *testing.T) {
	// Server redirects everywhere to a fixed external host (not our canary).
	// That's still potentially questionable, but it's not what we probed -
	// the canary didn't influence the destination, so no finding. Path is
	// redirect-ish so the canonical sweep fires and the matcher gets exercised.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://partner.example.org/welcome")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when redirect ignores our payload, got %d", len(findings))
	}
}

func TestOpenRedirectRespectsScope(t *testing.T) {
	// Out-of-scope target: the check must NOT send a probe even though the
	// scanner handed it to us. Counter on the server stays zero.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Scope that allows a host the target doesn't match.
	sc, err := scope.New(scope.Config{Hosts: []string{"only-this-host.invalid"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), sc, page.FromURL(srv.URL+"/"))
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

func TestOpenRedirectPreservesOtherQueryParamsAndOverridesProbedParam(t *testing.T) {
	// Capture every probe's raw query so we can verify the per-param
	// overlay shape. The check fans out across many candidate params; each
	// request must (a) preserve the unrelated params and (b) overlay the
	// canary onto exactly one param's value.
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.RawQuery)
		mu.Unlock()
		w.WriteHeader(http.StatusOK) // not vulnerable; only the probe shape matters
	}))
	defer srv.Close()

	// /r is intentionally NOT a redirect-ish path: the test should pass on
	// the strength of URL-present params (a, b, next) alone, proving they're
	// probed regardless of the path heuristic.
	_, err := OpenRedirect{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/r?a=1&b=2&next=original"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(seen) == 0 {
		t.Fatalf("server never saw any probes")
	}

	var sawNextOverlay, sawAOverlay bool
	for _, raw := range seen {
		q, err := url.ParseQuery(raw)
		if err != nil {
			t.Errorf("ParseQuery(%q): %v", raw, err)
			continue
		}
		// Unrelated params must always survive. The probe targeting `a`
		// or `b` will overlay that one specifically, so check the other.
		if q.Get("a") != openRedirectCanary && q.Get("a") != "1" {
			t.Errorf("param a corrupted in %q: %v", raw, q)
		}
		if q.Get("b") != openRedirectCanary && q.Get("b") != "2" {
			t.Errorf("param b corrupted in %q: %v", raw, q)
		}
		if q.Get("next") == openRedirectCanary && q.Get("a") == "1" && q.Get("b") == "2" {
			sawNextOverlay = true
		}
		if q.Get("a") == openRedirectCanary && q.Get("b") == "2" && q.Get("next") == "original" {
			sawAOverlay = true
		}
	}
	if !sawNextOverlay {
		t.Errorf("no probe overlaid canary onto `next` while preserving a=1,b=2; seen: %v", seen)
	}
	if !sawAOverlay {
		t.Errorf("no probe overlaid canary onto the non-standard `a` param; seen: %v", seen)
	}
}

func TestOpenRedirectProbesCanonicalParamNames(t *testing.T) {
	// Server reflects only ?redirect= (not ?next=). The check should catch it
	// because `redirect` is in the canonical list AND /login is a redirect-ish
	// path that earns the full canonical sweep at LevelDefault.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("redirect")
		if v == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", v)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for canonical `redirect` param, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "redirect") {
		t.Errorf("Title should name the probed param: %q", findings[0].Title)
	}
}

func TestOpenRedirectProbesExistingNonStandardParam(t *testing.T) {
	// `weirdname` isn't in the canonical list. The check only probes it
	// because it appears on the target URL itself.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("weirdname")
		if v == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", v)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/r?weirdname=foo"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from existing-param probe, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "weirdname") {
		t.Errorf("Title should name the non-standard param: %q", findings[0].Title)
	}
}

func TestOpenRedirectMultipleVulnerableParamsProduceDistinctFindings(t *testing.T) {
	// Server reflects whichever of {next,redirect,goto} arrives first.
	// All three are canonical, so the check should fire three independent
	// findings with distinct DedupeKeys.
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

	// /login is redirect-ish, so the canonical sweep fires and all three names
	// get probed at LevelDefault.
	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
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

func TestOpenRedirectDedupeKeyStableAndPerPath(t *testing.T) {
	srv := httptest.NewServer(vulnRedirectHandler(t))
	defer srv.Close()

	run := func(path string) string {
		fs, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+path))
		if err != nil {
			t.Fatalf("Run %q: %v", path, err)
		}
		if len(fs) != 1 {
			t.Fatalf("Run %q: got %d findings, want 1", path, len(fs))
		}
		return fs[0].DedupeKey
	}
	loginA := run("/login")
	loginB := run("/login") // same path, must dedupe to same key
	// /logout is also redirect-ish (different keyword), so the canonical
	// sweep fires there too - exercising "different path, different key".
	logout := run("/logout")
	if loginA == "" {
		t.Fatal("DedupeKey empty")
	}
	if loginA != loginB {
		t.Errorf("same-path keys drifted: %q vs %q", loginA, loginB)
	}
	if loginA == logout {
		t.Errorf("different-path keys collapsed: %q == %q", loginA, logout)
	}
}

func TestOpenRedirectDoesNotFollowRedirect(t *testing.T) {
	// The probe must read the 3xx verbatim and NOT chase Location. Each
	// candidate-param probe will hit the server once; if any follow
	// occurred, the follow-up request would carry our marker query.
	var followHit atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("hyperz-follow-marker") == "1" {
			followHit.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		// Self-redirect with a marker; a follower would loop into the
		// marker-carrying request and we'd count it.
		w.Header().Set("Location", r.URL.Path+"?hyperz-follow-marker=1")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	_, _ = OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))

	if got := followHit.Load(); got != 0 {
		t.Errorf("server saw %d follow-up requests, want 0 (no follow)", got)
	}
}

func TestOpenRedirectIgnoresUnparseableTarget(t *testing.T) {
	// Garbage target: not an error worth surfacing to scan summary; just
	// silently no-op. The crawler/seed loader is responsible for input
	// validation.
	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL("::not-a-url::"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on garbage URL, got %d", len(findings))
	}
}

func TestOpenRedirectReturnsErrorOnNetworkFailure(t *testing.T) {
	c := httpclient.New(httpclient.Config{
		Timeout:   1 * time.Second,
		UserAgent: "test",
	})
	// /login is redirect-ish so the canonical sweep fires; with the host
	// unreachable every probe errors and the wholesale-failure path returns
	// the first error.
	_, err := OpenRedirect{}.Run(context.Background(), c, nil, page.FromURL("http://hyperz-test-no-such-host.invalid/login"))
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
}

func TestOpenRedirectReportsEveryProbeFailureAsBreadcrumb(t *testing.T) {
	// Unreachable host: every candidate-param probe will fail. Even though
	// the function-level return error only carries the first failure, the
	// reporter attached to the context must see one event per probe so the
	// scan summary doesn't lose 13/14 errors when a host is flaky.
	c := httpclient.New(httpclient.Config{
		Timeout:   500 * time.Millisecond,
		UserAgent: "test",
	})

	var (
		mu     sync.Mutex
		errors []error
	)
	ctx := WithReporter(context.Background(), func(err error) {
		mu.Lock()
		defer mu.Unlock()
		errors = append(errors, err)
	})

	// /login earns the full canonical sweep; with the host unreachable every
	// probe fails, so the reporter sees one breadcrumb per canonical param.
	_, runErr := OpenRedirect{}.Run(ctx, c, nil, page.FromURL("http://hyperz-test-no-such-host.invalid/login"))
	if runErr == nil {
		t.Fatal("expected wholesale-failure error to propagate")
	}

	mu.Lock()
	defer mu.Unlock()
	wantAtLeast := len(openRedirectParams)
	if len(errors) < wantAtLeast {
		t.Fatalf("reporter saw %d events, want >= %d (one per probe)", len(errors), wantAtLeast)
	}
	// Every breadcrumb should name the parameter that failed so the user can
	// tell which probe blew up - a bare "connection refused" with no param
	// context defeats the point of the breadcrumb.
	for _, err := range errors {
		if !strings.Contains(err.Error(), "probe param") {
			t.Errorf("breadcrumb missing param context: %v", err)
		}
	}
}

func TestOpenRedirectSkipsCanonicalSweepOnNonRedirectishPath(t *testing.T) {
	// /products has no redirect-ish keyword and the URL carries no params,
	// so candidate set is empty: the check must not send any probes. This
	// is the central blast-radius guarantee - on a 200-page crawl the
	// product/article pages stay un-probed.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/products"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 on non-redirect-ish path with no params", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; non-redirect-ish path with no params must not be probed", got)
	}
}

func TestOpenRedirectProbesUrlParamsEvenOnNonRedirectishPath(t *testing.T) {
	// `next` is canonical but the path /products doesn't earn the canonical
	// sweep. Because `next` is already in the URL it still gets probed - the
	// app is actively passing it, so it's the highest-signal candidate.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("next")
		if v == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", v)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/products?next=original"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from URL-present `next` probe, got %d: %+v", len(findings), findings)
	}
}

func TestOpenRedirectSkipsNonUrlCanonicalNamesOnNonRedirectishPath(t *testing.T) {
	// The page has `next` present (so `next` IS probed) but reflects only
	// `redirect`. Since /products isn't redirect-ish, `redirect` is NOT in
	// the candidate set and the bug stays uncaught at LevelDefault - by
	// design. This pins the blast-radius trade-off: cheap default scans
	// trade away coverage on non-redirect-ish pages.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("redirect")
		if v == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", v)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/products?next=original"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (canonical `redirect` should be skipped on non-redirect-ish path), got %d: %+v", len(findings), findings)
	}
}

func TestOpenRedirectAggressiveLevelSweepsEverywhere(t *testing.T) {
	// At LevelAggressive the canonical sweep fires regardless of path -
	// the user has explicitly opted into the noisier scan. /products is
	// not redirect-ish but `redirect` still gets probed and the bug fires.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("redirect")
		if v == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", v)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := OpenRedirect{}.Run(ctx, newTestClient(t), nil, page.FromURL(srv.URL+"/products"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding at LevelAggressive on non-redirect-ish path, got %d: %+v", len(findings), findings)
	}
}

func TestLooksRedirectish(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/login", true},
		{"/LOGIN", true},
		{"/logout", true},
		{"/api/auth/callback", true},
		{"/admin/sso-init", true},
		{"/go/redirect/123", true},
		{"/authentication", true}, // substring match by design - loose
		{"/products", false},
		{"/articles/2024", false},
		{"/", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := looksRedirectish(tc.path); got != tc.want {
				t.Errorf("looksRedirectish(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestOpenRedirectMatchesHelper(t *testing.T) {
	bs := "\x5c" // single backslash; raw-string handling differs across editors.
	cases := []struct {
		name string
		loc  string
		want bool
	}{
		{"absolute canary", "https://evil.example/hyperz-probe", true},
		{"absolute canary different path", "https://evil.example/elsewhere", true},
		{"protocol relative", "//evil.example/x", true},
		{"different host", "https://safe.example.org/x", false},
		{"same origin path", "/login", false},
		{"empty", "", false},
		{"whitespace", "   ", false},
		{"uppercase host echo", "HTTPS://EVIL.EXAMPLE/x", true},

		// Browser-quirk bypass forms: each form is one strict-parser thinks
		// "no host" but a browser navigates cross-origin to the canary.
		{"backslash double prefix", bs + bs + "evil.example/x", true},
		{"backslash quad prefix", bs + bs + bs + bs + "evil.example/x", true},
		{"mixed slash backslash prefix", bs + "/" + bs + "/evil.example/x", true},
		{"triple slash prefix", "///evil.example/x", true},
		{"quad slash prefix", "////evil.example/x", true},
		{"backslash absolute scheme", "https:" + bs + bs + "evil.example/x", true},
		{"slash backslash mix authority", "/" + bs + "/evil.example/x", true},
		{"userinfo canary actual host target", "//evil.example@target.com/x", false},
		{"userinfo target actual host canary", "//target.com@evil.example/x", true},
		{"userinfo target actual host canary absolute", "https://target.com@evil.example/x", true},

		// A leading single forward slash with the canary name in the path is
		// same-origin and must NOT match - guards against a sloppy normalizer
		// that lifts host out of a path segment.
		{"path containing canary literal", "/evil.example/x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := openRedirectMatches(tc.loc, openRedirectCanary); got != tc.want {
				t.Errorf("openRedirectMatches(%q) = %v, want %v", tc.loc, got, tc.want)
			}
		})
	}
}

// TestOpenRedirectDetectsBackslashBypass exercises the full probe path with a
// server that reflects "\\evil.example/..." in its Location header. Strict URL
// parsers (including Go's stdlib) park the value in path, but Chrome and Edge
// treat backslashes as forward slashes and navigate cross-origin. The
// normalize-and-reparse fallback in locationTargetsHost is what catches it.
func TestOpenRedirectDetectsBackslashBypass(t *testing.T) {
	bs := "\x5c"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Take everything after "https://" and prepend "\\" to produce
		// the backslash bypass form.
		host := strings.TrimPrefix(next, "https://")
		w.Header().Set("Location", bs+bs+host)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for backslash bypass, got %d: %+v", len(findings), findings)
	}
}

// TestOpenRedirectDetectsTripleSlashBypass exercises the "///evil.example"
// reflection - browsers collapse leading slashes to two when parsing Location.
func TestOpenRedirectDetectsTripleSlashBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		host := strings.TrimPrefix(next, "https://")
		w.Header().Set("Location", "///"+host)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for triple-slash bypass, got %d: %+v", len(findings), findings)
	}
}

// TestOpenRedirectDetectsUserinfoBypass: an app that allowlists "target.com"
// can be tricked when an attacker supplies "//target.com@evil.example" - the
// app's host check sees "target.com" first, but a browser parses the
// authority as userinfo=target.com, host=evil.example. The probe needs to
// flag this as a bug because browsers navigate to evil.example.
func TestOpenRedirectDetectsUserinfoBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Hardcoded "target.com" as the allegedly-allowed host. The
		// canary's actual host becomes the post-@ authority.
		host := strings.TrimPrefix(next, "https://")
		w.Header().Set("Location", "//target.com@"+host)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for userinfo-trick bypass, got %d: %+v", len(findings), findings)
	}
}

// TestOpenRedirectIgnoresUserinfoOnlyTrick: the symmetric "//evil.example@target"
// shape looks like the canary host at a glance, but browsers (correctly) put
// evil.example into userinfo and navigate to target. We must NOT false-positive
// here - the victim stays on the trusted host. The server emits this Location
// regardless of the input so the bare authority (no path before @) is what
// the parser sees.
func TestOpenRedirectIgnoresUserinfoOnlyTrick(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("next") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Canary host as userinfo, target.invalid as actual host. Browsers
		// (and our matcher) must navigate to target.invalid.
		w.Header().Set("Location", "//evil.example@target.invalid/x")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings - userinfo-only trick is not exploitable, got %d: %+v", len(findings), findings)
	}
}

// TestOpenRedirectDetectsJSLocationAssign exercises the body-driven sink path:
// 200 OK with inline JS calling location.assign(canary). Many SPA login pages
// bounce this way without ever issuing a 3xx.
func TestOpenRedirectDetectsJSLocationAssign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!doctype html><html><head><script>location.assign("%s");</script></head><body>bouncing</body></html>`, next)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from location.assign sink, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "JavaScript navigation sink") {
		t.Errorf("Detail should name the JS sink kind: %q", findings[0].Detail)
	}
}

// TestOpenRedirectDetectsJSLocationHref covers the assignment form of the JS
// sink (location.href = "...") which is the most common SPA bounce idiom.
func TestOpenRedirectDetectsJSLocationHref(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<script>window.location.href = '%s';</script>`, next)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from location.href sink, got %d: %+v", len(findings), findings)
	}
}

// TestOpenRedirectDetectsJSLocationReplace covers location.replace() which is
// often used to avoid pushing a history entry on the bounce.
func TestOpenRedirectDetectsJSLocationReplace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<script>top.location.replace("%s")</script>`, next)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from location.replace sink, got %d: %+v", len(findings), findings)
	}
}

// TestOpenRedirectDetectsMetaRefresh covers the fallback bounce channel for
// JS-disabled clients: <meta http-equiv="refresh" content="0;url=...">.
func TestOpenRedirectDetectsMetaRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<meta http-equiv="refresh" content="0;url=%s">`, next)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from meta refresh sink, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "meta refresh") {
		t.Errorf("Detail should name the meta refresh sink: %q", findings[0].Detail)
	}
}

// TestOpenRedirectIgnoresCanaryHostMentionOutsideJSSink: the canary host
// appears in the body but NOT as a navigation target (just as text inside a
// <p> tag). Must not false-positive - reflection alone without a sink is not
// an open redirect.
func TestOpenRedirectIgnoresCanaryHostMentionOutsideJSSink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Echo into prose with HTML-encoding so it's clearly not a sink.
		fmt.Fprintf(w, "<p>You asked to go to: %s</p>", next)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings - canary echoed only as prose, got %d: %+v", len(findings), findings)
	}
}

// TestNormalizeBypassyRedirect pins the normalizer rules directly so the
// matcher table tests stay focused on the host-comparison behavior.
func TestNormalizeBypassyRedirect(t *testing.T) {
	bs := "\x5c"
	cases := []struct {
		in, want string
	}{
		{bs + bs + "evil.example/x", "//evil.example/x"},
		{bs + "/" + bs + "/evil.example/x", "//evil.example/x"},
		{"///evil.example/x", "//evil.example/x"},
		{"////evil.example/x", "//evil.example/x"},
		{"https:" + bs + bs + "evil.example/x", "https://evil.example/x"},
		{"https:////evil.example/x", "https://evil.example/x"},
		{"//evil.example/x", "//evil.example/x"},                       // no-op
		{"https://evil.example/x", "https://evil.example/x"},           // no-op
		{"/login?next=foo", "/login?next=foo"},                         // no-op
		{"//target.com@evil.example/x", "//target.com@evil.example/x"}, // no-op (already parseable)
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizeBypassyRedirect(tc.in); got != tc.want {
				t.Errorf("normalizeBypassyRedirect(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
