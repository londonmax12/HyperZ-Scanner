package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/scope"
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

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, srv.URL+"/login")
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

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, srv.URL+"/login")
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

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, srv.URL+"/")
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

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, srv.URL+"/login")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on same-origin redirect, got %d: %+v", len(findings), findings)
	}
}

func TestOpenRedirectNoFindingWhenNo3xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, srv.URL+"/")
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
	// the canary didn't influence the destination, so no finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://partner.example.org/welcome")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, srv.URL+"/")
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
	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), sc, srv.URL+"/")
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

	_, err := OpenRedirect{}.Run(context.Background(), newTestClient(t),
		nil, srv.URL+"/r?a=1&b=2&next=original")
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
	// Server reflects only ?redirect= (not ?next=). The check should still
	// catch it because `redirect` is in the canonical list.
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

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, srv.URL+"/r")
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
		nil, srv.URL+"/r?weirdname=foo")
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

	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, srv.URL+"/r")
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
		fs, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, srv.URL+path)
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
	profile := run("/profile")
	if loginA == "" {
		t.Fatal("DedupeKey empty")
	}
	if loginA != loginB {
		t.Errorf("same-path keys drifted: %q vs %q", loginA, loginB)
	}
	if loginA == profile {
		t.Errorf("different-path keys collapsed: %q == %q", loginA, profile)
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

	_, _ = OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, srv.URL+"/login")

	if got := followHit.Load(); got != 0 {
		t.Errorf("server saw %d follow-up requests, want 0 (no follow)", got)
	}
}

func TestOpenRedirectIgnoresUnparseableTarget(t *testing.T) {
	// Garbage target: not an error worth surfacing to scan summary; just
	// silently no-op. The crawler/seed loader is responsible for input
	// validation.
	findings, err := OpenRedirect{}.Run(context.Background(), newTestClient(t), nil, "::not-a-url::")
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
	_, err := OpenRedirect{}.Run(context.Background(), c, nil, "http://hyperz-test-no-such-host.invalid/")
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
}

func TestOpenRedirectMatchesHelper(t *testing.T) {
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := openRedirectMatches(tc.loc, openRedirectCanary); got != tc.want {
				t.Errorf("openRedirectMatches(%q) = %v, want %v", tc.loc, got, tc.want)
			}
		})
	}
}
