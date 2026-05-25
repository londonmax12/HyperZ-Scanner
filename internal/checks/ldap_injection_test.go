package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestLDAPiName(t *testing.T) {
	if got := (LDAPi{}).Name(); got != "ldapi" {
		t.Fatalf("Name = %q, want ldapi", got)
	}
}

func TestLDAPiLevel(t *testing.T) {
	if got := (LDAPi{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// vulnLDAPHandler simulates a vulnerable AND-template backend roughly
// equivalent to `(&(cn=USER)(active=true))`. The naive shape is: if the
// injected suffix re-wraps the original value in an OR with an always-
// match operand (`objectClass=*` / `cn=*`) the rebuilt filter still
// matches the original entry; if it instead wraps the original value
// in an AND with a never-match canary the filter collapses to empty.
//
// Concretely: we look at the substring shape of the injection, not at
// the literal characters, so the handler's verdict reflects what a
// permissive LDAP parser would do with the rebuilt filter rather than
// requiring us to ship a full LDAP filter evaluator inside the test.
func vulnLDAPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		id := r.URL.Query().Get("id")

		alwaysMatch := strings.Contains(id, "objectClass=*") || strings.Contains(id, "cn=*")
		neverMatch := strings.Contains(id, "objectClass=hpzc") || strings.Contains(id, "cn=hpzc")

		switch {
		case neverMatch:
			// Falsy injection: rebuilt filter ANDs in a canary that does
			// not exist, so the directory returns no rows even though
			// the cn=admin half is satisfied.
			_, _ = w.Write([]byte("<html><body><p>No matching records.</p></body></html>"))
		case alwaysMatch && strings.HasPrefix(id, "admin"):
			// Truthy injection: rebuilt filter ORs in objectClass=*,
			// which every entry satisfies, so the AND still collapses
			// to "cn=admin matches" - same as baseline.
			_, _ = w.Write([]byte("<html><body><p>User: alice (cn=admin)</p></body></html>"))
		case id == "admin":
			_, _ = w.Write([]byte("<html><body><p>User: alice (cn=admin)</p></body></html>"))
		default:
			_, _ = w.Write([]byte("<html><body><p>No matching records.</p></body></html>"))
		}
	})
}

func TestLDAPiDetectsFilterBreak(t *testing.T) {
	srv := httptest.NewServer(vulnLDAPHandler())
	defer srv.Close()

	findings, err := LDAPi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=admin"))
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
	if f.CWE != "CWE-90" {
		t.Errorf("CWE = %q, want CWE-90", f.CWE)
	}
	if !strings.Contains(f.Title, "filter-break") {
		t.Errorf("Title should mention filter-break: %q", f.Title)
	}
	if !strings.Contains(f.Title, "id") {
		t.Errorf("Title should name the param: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "truthy~baseline") || !strings.Contains(f.Detail, "falsy!=baseline") {
		t.Errorf("Detail should describe the truthy/falsy split: %q", f.Detail)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
}

func TestLDAPiNoFindingOnSafeServer(t *testing.T) {
	// Safe backend: treats every input as a literal cn value; bracket
	// metacharacters never escape the value. Both truthy and falsy
	// probes collapse to "no matching records" so BoolNoSignal /
	// Indeterminate fires - never BoolVulnerable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		id := r.URL.Query().Get("id")
		if id == "admin" {
			_, _ = w.Write([]byte("<html><body><p>User: alice (cn=admin)</p></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><p>No matching records.</p></body></html>"))
	}))
	defer srv.Close()

	findings, err := LDAPi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=admin"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on safe backend, got %d: %+v", len(findings), findings)
	}
}

func TestLDAPiDetectsErrorBased(t *testing.T) {
	// Backend that surfaces an LDAP driver error when the filter cannot
	// be parsed - the classic shape of a service that concatenates
	// untrusted input into a JNDI search filter. The boolean phase is
	// silent here (the always-match / never-match probes don't differ
	// from baseline) so this hits via Phase 2 only.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		id := r.URL.Query().Get("id")
		// Trigger on the lone-backslash / unbalanced-paren payloads.
		if strings.HasSuffix(id, `\`) || strings.HasSuffix(id, `)(`) ||
			strings.HasSuffix(id, `(`) || strings.Contains(id, `(|`) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Internal error: javax.naming.directoryexception: bad search filter"))
			return
		}
		_, _ = w.Write([]byte("<p>OK</p>"))
	}))
	defer srv.Close()

	findings, err := LDAPi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=admin"))
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
	if !strings.Contains(f.Title, "error-based") {
		t.Errorf("Title should mention error-based: %q", f.Title)
	}
	if !strings.Contains(strings.ToLower(f.Detail), "javax.naming") {
		t.Errorf("Detail should mention the matched error signature: %q", f.Detail)
	}
}

func TestLDAPiBaselineSubtractionSuppressesFalsePositive(t *testing.T) {
	// Docs-style page that always shows an LDAP error string. Baseline
	// subtraction must suppress the always-present pattern from the
	// error-based match - otherwise every page that mentions JNDI in
	// its documentation would fire.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<p>Documentation: javax.naming.directoryexception is raised when...</p>"))
	}))
	defer srv.Close()

	findings, err := LDAPi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=admin"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (baseline subtraction must suppress always-present LDAP text), got %d: %+v",
			len(findings), findings)
	}
}

func TestLDAPiSuppressesReflectionOnlyFalsePositive(t *testing.T) {
	// Echo-only page: reflects the value the user supplied. Without
	// the value-and-suffix strip the truthy/falsy bodies would diverge
	// purely from the reflected canary vs the reflected original,
	// producing a false positive on every echoing page.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		id := r.URL.Query().Get("id")
		_, _ = w.Write([]byte("<p>You queried for: " + id + "</p>"))
	}))
	defer srv.Close()

	findings, err := LDAPi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=admin"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on echo-only page, got %d: %+v", len(findings), findings)
	}
}

func TestLDAPiRespectsScope(t *testing.T) {
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
	findings, err := LDAPi{}.Run(context.Background(), newTestClient(t), sc,
		page.FromURL(srv.URL+"/?id=admin"))
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

func TestLDAPiNoProbeWhenNoSinks(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := LDAPi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/static"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without sinks, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; no-sinks page must not be probed", got)
	}
}

func TestLDAPiDedupeKeyStable(t *testing.T) {
	srv := httptest.NewServer(vulnLDAPHandler())
	defer srv.Close()

	run := func(rawurl string) string {
		fs, err := LDAPi{}.Run(context.Background(), newTestClient(t),
			nil, page.FromURL(rawurl))
		if err != nil {
			t.Fatalf("Run %q: %v", rawurl, err)
		}
		if len(fs) != 1 {
			t.Fatalf("Run %q: got %d findings, want 1", rawurl, len(fs))
		}
		return fs[0].DedupeKey
	}
	a := run(srv.URL + "/user?id=admin")
	b := run(srv.URL + "/user?id=admin")
	if a == "" {
		t.Fatal("DedupeKey empty")
	}
	if a != b {
		t.Errorf("same-param keys drifted: %q vs %q", a, b)
	}
}

func TestLDAPiEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(vulnLDAPHandler())
	defer srv.Close()

	findings, err := LDAPi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=admin"))
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
	if ev.Exchange.Status != http.StatusOK {
		t.Errorf("Exchange.Status = %d, want 200", ev.Exchange.Status)
	}
	// Evidence is captured from the falsy probe - the variant that
	// diverged from baseline. On the vulnerable backend that returns
	// the "no matching records" page when the AND-with-canary fires.
	if !strings.Contains(ev.Exchange.ResponseBody, "No matching records") {
		t.Errorf("Exchange should carry the falsy response body: %q", ev.Exchange.ResponseBody)
	}
	// The Exchange URL must carry the canary in the injected suffix so
	// the reviewer can see exactly which AND-canary wedge fired the
	// finding. URL encoding rewrites the bracket / paren chars - we
	// assert on the canary prefix which survives URL encoding intact.
	if !strings.Contains(ev.Exchange.URL, "hpzc") {
		t.Errorf("Exchange URL should carry the rendered canary: %q", ev.Exchange.URL)
	}
}

func TestLDAPiSkipsHeaderAndCookieSinks(t *testing.T) {
	// Headers and cookies are never used to construct LDAP filters in
	// real code - sinkProbable must filter them out so the check never
	// wastes a request on a loc the boolean / error payloads can't
	// meaningfully exercise.
	for _, loc := range []Loc{LocHeader, LocCookie} {
		s := Sink{Method: http.MethodGet, URL: "https://example.test/", Loc: loc, Name: "id"}
		if (LDAPi{}).sinkProbable(s) {
			t.Errorf("sinkProbable(%s) = true, want false", loc)
		}
	}
	for _, loc := range []Loc{LocQuery, LocForm, LocJSON, LocPath} {
		s := Sink{Method: http.MethodGet, URL: "https://example.test/", Loc: loc, Name: "id"}
		if !(LDAPi{}).sinkProbable(s) {
			t.Errorf("sinkProbable(%s) = false, want true", loc)
		}
	}
}

func TestLDAPiMultipleVulnerableParamsProduceDistinctFindings(t *testing.T) {
	// Two params both flow into the LDAP filter. The check should fire
	// one finding per param with distinct DedupeKeys.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		q := r.URL.Query()
		check := func(v string, baseline string) string {
			alwaysMatch := strings.Contains(v, "objectClass=*") || strings.Contains(v, "cn=*")
			neverMatch := strings.Contains(v, "objectClass=hpzc") || strings.Contains(v, "cn=hpzc")
			switch {
			case neverMatch:
				return "miss"
			case alwaysMatch && strings.HasPrefix(v, baseline):
				return "hit"
			case v == baseline:
				return "hit"
			default:
				return "miss"
			}
		}
		idVerdict := check(q.Get("id"), "admin")
		nameVerdict := check(q.Get("name"), "alice")
		if idVerdict == "hit" && nameVerdict == "hit" {
			_, _ = w.Write([]byte("<p>Match: alice (cn=admin)</p>"))
			return
		}
		_, _ = w.Write([]byte("<p>No matching records.</p>"))
	}))
	defer srv.Close()

	findings, err := LDAPi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=admin&name=alice"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (one per vulnerable param), got %d: %+v", len(findings), findings)
	}
	keys := map[string]string{}
	for _, f := range findings {
		if prev, dup := keys[f.DedupeKey]; dup {
			t.Errorf("dedupe collision: %q and %q share key %q", prev, f.Title, f.DedupeKey)
		}
		keys[f.DedupeKey] = f.Title
	}
}

func TestLDAPiIgnoresUnparseableTarget(t *testing.T) {
	findings, err := LDAPi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL("::not-a-url::"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on garbage URL, got %d", len(findings))
	}
}

func TestMatchLDAPErrors(t *testing.T) {
	body := []byte("Error response: javax.naming.DirectoryException: invalid filter syntax for cn=*")
	hits := matchLDAPErrors(body)
	if len(hits) == 0 {
		t.Fatal("expected at least one hit on a known LDAP error pattern")
	}
	gotJNDI := false
	gotFilter := false
	for _, h := range hits {
		if strings.Contains(h, "javax.naming.directoryexception") {
			gotJNDI = true
		}
		if strings.Contains(h, "invalid filter syntax") {
			gotFilter = true
		}
	}
	if !gotJNDI || !gotFilter {
		t.Errorf("hits = %+v, want one each for javax.naming and invalid filter syntax", hits)
	}
}

func TestMatchLDAPErrorsEmpty(t *testing.T) {
	if got := matchLDAPErrors(nil); got != nil {
		t.Errorf("empty body should yield nil hits, got %+v", got)
	}
	if got := matchLDAPErrors([]byte("totally benign HTML")); got != nil {
		t.Errorf("clean body should yield nil hits, got %+v", got)
	}
}
