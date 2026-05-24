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

func TestNoSQLiName(t *testing.T) {
	if got := (NoSQLi{}).Name(); got != "nosqli" {
		t.Fatalf("Name = %q, want nosqli", got)
	}
}

func TestNoSQLiLevel(t *testing.T) {
	if got := (NoSQLi{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// vulnMongoHandler simulates an Express+Mongoose stack that parses
// bracket-notation query params into operator objects (the qs default):
// `id=42`, `id[$eq]=42`, and `id[$in][0]=42` all resolve to the same
// underlying equality query.
func vulnMongoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		q := r.URL.Query()
		target := q.Get("id")
		if target == "" {
			target = q.Get("id[$eq]")
		}
		if target == "" {
			target = q.Get("id[$in][0]")
		}
		if target == "42" {
			_, _ = w.Write([]byte("<html><body><p>User: alice (id=42)</p></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><p>No matching records.</p></body></html>"))
	})
}

func TestNoSQLiDetectsOperatorInjection(t *testing.T) {
	srv := httptest.NewServer(vulnMongoHandler())
	defer srv.Close()

	findings, err := NoSQLi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=42"))
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
	if f.CWE != "CWE-943" {
		t.Errorf("CWE = %q, want CWE-943", f.CWE)
	}
	if !strings.Contains(f.Title, "operator injection") {
		t.Errorf("Title should mention operator injection: %q", f.Title)
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

func TestNoSQLiNoFindingOnSafeServer(t *testing.T) {
	// Safe backend: only reads the literal `id` key, never parses
	// bracketed operator syntax. The bracketed probes look like a
	// missing id to it, so truthy and falsy collapse to the same
	// no-match response - BoolNoSignal / Indeterminate, not vulnerable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		id := r.URL.Query().Get("id")
		if id == "42" {
			_, _ = w.Write([]byte("<html><body><p>User: alice (id=42)</p></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><p>No matching records.</p></body></html>"))
	}))
	defer srv.Close()

	findings, err := NoSQLi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on safe backend, got %d: %+v", len(findings), findings)
	}
}

func TestNoSQLiDetectsErrorBased(t *testing.T) {
	// Backend that surfaces a Mongo driver error when the value carries
	// JS-string-break syntax (the canonical $where injection shape).
	// Boolean phase is silent (bracketed probes don't affect output),
	// so this hits via Phase 2 only.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "';return") || strings.Contains(id, "$ne") || strings.Contains(id, "$gt") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Internal Error: MongoError: $where is not a function"))
			return
		}
		_, _ = w.Write([]byte("<p>OK</p>"))
	}))
	defer srv.Close()

	findings, err := NoSQLi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=42"))
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
	if !strings.Contains(strings.ToLower(f.Detail), "mongoerror") {
		t.Errorf("Detail should mention the matched error signature: %q", f.Detail)
	}
}

func TestNoSQLiBaselineSubtractionSuppressesFalsePositive(t *testing.T) {
	// Docs-style page that always shows "MongoError" text. Baseline
	// subtraction must suppress the always-present pattern from the
	// error-based match - otherwise every page in the wild that
	// mentions Mongo would fire.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<p>Documentation: MongoError exceptions can occur when...</p>"))
	}))
	defer srv.Close()

	findings, err := NoSQLi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (baseline subtraction must suppress always-present Mongo text), got %d: %+v",
			len(findings), findings)
	}
}

func TestNoSQLiSuppressesReflectionOnlyFalsePositive(t *testing.T) {
	// Echo-only page: reflects the value the user supplied. Without the
	// triple value-strip the truthy/falsy bodies would diverge purely
	// from the reflected canary vs the reflected original, producing a
	// false positive on every echoing page.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		id := r.URL.Query().Get("id")
		_, _ = w.Write([]byte("<p>You queried for: " + id + "</p>"))
	}))
	defer srv.Close()

	findings, err := NoSQLi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on echo-only page, got %d: %+v", len(findings), findings)
	}
}

func TestNoSQLiRespectsScope(t *testing.T) {
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
	findings, err := NoSQLi{}.Run(context.Background(), newTestClient(t), sc,
		page.FromURL(srv.URL+"/?id=42"))
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

func TestNoSQLiNoProbeWhenNoSinks(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := NoSQLi{}.Run(context.Background(), newTestClient(t),
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

func TestNoSQLiDedupeKeyStable(t *testing.T) {
	srv := httptest.NewServer(vulnMongoHandler())
	defer srv.Close()

	run := func(rawurl string) string {
		fs, err := NoSQLi{}.Run(context.Background(), newTestClient(t),
			nil, page.FromURL(rawurl))
		if err != nil {
			t.Fatalf("Run %q: %v", rawurl, err)
		}
		if len(fs) != 1 {
			t.Fatalf("Run %q: got %d findings, want 1", rawurl, len(fs))
		}
		return fs[0].DedupeKey
	}
	a := run(srv.URL + "/user?id=42")
	b := run(srv.URL + "/user?id=42") // same URL, stable key
	if a == "" {
		t.Fatal("DedupeKey empty")
	}
	if a != b {
		t.Errorf("same-param keys drifted: %q vs %q", a, b)
	}
}

func TestNoSQLiEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(vulnMongoHandler())
	defer srv.Close()

	findings, err := NoSQLi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=42"))
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
	// diverged from baseline. The vulnerable backend returned the
	// no-match page for the falsy probe.
	if !strings.Contains(ev.Exchange.ResponseBody, "No matching records") {
		t.Errorf("Exchange should carry the falsy response body: %q", ev.Exchange.ResponseBody)
	}
	// The Exchange URL must carry the bracket-injected param so the
	// reviewer can see exactly which operator wedge fired the finding.
	if !strings.Contains(ev.Exchange.URL, "%5B%24") {
		t.Errorf("Exchange URL should carry the encoded bracket+operator: %q", ev.Exchange.URL)
	}
}

func TestNoSQLiSkipsHeaderAndCookieSinks(t *testing.T) {
	// Sinks built directly so we don't depend on aggressive-level
	// header sink expansion (NoSQLi doesn't add header sinks at all).
	// sinkProbable must filter both out so the check never wastes a
	// request on a loc the bracket trick can't reach.
	for _, loc := range []Loc{LocHeader, LocCookie, LocPath} {
		s := Sink{Method: http.MethodGet, URL: "https://example.test/", Loc: loc, Name: "id"}
		if (NoSQLi{}).sinkProbable(s) {
			t.Errorf("sinkProbable(%s) = true, want false", loc)
		}
	}
	for _, loc := range []Loc{LocQuery, LocForm, LocJSON} {
		s := Sink{Method: http.MethodGet, URL: "https://example.test/", Loc: loc, Name: "id"}
		if !(NoSQLi{}).sinkProbable(s) {
			t.Errorf("sinkProbable(%s) = false, want true", loc)
		}
	}
}

func TestNoSQLiMultipleVulnerableParamsProduceDistinctFindings(t *testing.T) {
	// Two params both flow into the operator-aware query. The check
	// should fire one finding per param with distinct DedupeKeys.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		q := r.URL.Query()
		idTarget := q.Get("id")
		if idTarget == "" {
			idTarget = q.Get("id[$eq]")
		}
		if idTarget == "" {
			idTarget = q.Get("id[$in][0]")
		}
		nameTarget := q.Get("name")
		if nameTarget == "" {
			nameTarget = q.Get("name[$eq]")
		}
		if nameTarget == "" {
			nameTarget = q.Get("name[$in][0]")
		}
		if idTarget == "42" && nameTarget == "alice" {
			_, _ = w.Write([]byte("<p>Match: alice (id=42)</p>"))
			return
		}
		_, _ = w.Write([]byte("<p>No matching records.</p>"))
	}))
	defer srv.Close()

	findings, err := NoSQLi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=42&name=alice"))
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

func TestNoSQLiIgnoresUnparseableTarget(t *testing.T) {
	findings, err := NoSQLi{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL("::not-a-url::"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on garbage URL, got %d", len(findings))
	}
}

func TestMatchMongoErrors(t *testing.T) {
	body := []byte("Error response: MongoError: Cast to ObjectId failed for 'abc'")
	hits := matchMongoErrors(body)
	if len(hits) == 0 {
		t.Fatal("expected at least one hit on a known Mongo error pattern")
	}
	gotMongoError := false
	gotCastError := false
	for _, h := range hits {
		if strings.Contains(h, "mongoerror") {
			gotMongoError = true
		}
		if strings.Contains(h, "cast to objectid") {
			gotCastError = true
		}
	}
	if !gotMongoError || !gotCastError {
		t.Errorf("hits = %+v, want one each for mongoerror and cast to objectid", hits)
	}
}

func TestMatchMongoErrorsEmpty(t *testing.T) {
	if got := matchMongoErrors(nil); got != nil {
		t.Errorf("empty body should yield nil hits, got %+v", got)
	}
	if got := matchMongoErrors([]byte("totally benign HTML")); got != nil {
		t.Errorf("clean body should yield nil hits, got %+v", got)
	}
}
