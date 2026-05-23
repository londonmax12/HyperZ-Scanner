package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonball/hyperz/internal/page"
	"github.com/londonball/hyperz/internal/scope"
)

func TestSQLiBooleanName(t *testing.T) {
	if got := (SQLiBoolean{}).Name(); got != "sqli-boolean" {
		t.Fatalf("Name = %q, want sqli-boolean", got)
	}
}

func TestSQLiBooleanLevel(t *testing.T) {
	if got := (SQLiBoolean{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// vulnBooleanHandler simulates a backend that concatenates the `id`
// query param into a WHERE clause: any payload making the WHERE evaluate
// false (the falsy variants ` AND '1'='2`, ` AND 1=2`) returns an empty
// row set; everything else returns the canonical row.
func vulnBooleanHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		falsy := strings.Contains(id, "1=2") || strings.Contains(id, "'1'='2'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if falsy {
			_, _ = w.Write([]byte("<html><body><p>No matching records.</p></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><p>User: alice (id=42)</p></body></html>"))
	})
}

func TestSQLiBooleanDetectsVulnerableParameter(t *testing.T) {
	srv := httptest.NewServer(vulnBooleanHandler())
	defer srv.Close()

	findings, err := SQLiBoolean{}.Run(context.Background(), newTestClient(t),
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
	if f.CWE != "CWE-89" {
		t.Errorf("CWE = %q, want CWE-89", f.CWE)
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

func TestSQLiBooleanEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(vulnBooleanHandler())
	defer srv.Close()

	findings, err := SQLiBoolean{}.Run(context.Background(), newTestClient(t),
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
	// Evidence is captured from the falsy probe - the variant that
	// demonstrably diverges from baseline.
	if !strings.Contains(ev.Exchange.ResponseBody, "No matching records") {
		t.Errorf("Exchange should carry the falsy response body: %q", ev.Exchange.ResponseBody)
	}
	// URL-decode the query so the check works regardless of which curated
	// pair fired (string-quoted, numeric, or their comment-terminated
	// twins all encode differently on the wire).
	parsed, perr := url.Parse(ev.Exchange.URL)
	if perr != nil {
		t.Fatalf("parse exchange URL: %v", perr)
	}
	got := parsed.Query().Get("id")
	if !strings.Contains(got, "1=2") && !strings.Contains(got, "'1'='2") {
		t.Errorf("Exchange URL should carry the falsy payload (decoded id=%q)", got)
	}
}

func TestSQLiBooleanNoFindingOnRobustParameter(t *testing.T) {
	// Parameterized backend: response is identical regardless of payload,
	// so truthy~baseline AND falsy~baseline = BoolNoSignal.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<p>fixed safe content</p>"))
	}))
	defer srv.Close()

	findings, err := SQLiBoolean{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on robust param, got %d: %+v", len(findings), findings)
	}
}

func TestSQLiBooleanSuppressesReflectionOnlyFalsePositive(t *testing.T) {
	// Echo-only page: every response body contains the verbatim wire
	// value, so truthy and falsy bodies differ from baseline only by
	// the appended pair suffix. The strip step must remove those
	// suffixes before BooleanCompare runs - otherwise the page is
	// flagged as vulnerable on every request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<p>You queried for: " + id + "</p>"))
	}))
	defer srv.Close()

	findings, err := SQLiBoolean{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on echo-only page, got %d: %+v", len(findings), findings)
	}
}

func TestSQLiBooleanRespectsScope(t *testing.T) {
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
	findings, err := SQLiBoolean{}.Run(context.Background(), newTestClient(t), sc,
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

func TestSQLiBooleanNoProbeWhenNoSinks(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SQLiBoolean{}.Run(context.Background(), newTestClient(t),
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

func TestSQLiBooleanDedupeKeyStableAndPerParam(t *testing.T) {
	srv := httptest.NewServer(vulnBooleanHandler())
	defer srv.Close()

	run := func(rawurl string) string {
		fs, err := SQLiBoolean{}.Run(context.Background(), newTestClient(t),
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
	b := run(srv.URL + "/user?id=99") // same param, different value, same key
	if a == "" {
		t.Fatal("DedupeKey empty")
	}
	if a != b {
		t.Errorf("same-param keys drifted: %q vs %q", a, b)
	}
}

func TestSQLiBooleanMultipleVulnerableParamsProduceDistinctFindings(t *testing.T) {
	// Two params both flow into the SQL WHERE clause. The check should
	// fire one finding per param with distinct DedupeKeys.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		falsy := false
		for _, k := range []string{"id", "name"} {
			v := r.URL.Query().Get(k)
			if strings.Contains(v, "1=2") || strings.Contains(v, "'1'='2'") {
				falsy = true
				break
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if falsy {
			_, _ = w.Write([]byte("<p>No matching records.</p>"))
			return
		}
		_, _ = w.Write([]byte("<p>User: alice</p>"))
	}))
	defer srv.Close()

	findings, err := SQLiBoolean{}.Run(context.Background(), newTestClient(t),
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

func TestSQLiBooleanAppendsPayloadOntoOriginalValue(t *testing.T) {
	// Server records the wire value for the falsy probe (the only one
	// that uses our handler's distinctive marker). Wire value must
	// start with the original value `42`, confirming append-not-replace.
	var seenFalsy atomic.Value
	seenFalsy.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		falsy := strings.Contains(id, "1=2") || strings.Contains(id, "'1'='2'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if falsy {
			seenFalsy.Store(id)
			_, _ = w.Write([]byte("<p>No matching records.</p>"))
			return
		}
		_, _ = w.Write([]byte("<p>User: alice</p>"))
	}))
	defer srv.Close()

	_, err := SQLiBoolean{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := seenFalsy.Load().(string)
	if got == "" {
		t.Fatalf("server never saw a falsy probe")
	}
	if !strings.HasPrefix(got, "42") {
		t.Errorf("wire value = %q, want a string starting with the original \"42\"", got)
	}
}

func TestSQLiBooleanIgnoresUnparseableTarget(t *testing.T) {
	findings, err := SQLiBoolean{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL("::not-a-url::"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on garbage URL, got %d", len(findings))
	}
}

func TestSQLiBooleanIndeterminateProducesNoFinding(t *testing.T) {
	// Asymmetric divergence (truthy diverges from baseline, falsy
	// matches) is BoolIndeterminate - not the boolean-SQLi pattern.
	// The check must NOT report it as a finding; that's the precision
	// guarantee that keeps false-positive rate low on weirdly-behaving
	// apps.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Diverge specifically on the truthy variants; falsy + baseline
		// look the same.
		if strings.Contains(id, "1=1") || strings.Contains(id, "'1'='1'") {
			_, _ = w.Write([]byte("<p>weird truthy-only response</p>"))
			return
		}
		_, _ = w.Write([]byte("<p>baseline response</p>"))
	}))
	defer srv.Close()

	findings, err := SQLiBoolean{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on indeterminate behavior, got %d: %+v", len(findings), findings)
	}
}

