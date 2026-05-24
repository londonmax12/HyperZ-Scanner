package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestSSTIName(t *testing.T) {
	if got := (SSTI{}).Name(); got != "ssti" {
		t.Fatalf("Name = %q, want ssti", got)
	}
}

func TestSSTILevel(t *testing.T) {
	if got := (SSTI{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// jinja2EvalRe matches "{{ N*M }}" (Jinja2 / Twig syntax) with arbitrary
// integer operands so the test handlers cover both the initial 7*7 probe
// and the SSTI check's 8*9 confirmation probe without per-test rewrites.
var jinja2EvalRe = regexp.MustCompile(`\{\{(\d+)\*(\d+)\}\}`)

// freeMarkerEvalRe matches "${ N*M }" (FreeMarker / Mako / Spring EL).
var freeMarkerEvalRe = regexp.MustCompile(`\$\{(\d+)\*(\d+)\}`)

// erbEvalRe matches "<%= N*M %>" (ERB).
var erbEvalRe = regexp.MustCompile(`<%=\s*(\d+)\*(\d+)\s*%>`)

// evalAllMath rewrites every matching template expression in s with the
// integer product of its operands. Used by test handlers to simulate a
// template engine that honors arbitrary "N*M" expressions, not just the
// hard-coded "7*7" pair the original check used. With the confirmation
// step now firing "8*9" after a "7*7" hit, both must evaluate for the
// test handler to look like a real vulnerable backend.
func evalAllMath(s string, re *regexp.Regexp) string {
	return re.ReplaceAllStringFunc(s, func(match string) string {
		m := re.FindStringSubmatch(match)
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		return strconv.Itoa(a * b)
	})
}

// vulnJinja2Handler simulates a backend that renders the query param through Jinja2.
func vulnJinja2Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("template")
		result := evalAllMath(param, jinja2EvalRe)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("result: " + result))
	})
}

func TestSSTIDetectsJinja2ExprEval(t *testing.T) {
	srv := httptest.NewServer(vulnJinja2Handler())
	defer srv.Close()

	findings, err := SSTI{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?template=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical (confirmed)", f.Severity)
	}
	if f.CWE != "CWE-1336" {
		t.Errorf("CWE = %q, want CWE-1336", f.CWE)
	}
	if !strings.Contains(f.Title, "expression evaluation") {
		t.Errorf("Title should mention expression evaluation: %q", f.Title)
	}
	if strings.Contains(f.Title, "unconfirmed") {
		t.Errorf("Title should not say unconfirmed when both probes hit: %q", f.Title)
	}
	if !strings.Contains(strings.ToLower(f.Detail), "jinja2") {
		t.Errorf("Detail should mention jinja2: %q", f.Detail)
	}
	if !strings.Contains(f.Detail, "confirmed") {
		t.Errorf("Detail should report confirmation outcome: %q", f.Detail)
	}
}

// vulnFreeMarkerHandler evaluates FreeMarker ${} expressions.
func vulnFreeMarkerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("template")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(evalAllMath(param, freeMarkerEvalRe)))
	})
}

func TestSSTIDetectsFreeMarkerExprEval(t *testing.T) {
	srv := httptest.NewServer(vulnFreeMarkerHandler())
	defer srv.Close()

	findings, err := SSTI{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?template=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical for expression eval")
	}
}

// vulnERBHandler evaluates ERB <% %> expressions.
func vulnERBHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("template")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(evalAllMath(param, erbEvalRe)))
	})
}

func TestSSTIDetectsERBExprEval(t *testing.T) {
	srv := httptest.NewServer(vulnERBHandler())
	defer srv.Close()

	findings, err := SSTI{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?template=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical for expression eval")
	}
}

// fakeJinja2OneShotHandler evaluates ONLY the literal "{{7*7}}" pattern and
// reflects every other expression verbatim. Models a non-vulnerable page
// that nonetheless happens to round-trip a "49" in the right shape on
// the first probe; the confirmation step's "8*9" sweep fails to evaluate,
// so the SSTI check downgrades the finding from Critical to High rather
// than dropping it entirely (the first hit is still strong evidence).
func fakeJinja2OneShotHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("template")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.ReplaceAll(param, "{{7*7}}", "49")))
	})
}

func TestSSTIUnconfirmedDemotedToHigh(t *testing.T) {
	srv := httptest.NewServer(fakeJinja2OneShotHandler())
	defer srv.Close()

	findings, err := SSTI{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?template=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high (confirm probe did not match)", f.Severity)
	}
	if !strings.Contains(f.Title, "unconfirmed") {
		t.Errorf("Title should mark finding unconfirmed: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "did not confirm") {
		t.Errorf("Detail should call out the failed confirmation: %q", f.Detail)
	}
}

// vulnJinja2ErrorHandler leaks Jinja2 errors on malformed templates.
func vulnJinja2ErrorHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("template")
		// Unclosed braces trigger a template syntax error
		if strings.HasPrefix(param, "{{") && !strings.Contains(param, "}}") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("jinja2.exceptions.TemplateSyntaxError: unexpected '{'"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
}

func TestSSTIDetectsErrorBased(t *testing.T) {
	srv := httptest.NewServer(vulnJinja2ErrorHandler())
	defer srv.Close()

	findings, err := SSTI{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?template=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high (error-based is lower confidence than expression eval)", f.Severity)
	}
	if !strings.Contains(f.Title, "error-based") {
		t.Errorf("Title should mention error-based: %q", f.Title)
	}
	if !strings.Contains(strings.ToLower(f.Detail), "jinja2") {
		t.Errorf("Detail should mention jinja2: %q", f.Detail)
	}
}

// pageAlwaysShowsError shows a Jinja2 error regardless of input - to test baseline subtraction.
func pageAlwaysShowsError() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Documentation: jinja2.exceptions.TemplateSyntaxError can occur when..."))
	})
}

func TestSSTIBaselineSubtractionSuppressesFalsePositive(t *testing.T) {
	srv := httptest.NewServer(pageAlwaysShowsError())
	defer srv.Close()

	findings, err := SSTI{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?template=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (baseline subtraction should suppress always-present error), got %d", len(findings))
	}
}

func TestSSTINoFindingOnSafeServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("safe content"))
	}))
	defer srv.Close()

	findings, err := SSTI{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?template=test"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on safe server, got %d", len(findings))
	}
}

func TestSSTIRespectsScope(t *testing.T) {
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
	findings, err := SSTI{}.Run(context.Background(), newTestClient(t), sc,
		page.FromURL(srv.URL+"/?template=x"))
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

func TestSSTINoProbeWhenNoSinks(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SSTI{}.Run(context.Background(), newTestClient(t),
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

func TestSSTIExprEvalSeverityIsCritical(t *testing.T) {
	srv := httptest.NewServer(vulnJinja2Handler())
	defer srv.Close()

	findings, err := SSTI{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?template=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expression eval finding must be SeverityCritical, got %q", findings[0].Severity)
	}
}

func TestSSTIErrorBasedSeverityIsHigh(t *testing.T) {
	srv := httptest.NewServer(vulnJinja2ErrorHandler())
	defer srv.Close()

	findings, err := SSTI{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?template=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("error-based finding must be SeverityHigh, got %q", findings[0].Severity)
	}
}

func TestSSTIAggressive_ProbesHeaders(t *testing.T) {
	var userAgent atomic.Value
	userAgent.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		result := evalAllMath(ua, jinja2EvalRe)
		if result != ua {
			userAgent.Store(result)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(result))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := SSTI{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for User-Agent header at LevelAggressive, got %d", len(findings))
	}
	ua := userAgent.Load().(string)
	if ua == "" {
		t.Fatal("User-Agent header was never probed")
	}
	// "49" is the initial 7*7 probe, "72" is the 8*9 confirmation probe;
	// the handler stores the result of whichever request landed last, so
	// either is acceptable proof the engine evaluated the header.
	if !strings.Contains(ua, "49") && !strings.Contains(ua, "72") {
		t.Errorf("User-Agent should contain an evaluated math result, got %q", ua)
	}
}

func TestSSTIDefaultDoesNotProbeHeaders(t *testing.T) {
	var userAgentHit atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if strings.Contains(ua, "{{7*7}}") {
			userAgentHit.Store(true)
			result := strings.ReplaceAll(ua, "{{7*7}}", "49")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(result))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Explicitly set to LevelDefault (even though it's the default)
	ctx := WithLevel(context.Background(), LevelDefault)
	findings, err := SSTI{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings at LevelDefault, got %d", len(findings))
	}
	if userAgentHit.Load() {
		t.Fatal("User-Agent header was probed at LevelDefault, should only happen at LevelAggressive")
	}
}

func TestSSTIDedupeKeyStable(t *testing.T) {
	srv := httptest.NewServer(vulnJinja2Handler())
	defer srv.Close()

	run := func(rawurl string) string {
		fs, err := SSTI{}.Run(context.Background(), newTestClient(t),
			nil, page.FromURL(rawurl))
		if err != nil {
			t.Fatalf("Run %q: %v", rawurl, err)
		}
		if len(fs) != 1 {
			t.Fatalf("Run %q: got %d findings, want 1", rawurl, len(fs))
		}
		return fs[0].DedupeKey
	}
	a := run(srv.URL + "/?template=42")
	b := run(srv.URL + "/?template=99") // same param, different value
	if a == "" {
		t.Fatal("DedupeKey empty")
	}
	if a != b {
		t.Errorf("same-param keys drifted: %q vs %q", a, b)
	}
}

func TestSSTIEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(vulnJinja2Handler())
	defer srv.Close()

	findings, err := SSTI{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?template=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding")
	}
	ev := findings[0].Evidence
	if ev == nil || ev.Exchange == nil {
		t.Fatalf("Evidence/Exchange missing: %+v", ev)
	}
	if ev.Exchange.Status != http.StatusOK {
		t.Errorf("Exchange.Status = %d, want 200", ev.Exchange.Status)
	}
	if !strings.Contains(ev.Exchange.ResponseBody, "49") {
		t.Errorf("Exchange body should contain evaluated result, got %q", ev.Exchange.ResponseBody)
	}
}

func TestMatchSSTIErrors(t *testing.T) {
	body := []byte("Error: jinja2.exceptions.TemplateSyntaxError at line 42")
	hits := matchSSTIErrors(body)
	if len(hits) == 0 {
		t.Fatal("expected at least one hit on a known error pattern")
	}
	found := false
	for _, h := range hits {
		if strings.Contains(h, "jinja2") {
			found = true
		}
	}
	if !found {
		t.Errorf("hits = %+v, want one mentioning jinja2", hits)
	}
}

func TestMatchSSTIErrorsEmpty(t *testing.T) {
	if got := matchSSTIErrors(nil); got != nil {
		t.Errorf("empty body should yield nil hits, got %+v", got)
	}
	if got := matchSSTIErrors([]byte("totally benign HTML")); got != nil {
		t.Errorf("clean body should yield nil hits, got %+v", got)
	}
}

func TestSSTIConfirmProbeSwapsOperands(t *testing.T) {
	// Confirmation derives a 2nd probe from the 1st by string-replacing
	// "7*7" with "8*9" in the template; expected becomes "72". This
	// invariant is what keeps confirm probes engine-agnostic.
	tpl, expected := SSTI{}.confirmProbe(SSTIProbe{
		Name:     "freemarker",
		Template: `{{TOKEN}}${7*7}{{TOKEN}}`,
		Expected: "49",
	})
	if tpl != `{{TOKEN}}${8*9}{{TOKEN}}` {
		t.Errorf("confirm template = %q, want {{TOKEN}}${8*9}{{TOKEN}}", tpl)
	}
	if expected != "72" {
		t.Errorf("confirm expected = %q, want 72", expected)
	}
}
