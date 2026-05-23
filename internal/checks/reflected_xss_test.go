package checks

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonball/hyperz/internal/page"
	"github.com/londonball/hyperz/internal/scope"
)

func TestReflectedXSSName(t *testing.T) {
	if got := (ReflectedXSS{}).Name(); got != "reflected-xss" {
		t.Fatalf("Name = %q, want reflected-xss", got)
	}
}

func TestReflectedXSSLevel(t *testing.T) {
	if got := (ReflectedXSS{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// xssTextHandler echoes ?q= verbatim into HTML text - the canonical
// reflected-XSS-in-text bug.
func xssTextHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body><p>You searched for: " + q + "</p></body></html>"))
	})
}

func TestReflectedXSSDetectsHTMLTextReflection(t *testing.T) {
	srv := httptest.NewServer(xssTextHandler())
	defer srv.Close()

	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/search?q=hello"))
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
	if !strings.Contains(f.Title, "q") {
		t.Errorf("Title should name the param: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "html-text") {
		t.Errorf("Detail should describe the reflection context: %q", f.Detail)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
}

func TestReflectedXSSEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(xssTextHandler())
	defer srv.Close()

	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/search?q=hello"))
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
	if !strings.Contains(ev.Exchange.ResponseBody, "<svg onload") && !strings.Contains(ev.Exchange.ResponseBody, "<img src=x onerror") {
		t.Errorf("Exchange response body should contain the surviving payload: %q", ev.Exchange.ResponseBody)
	}
	if ev.Snippet == "" {
		t.Errorf("Evidence snippet should be populated")
	}
}

func TestReflectedXSSNoFindingWhenInputNotReflected(t *testing.T) {
	// Page renders a fixed string and ignores the query - no reflection,
	// no probe should fire beyond stage 1.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<p>static content</p>"))
	}))
	defer srv.Close()

	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/search?q=anything"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestReflectedXSSNoFindingWhenInputHTMLEncoded(t *testing.T) {
	// Vulnerable-looking endpoint that actually escapes its input.
	// The bare canary still reflects (alphanumeric, unchanged by encoding)
	// so the breakout payload fires, but the rendered tags come back as
	// &lt;svg ... &gt; and the bytes.Contains check fails. No finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<p>" + html.EscapeString(q) + "</p>"))
	}))
	defer srv.Close()

	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/search?q=hello"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings against HTML-encoded reflection, got %d: %+v", len(findings), findings)
	}
}

func TestReflectedXSSDetectsAttributeDoubleQuotedReflection(t *testing.T) {
	// Reflection lands inside value="..." - the right breakout is the
	// attr-double-break payload starting with `">`.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<input value="` + q + `">`))
	}))
	defer srv.Close()

	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?q=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "attr-double-quoted") {
		t.Errorf("Detail should mention attr-double-quoted context: %q", findings[0].Detail)
	}
}

func TestReflectedXSSDetectsAttrUnquotedReflection(t *testing.T) {
	// Reflection lands inside an unquoted attribute value. The HTML-text
	// payloads cannot break out here (parser stays in attr-value-unquoted
	// until `>` or whitespace), so the right breakout is the dedicated
	// attr-unquoted-break payload starting with `>`.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<a href=` + q + `>link</a>`))
	}))
	defer srv.Close()

	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?q=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "attr-unquoted") {
		t.Errorf("Detail should mention attr-unquoted context: %q", findings[0].Detail)
	}
	body := findings[0].Evidence.Exchange.ResponseBody
	if !strings.Contains(body, "><svg onload") {
		t.Errorf("Exchange body should contain the unquoted-break payload: %q", body)
	}
}

func TestReflectedXSSDetectsScriptTextReflection(t *testing.T) {
	// Reflection lands in raw <script> text (between statements, no
	// surrounding string). A JS-string-break payload would emit a
	// syntax error here; the bare js-bare-break payload is required.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<script>var a = 1; ` + q + `; var b = 2;</script>`))
	}))
	defer srv.Close()

	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?q=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "script-text") {
		t.Errorf("Detail should mention script-text context: %q", findings[0].Detail)
	}
	body := findings[0].Evidence.Exchange.ResponseBody
	if !strings.Contains(body, ";alert(") {
		t.Errorf("Exchange body should contain the bare-JS payload: %q", body)
	}
}

func TestReflectedXSSDetectsScriptStringReflection(t *testing.T) {
	// Reflection lands inside a JS double-quoted string. Right breakout:
	// js-string-double-break (`";alert("X");//`).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<script>var name = "` + q + `";</script>`))
	}))
	defer srv.Close()

	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?q=x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "script-string-double") {
		t.Errorf("Detail should mention script-string-double context: %q", findings[0].Detail)
	}
}

func TestReflectedXSSRespectsScope(t *testing.T) {
	// Out-of-scope target: no probe must fire even though the scanner
	// handed the page to us.
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
	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t), sc, page.FromURL(srv.URL+"/?q=x"))
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

func TestReflectedXSSNoProbeWhenNoSinks(t *testing.T) {
	// /static has no query params and no forms: SinksFor is empty so the
	// check returns immediately without issuing a single request.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
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

func TestReflectedXSSDedupeKeyStableAndPerParam(t *testing.T) {
	srv := httptest.NewServer(xssTextHandler())
	defer srv.Close()

	run := func(rawurl string) string {
		fs, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
			nil, page.FromURL(rawurl))
		if err != nil {
			t.Fatalf("Run %q: %v", rawurl, err)
		}
		if len(fs) != 1 {
			t.Fatalf("Run %q: got %d findings, want 1", rawurl, len(fs))
		}
		return fs[0].DedupeKey
	}
	a := run(srv.URL + "/search?q=foo")
	b := run(srv.URL + "/search?q=bar") // same param, different value, same key
	if a == "" {
		t.Fatal("DedupeKey empty")
	}
	if a != b {
		t.Errorf("same-param keys drifted: %q vs %q", a, b)
	}
}

func TestReflectedXSSMultipleVulnerableParamsProduceDistinctFindings(t *testing.T) {
	// Two params both echoed into HTML text. The check should fire one
	// finding per param with distinct DedupeKeys (Scope=Param keyed on
	// loc + param).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<p>" + q + "</p><p>" + name + "</p>"))
	}))
	defer srv.Close()

	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?q=a&name=b"))
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

func TestReflectedXSSReportsTruncationWhenNoFinding(t *testing.T) {
	// Server reflects the canary far past the response-body cap so
	// FindReflections sees nothing. The check must emit a Report breadcrumb
	// so the operator knows the no-finding outcome was on a clipped read,
	// not on a genuinely non-reflecting page.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// 70 KiB of padding (> reflectedXSSBodyCap = 64 KiB) then the
		// reflection, so the cap chops the echo off the read.
		_, _ = w.Write([]byte("<html><body>" + strings.Repeat("a", 70*1024) + q + "</body></html>"))
	}))
	defer srv.Close()

	var reported []string
	ctx := WithReporter(context.Background(), func(err error) {
		reported = append(reported, err.Error())
	})

	findings, err := ReflectedXSS{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/?q=hello"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (reflection past cap), got %d: %+v", len(findings), findings)
	}
	if len(reported) == 0 {
		t.Fatal("expected a truncation breadcrumb via Report, got none")
	}
	joined := strings.Join(reported, "\n")
	if !strings.Contains(joined, "truncated") {
		t.Errorf("Report message should mention truncation: %q", joined)
	}
}

func TestReflectedXSSIgnoresUnparseableTarget(t *testing.T) {
	// Garbage target: not a finding, not an error - silent no-op, same as
	// open-redirect.
	findings, err := ReflectedXSS{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL("::not-a-url::"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on garbage URL, got %d", len(findings))
	}
}

func TestPayloadsForContextsDedupesByName(t *testing.T) {
	// Two reflections in the same context must not yield two copies of
	// the same payload - that would double the request count for no gain.
	refs := []Reflection{
		{Context: CtxAttrDoubleQuoted, Offset: 10},
		{Context: CtxAttrDoubleQuoted, Offset: 99},
	}
	got := payloadsForContexts(refs, LevelDefault)
	if len(got) != 1 || got[0].Name != "attr-double-break" {
		t.Fatalf("got %+v, want one attr-double-break", got)
	}
}

func TestPayloadsForContextsAggressiveReturnsAll(t *testing.T) {
	got := payloadsForContexts([]Reflection{{Context: CtxHTMLText}}, LevelAggressive)
	if len(got) != len(PayloadsFor(PayloadXSS)) {
		t.Fatalf("aggressive returned %d, want full payload list %d", len(got), len(PayloadsFor(PayloadXSS)))
	}
	// Catalog payload count must remain unique by name in the output;
	// otherwise the probe loop would burn duplicate requests.
	names := map[string]int{}
	for _, p := range got {
		names[p.Name]++
		if names[p.Name] > 1 {
			t.Errorf("payload %q appears %d times; aggressive output must be unique", p.Name, names[p.Name])
		}
	}
}

func TestPayloadsForContextsAggressiveFrontLoadsContextMatched(t *testing.T) {
	// Context-matched payloads must appear BEFORE the catalog tail so the
	// probe's first-success short-circuit fires on the matched payload
	// instead of grinding through every alternative first.
	got := payloadsForContexts([]Reflection{{Context: CtxScriptStringDouble}}, LevelAggressive)
	if len(got) == 0 {
		t.Fatal("aggressive returned empty slice")
	}
	if got[0].Name != "js-string-double-break" {
		t.Errorf("first payload at aggressive should be the context-matched js-string-double-break, got %q", got[0].Name)
	}
}

func TestPayloadsForContextsSkipsCommentAndHeaderAtDefault(t *testing.T) {
	refs := []Reflection{
		{Context: CtxHTMLComment, Offset: 1},
		{Context: CtxHeaderValue, Offset: -1, Header: "X-Echo"},
	}
	if got := payloadsForContexts(refs, LevelDefault); len(got) != 0 {
		t.Fatalf("got %+v, want empty for comment + header at default level", got)
	}
}

