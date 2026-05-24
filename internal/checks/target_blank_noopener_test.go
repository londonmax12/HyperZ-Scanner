package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func tbnPage(rawurl, body string) page.Page {
	return page.Page{
		URL:     rawurl,
		Status:  200,
		Headers: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:    []byte(body),
	}
}

func runTBN(t *testing.T, p page.Page) []Finding {
	t.Helper()
	findings, err := TargetBlankNoopener{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

func TestTargetBlankNoopenerName(t *testing.T) {
	if got := (TargetBlankNoopener{}).Name(); got != "target-blank-noopener" {
		t.Fatalf("Name = %q, want target-blank-noopener", got)
	}
}

func TestTargetBlankNoopenerLevel(t *testing.T) {
	if got := (TargetBlankNoopener{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestTargetBlankNoopenerFlagsCrossOriginAnchor(t *testing.T) {
	body := `<html><body>
<a href="https://evil.example.com/landing" target="_blank">Click</a>
</body></html>`
	findings := runTBN(t, tbnPage("https://example.com/page", body))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium (cross-origin)", f.Severity)
	}
	if f.CWE != "CWE-1022" {
		t.Errorf("CWE = %q, want CWE-1022", f.CWE)
	}
	if !strings.Contains(f.Detail, "https://evil.example.com/landing") {
		t.Errorf("Detail missing resolved href: %q", f.Detail)
	}
	if !strings.Contains(f.Title, "cross-origin") {
		t.Errorf("Title should mark cross-origin: %q", f.Title)
	}
}

func TestTargetBlankNoopenerSameOriginIsLow(t *testing.T) {
	body := `<html><body>
<a href="/inner" target="_blank">Open</a>
</body></html>`
	findings := runTBN(t, tbnPage("https://example.com/page", body))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("Severity = %q, want low (same-origin)", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Title, "same-origin") {
		t.Errorf("Title should mark same-origin: %q", findings[0].Title)
	}
}

func TestTargetBlankNoopenerRelNoopenerIsSafe(t *testing.T) {
	body := `<html><body>
<a href="https://evil.example.com/" target="_blank" rel="noopener">Click</a>
<a href="https://evil.example.com/x" target="_blank" rel="NOREFERRER">Click</a>
<a href="https://evil.example.com/y" target="_blank" rel="author noopener external">Click</a>
</body></html>`
	if findings := runTBN(t, tbnPage("https://example.com/page", body)); len(findings) != 0 {
		t.Fatalf("expected 0 findings (rel covers it), got %d: %+v", len(findings), findings)
	}
}

func TestTargetBlankNoopenerOtherTargetsIgnored(t *testing.T) {
	body := `<html><body>
<a href="https://evil.example.com/" target="_self">a</a>
<a href="https://evil.example.com/" target="_top">b</a>
<a href="https://evil.example.com/" target="_parent">c</a>
<a href="https://evil.example.com/">d</a>
</body></html>`
	if findings := runTBN(t, tbnPage("https://example.com/page", body)); len(findings) != 0 {
		t.Fatalf("expected 0 findings (target is not _blank), got %d: %+v", len(findings), findings)
	}
}

func TestTargetBlankNoopenerCaseInsensitiveTarget(t *testing.T) {
	body := `<html><body>
<a href="https://evil.example.com/" target="_BLANK">Click</a>
</body></html>`
	if findings := runTBN(t, tbnPage("https://example.com/page", body)); len(findings) != 1 {
		t.Fatalf("expected 1 finding (case-insensitive _blank), got %d: %+v", len(findings), findings)
	}
}

func TestTargetBlankNoopenerSkipsNonNetworkSchemes(t *testing.T) {
	body := `<html><body>
<a href="javascript:void(0)" target="_blank">a</a>
<a href="mailto:foo@example.com" target="_blank">b</a>
<a href="tel:+15551234" target="_blank">c</a>
<a href="data:text/plain,hi" target="_blank">d</a>
<a href="#section" target="_blank">e</a>
<a href="" target="_blank">f</a>
</body></html>`
	if findings := runTBN(t, tbnPage("https://example.com/page", body)); len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-network hrefs, got %d: %+v", len(findings), findings)
	}
}

func TestTargetBlankNoopenerFlagsArea(t *testing.T) {
	body := `<html><body>
<map><area href="https://evil.example.com/" target="_blank" shape="rect" coords="0,0,10,10"></map>
</body></html>`
	findings := runTBN(t, tbnPage("https://example.com/page", body))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for <area>, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "<area") {
		t.Errorf("Title should mention area tag: %q", findings[0].Title)
	}
}

func TestTargetBlankNoopenerFlagsForm(t *testing.T) {
	body := `<html><body>
<form action="https://evil.example.com/submit" target="_blank" method="post">
  <input type="text" name="x">
</form>
</body></html>`
	findings := runTBN(t, tbnPage("https://example.com/page", body))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for <form target=_blank>, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if !strings.Contains(f.Title, "<form") {
		t.Errorf("Title should mention form tag: %q", f.Title)
	}
	if !strings.Contains(f.Remediation, "<form>") {
		t.Errorf("Remediation should be form-specific: %q", f.Remediation)
	}
}

func TestTargetBlankNoopenerProtocolRelativeFlagged(t *testing.T) {
	body := `<html><body>
<a href="//cdn.evil.example/page" target="_blank">Click</a>
</body></html>`
	findings := runTBN(t, tbnPage("https://example.com/page", body))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "https://cdn.evil.example/page") {
		t.Errorf("Detail should resolve protocol-relative URL: %q", findings[0].Detail)
	}
}

func TestTargetBlankNoopenerHonorsBaseHref(t *testing.T) {
	body := `<html><head>
<base href="https://other.example.com/">
</head><body>
<a href="/landing" target="_blank">Click</a>
</body></html>`
	findings := runTBN(t, tbnPage("https://example.com/page", body))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding via <base href>, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "https://other.example.com/landing") {
		t.Errorf("Detail should show base-resolved URL: %q", findings[0].Detail)
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium (cross-origin after base)", findings[0].Severity)
	}
}

func TestTargetBlankNoopenerDedupesSameRef(t *testing.T) {
	body := `<html><body>
<a href="https://evil.example.com/x" target="_blank">one</a>
<a href="https://evil.example.com/x" target="_blank">two</a>
</body></html>`
	if findings := runTBN(t, tbnPage("https://example.com/page", body)); len(findings) != 1 {
		t.Fatalf("expected 1 finding (deduped), got %d: %+v", len(findings), findings)
	}
}

func TestTargetBlankNoopenerDistinctRefsProduceDistinctFindings(t *testing.T) {
	body := `<html><body>
<a href="https://a.evil.example/" target="_blank">a</a>
<a href="https://b.evil.example/" target="_blank">b</a>
</body></html>`
	findings := runTBN(t, tbnPage("https://example.com/page", body))
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	keys := map[string]struct{}{}
	for _, f := range findings {
		if _, dup := keys[f.DedupeKey]; dup {
			t.Errorf("dedupe collision across distinct refs: %q", f.DedupeKey)
		}
		keys[f.DedupeKey] = struct{}{}
	}
}

func TestTargetBlankNoopenerIgnoresAnchorWithoutHref(t *testing.T) {
	body := `<html><body>
<a target="_blank">no href</a>
</body></html>`
	if findings := runTBN(t, tbnPage("https://example.com/page", body)); len(findings) != 0 {
		t.Fatalf("expected 0 findings for href-less anchor, got %d: %+v", len(findings), findings)
	}
}

func TestTargetBlankNoopenerIgnoresCommentedTags(t *testing.T) {
	body := `<html><body>
<!-- <a href="https://evil.example.com/" target="_blank">Click</a> -->
</body></html>`
	if findings := runTBN(t, tbnPage("https://example.com/page", body)); len(findings) != 0 {
		t.Fatalf("commented tags must not flag, got %d: %+v", len(findings), findings)
	}
}

func TestTargetBlankNoopenerIgnoresNonHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"a":"<a href=https://x target=_blank>x</a>"}`))
	}))
	defer srv.Close()

	findings, err := TargetBlankNoopener{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-HTML, got %d: %+v", len(findings), findings)
	}
}

func TestTargetBlankNoopenerEmptyBody(t *testing.T) {
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: http.Header{"Content-Type": {"text/html"}},
		Body:    nil,
	}
	if findings := runTBN(t, p); len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty body, got %d: %+v", len(findings), findings)
	}
}

func TestTargetBlankNoopenerPopulatesEnrichedFields(t *testing.T) {
	body := `<html><body><a href="https://evil.example.com/" target="_blank">x</a></body></html>`
	findings := runTBN(t, tbnPage("https://example.com/page", body))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Target != "https://example.com/page" || f.URL != "https://example.com/page" {
		t.Errorf("Target/URL mismatch: %q / %q", f.Target, f.URL)
	}
	if f.OWASP == "" || f.Remediation == "" || f.DedupeKey == "" {
		t.Errorf("OWASP/Remediation/DedupeKey must be populated: %+v", f)
	}
	if f.Evidence == nil {
		t.Fatalf("Evidence is nil")
	}
}

func TestTargetBlankNoopenerDuplicateAttrFirstWins(t *testing.T) {
	body := `<html><body>
<a href="https://evil.example.com/" target="_self" target="_blank">first-target-wins</a>
<a href="https://evil.example.com/x" target="_blank" rel="noopener" rel="">first-rel-wins</a>
</body></html>`
	if findings := runTBN(t, tbnPage("https://example.com/page", body)); len(findings) != 0 {
		t.Fatalf("expected 0 findings (browsers honor the first attribute), got %d: %+v", len(findings), findings)
	}
}

func TestTargetBlankNoopenerDedupeKeyStablePerPage(t *testing.T) {
	body := `<html><body><a href="https://evil.example.com/lib" target="_blank">x</a></body></html>`
	a := runTBN(t, tbnPage("https://example.com/page", body))
	b := runTBN(t, tbnPage("https://example.com/page", body))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding per call, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeKey != b[0].DedupeKey {
		t.Errorf("DedupeKey should be stable across runs: %q vs %q", a[0].DedupeKey, b[0].DedupeKey)
	}
}
