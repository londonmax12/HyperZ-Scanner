package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func sriPage(rawurl, body string) page.Page {
	return page.Page{
		URL:     rawurl,
		Status:  200,
		Headers: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:    []byte(body),
	}
}

func runSRI(t *testing.T, p page.Page) []Finding {
	t.Helper()
	findings, err := SRIMissing{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

func TestSRIMissingName(t *testing.T) {
	if got := (SRIMissing{}).Name(); got != "sri-missing" {
		t.Fatalf("Name = %q, want sri-missing", got)
	}
}

func TestSRIMissingLevel(t *testing.T) {
	if got := (SRIMissing{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestSRIMissingScriptCrossOrigin(t *testing.T) {
	p := sriPage("https://example.com/page",
		`<html><head><script src="https://cdn.example.org/lib.js"></script></head></html>`)
	findings := runSRI(t, p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if !strings.Contains(f.Title, "script") {
		t.Errorf("Title should mention script: %q", f.Title)
	}
	if f.CWE != "CWE-345" {
		t.Errorf("CWE = %q, want CWE-345", f.CWE)
	}
}

func TestSRIMissingScriptWithIntegrityIsOK(t *testing.T) {
	p := sriPage("https://example.com/page",
		`<html><head><script src="https://cdn.example.org/lib.js" integrity="sha384-abc"></script></head></html>`)
	if findings := runSRI(t, p); len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestSRIMissingStylesheetCrossOrigin(t *testing.T) {
	p := sriPage("https://example.com/page",
		`<html><head><link rel="stylesheet" href="https://cdn.example.org/site.css"></head></html>`)
	findings := runSRI(t, p)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium", findings[0].Severity)
	}
}

func TestSRIMissingPreloadAndModulePreloadCovered(t *testing.T) {
	cases := []string{"preload", "modulepreload", "prefetch", "stylesheet alternate"}
	for _, rel := range cases {
		t.Run(rel, func(t *testing.T) {
			body := `<html><head><link rel="` + rel + `" href="https://cdn.example.org/x.js"></head></html>`
			if findings := runSRI(t, sriPage("https://example.com/page", body)); len(findings) != 1 {
				t.Fatalf("rel=%q expected 1 finding, got %d: %+v", rel, len(findings), findings)
			}
		})
	}
}

func TestSRIMissingIgnoresNonSRIRels(t *testing.T) {
	// These rels either don't fetch executable content, don't validate via
	// SRI in any browser, or are navigation hints. Flagging them is noise.
	rels := []string{
		"canonical",
		"icon",
		"shortcut icon",
		"dns-prefetch",
		"preconnect",
		"alternate",
		"manifest",
		"author",
		"",
	}
	for _, rel := range rels {
		t.Run(rel, func(t *testing.T) {
			body := `<html><head><link rel="` + rel + `" href="https://cdn.example.org/x"></head></html>`
			if findings := runSRI(t, sriPage("https://example.com/page", body)); len(findings) != 0 {
				t.Fatalf("rel=%q should not produce a finding, got %d: %+v", rel, len(findings), findings)
			}
		})
	}
}

func TestSRIMissingIgnoresIframes(t *testing.T) {
	// Browsers do not validate integrity on cross-origin iframe src, so any
	// finding for an iframe would be a false positive.
	p := sriPage("https://example.com/page",
		`<html><body><iframe src="https://other.example.org/page"></iframe></body></html>`)
	if findings := runSRI(t, p); len(findings) != 0 {
		t.Fatalf("iframes must not be flagged, got %d: %+v", len(findings), findings)
	}
}

func TestSRIMissingSameOriginSkipped(t *testing.T) {
	p := sriPage("https://example.com/page", `
		<html><head>
			<script src="/static/app.js"></script>
			<script src="https://example.com/static/main.js"></script>
			<link rel="stylesheet" href="/static/site.css">
		</head></html>`)
	if findings := runSRI(t, p); len(findings) != 0 {
		t.Fatalf("same-origin assets must not be flagged, got %d: %+v", len(findings), findings)
	}
}

func TestSRIMissingSameOriginIgnoresPort(t *testing.T) {
	// Default port 443 omitted on one side and explicit on the other should
	// still be treated as same-origin.
	p := sriPage("https://example.com/page",
		`<html><head><script src="https://example.com:443/static/main.js"></script></head></html>`)
	if findings := runSRI(t, p); len(findings) != 0 {
		t.Fatalf("default-port mismatch must not flag, got %d: %+v", len(findings), findings)
	}
}

func TestSRIMissingProtocolRelativeExternalFlagged(t *testing.T) {
	p := sriPage("https://example.com/page",
		`<html><head><script src="//cdn.example.org/lib.js"></script></head></html>`)
	findings := runSRI(t, p)
	if len(findings) != 1 {
		t.Fatalf("protocol-relative external script must be flagged, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "https://cdn.example.org/lib.js") {
		t.Errorf("Detail should resolve protocol-relative URL: %q", findings[0].Detail)
	}
}

func TestSRIMissingProtocolRelativeSameHostSkipped(t *testing.T) {
	p := sriPage("https://example.com/page",
		`<html><head><script src="//example.com/static/main.js"></script></head></html>`)
	if findings := runSRI(t, p); len(findings) != 0 {
		t.Fatalf("protocol-relative same-host script must not flag, got %d: %+v", len(findings), findings)
	}
}

func TestSRIMissingIgnoresNonNetworkSchemes(t *testing.T) {
	p := sriPage("https://example.com/page", `
		<html><head>
			<script src="data:application/javascript,alert(1)"></script>
			<script src="javascript:void(0)"></script>
		</head></html>`)
	if findings := runSRI(t, p); len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-network schemes, got %d: %+v", len(findings), findings)
	}
}

func TestSRIMissingDedupesAcrossDuplicateRefs(t *testing.T) {
	p := sriPage("https://example.com/page", `
		<html><head>
			<script src="https://cdn.example.org/lib.js"></script>
			<script src="https://cdn.example.org/lib.js"></script>
		</head></html>`)
	if findings := runSRI(t, p); len(findings) != 1 {
		t.Fatalf("expected 1 finding (deduplicated), got %d: %+v", len(findings), findings)
	}
}

func TestSRIMissingDedupeKeyStableAcrossPages(t *testing.T) {
	// Same external resource referenced from two different pages on the same
	// host should produce the same DedupeKey so the scanner collapses them
	// into one finding. ScopeHost is what makes this hold.
	body := `<html><head><script src="https://cdn.example.org/lib.js"></script></head></html>`
	a := runSRI(t, sriPage("https://example.com/a", body))
	b := runSRI(t, sriPage("https://example.com/b", body))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding per page, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeKey != b[0].DedupeKey {
		t.Errorf("DedupeKey should match across pages: %q vs %q", a[0].DedupeKey, b[0].DedupeKey)
	}
}

func TestSRIMissingMixedDocument(t *testing.T) {
	// Two missing (script + stylesheet from different cross-origin hosts),
	// two safe (integrity present), four ignored (same-host, canonical link,
	// iframe, internal stylesheet).
	p := sriPage("https://example.com/page", `
		<html><head>
			<script src="https://cdn.a.example/lib1.js"></script>
			<script src="https://cdn.a.example/lib2.js" integrity="sha384-x"></script>
			<link rel="stylesheet" href="https://cdn.b.example/style1.css">
			<link rel="stylesheet" href="https://cdn.b.example/style2.css" integrity="sha384-y">
			<link rel="canonical" href="https://other.example/page">
			<link rel="stylesheet" href="/local/site.css">
			<script src="/local/main.js"></script>
		</head>
		<body><iframe src="https://other.example/embed"></iframe></body>
		</html>`)
	findings := runSRI(t, p)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
}

func TestSRIMissingIgnoresCommentedTags(t *testing.T) {
	// html.NewTokenizer emits comments as CommentToken, so commented-out
	// script tags must not be flagged.
	p := sriPage("https://example.com/page", `
		<html><head>
			<!-- <script src="https://cdn.example.org/lib.js"></script> -->
		</head></html>`)
	if findings := runSRI(t, p); len(findings) != 0 {
		t.Fatalf("commented tags must not flag, got %d: %+v", len(findings), findings)
	}
}

func TestSRIMissingIgnoresNonHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"key":"value"}`))
	}))
	defer srv.Close()

	findings, err := SRIMissing{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-HTML, got %d: %+v", len(findings), findings)
	}
}

func TestSRIMissingEmptyBodyNoOp(t *testing.T) {
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: http.Header{"Content-Type": {"text/html"}},
		Body:    nil,
	}
	if findings := runSRI(t, p); len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty body, got %d: %+v", len(findings), findings)
	}
}

func TestSRIMissingPopulatesEnrichedFields(t *testing.T) {
	p := sriPage("https://example.com/page",
		`<html><head><script src="https://cdn.example.org/lib.js"></script></head></html>`)
	findings := runSRI(t, p)
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
