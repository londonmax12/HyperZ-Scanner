package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
)

func TestMixedContentName(t *testing.T) {
	if got := (MixedContent{}).Name(); got != "mixed-content" {
		t.Fatalf("Name = %q, want mixed-content", got)
	}
}

func TestMixedContentLevel(t *testing.T) {
	if got := (MixedContent{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestMixedContentSkippedOnHTTP(t *testing.T) {
	// On plaintext pages we deliberately produce nothing, the bigger issue
	// (page itself is HTTP) is surfaced elsewhere.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><img src="http://example.com/a.png"></body></html>`))
	}))
	defer srv.Close()

	findings, err := MixedContent{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on HTTP, got %d: %+v", len(findings), findings)
	}
}

func TestMixedContentSkippedOnNonHTMLContentType(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"href":"http://example.com/x.js"}`))
	}))
	defer srv.Close()

	findings, err := MixedContent{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-HTML content-type, got %d: %+v", len(findings), findings)
	}
}

func TestMixedContentCleanPageNoFindings(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
<script src="https://cdn.example.com/app.js"></script>
<img src="/static/logo.png">
<a href="http://example.com/page">link is navigation, not mixed</a>
</body></html>`))
	}))
	defer srv.Close()

	findings, err := MixedContent{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on clean page, got %d: %+v", len(findings), findings)
	}
}

func TestMixedContentActiveSeverityHigh(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
<script src="http://cdn.example.com/app.js"></script>
</body></html>`))
	}))
	defer srv.Close()

	findings, err := MixedContent{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
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
	if !strings.Contains(f.Title, "active") || !strings.Contains(f.Title, "<script>") {
		t.Errorf("Title = %q, want active+<script>", f.Title)
	}
	if f.CWE != "CWE-319" {
		t.Errorf("CWE = %q, want CWE-319", f.CWE)
	}
	if !strings.Contains(f.Detail, "http://cdn.example.com/app.js") {
		t.Errorf("Detail missing offending URL: %q", f.Detail)
	}
}

func TestMixedContentPassiveSeverityLow(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
<img src="http://images.example.com/banner.png">
</body></html>`))
	}))
	defer srv.Close()

	findings, err := MixedContent{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityLow {
		t.Errorf("Severity = %q, want low", f.Severity)
	}
	if !strings.Contains(f.Title, "passive") {
		t.Errorf("Title = %q, want passive", f.Title)
	}
}

func TestMixedContentMultipleTagsAndDedupePerURL(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Same script URL referenced twice -> one finding.
		// Different URLs across active/passive tags -> distinct findings.
		// <a href> with http:// must not produce a finding (navigation).
		_, _ = w.Write([]byte(`<html><body>
<script src="http://cdn.example.com/app.js"></script>
<script src="http://cdn.example.com/app.js"></script>
<img src="http://img.example.com/a.png">
<link rel="stylesheet" href="http://cdn.example.com/style.css">
<form action="http://forms.example.com/submit"><input name="x"></form>
<a href="http://example.com/page">nav</a>
</body></html>`))
	}))
	defer srv.Close()

	findings, err := MixedContent{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Expect 4 unique URLs: app.js, a.png, style.css, submit.
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d: %+v", len(findings), findings)
	}
	bySeverity := map[Severity]int{}
	for _, f := range findings {
		bySeverity[f.Severity]++
		if f.Check != "mixed-content" {
			t.Errorf("unexpected check %q", f.Check)
		}
		if strings.Contains(f.Detail, "example.com/page") {
			t.Errorf("anchor href should not produce a finding: %q", f.Detail)
		}
	}
	if bySeverity[SeverityHigh] != 3 { // script, link, form
		t.Errorf("expected 3 high findings, got %d (%v)", bySeverity[SeverityHigh], bySeverity)
	}
	if bySeverity[SeverityLow] != 1 { // img
		t.Errorf("expected 1 low finding, got %d (%v)", bySeverity[SeverityLow], bySeverity)
	}
}

func TestMixedContentIgnoresCommentedTags(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
<!-- <script src="http://evil.example.com/x.js"></script> -->
<p>hello</p>
</body></html>`))
	}))
	defer srv.Close()

	findings, err := MixedContent{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (commented out), got %d: %+v", len(findings), findings)
	}
}

func TestMixedContentDedupeStableAcrossRuns(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
<script src="http://cdn.example.com/a.js"></script>
<img src="http://img.example.com/b.png">
</body></html>`))
	}))
	defer srv.Close()

	run := func() map[string]string {
		fs, err := MixedContent{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		out := make(map[string]string, len(fs))
		for _, f := range fs {
			out[f.Title] = f.DedupeKey
		}
		return out
	}
	a, b := run(), run()
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("expected 2 findings each; got %d / %d", len(a), len(b))
	}
	for title, key := range a {
		if b[title] != key {
			t.Errorf("dedupe key for %q drifted: %q vs %q", title, key, b[title])
		}
	}
	seen := map[string]string{}
	for title, key := range a {
		if other, dup := seen[key]; dup {
			t.Errorf("%q and %q share dedupe key %q", other, title, key)
		}
		seen[key] = title
	}
}

func TestMixedContentPopulatesEnrichedFields(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script src="http://cdn.example.com/app.js"></script></body></html>`))
	}))
	defer srv.Close()

	findings, err := MixedContent{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Target != srv.URL {
		t.Errorf("Target = %q, want %q", f.Target, srv.URL)
	}
	if f.URL == "" {
		t.Errorf("URL empty - should be the observed request URL")
	}
	if f.OWASP == "" {
		t.Errorf("OWASP empty")
	}
	if f.Remediation == "" {
		t.Errorf("Remediation empty")
	}
	if f.DedupeKey == "" {
		t.Errorf("DedupeKey empty")
	}
	if f.Evidence == nil {
		t.Fatalf("Evidence is nil")
	}
	if f.Evidence.Method != "GET" || f.Evidence.Status != 200 {
		t.Errorf("Evidence method/status = %q/%d", f.Evidence.Method, f.Evidence.Status)
	}
}

func TestMixedContentSingleQuotedAndUppercaseScheme(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
<img src='HTTP://images.example.com/x.png'>
</body></html>`))
	}))
	defer srv.Close()

	findings, err := MixedContent{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
}

func TestMixedContentReturnsErrorOnNetworkFailure(t *testing.T) {
	c := httpclient.New(httpclient.Config{
		Timeout:   1 * time.Second,
		UserAgent: "test",
	})
	// HTTPS URL because the check now short-circuits on non-HTTPS pages
	// (mixed content only exists on HTTPS); the test still exercises the
	// "fetch fails, error propagates" branch.
	_, err := MixedContent{}.Run(context.Background(), c, nil, page.FromURL("https://hyperz-test-no-such-host.invalid"))
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
}
