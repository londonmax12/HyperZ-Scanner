package checks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestXXEName(t *testing.T) {
	if got := (XXE{}).Name(); got != "xxe" {
		t.Fatalf("Name = %q, want xxe", got)
	}
}

func TestXXELevel(t *testing.T) {
	if got := (XXE{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// vulnXXEFileHandler simulates a backend that resolves external entities
// in the POSTed XML body and inlines the file content into its response.
// A pinch of /etc/passwd is enough to land in TraversalMarkers.
func vulnXXEFileHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `SYSTEM "file:///etc/passwd"`) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("parsed: <foo>root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/sh</foo>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestXXEDetectsFileDisclosureOnFormPost(t *testing.T) {
	srv := httptest.NewServer(vulnXXEFileHandler())
	defer srv.Close()

	p := page.Page{
		URL: srv.URL + "/",
		Forms: []page.Form{
			{Method: http.MethodPost, Action: srv.URL + "/api"},
		},
	}
	findings, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical (file disclosure)", f.Severity)
	}
	if f.CWE != "CWE-611" {
		t.Errorf("CWE = %q, want CWE-611", f.CWE)
	}
	if !strings.Contains(f.Title, "file disclosure") {
		t.Errorf("Title should mention file disclosure: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "file:///etc/passwd") {
		t.Errorf("Detail should name the SYSTEM target: %q", f.Detail)
	}
	if f.Evidence == nil || f.Evidence.Exchange == nil {
		t.Fatalf("Evidence/Exchange missing: %+v", f.Evidence)
	}
	if !strings.Contains(f.Evidence.Exchange.RequestBody, "<!ENTITY") {
		t.Errorf("Exchange.RequestBody should include the XXE payload, got %q", f.Evidence.Exchange.RequestBody)
	}
}

// vulnXXEErrorHandler simulates a backend that parses XML and leaks
// libxml-style errors on undefined entities, without ever resolving
// externals (the hardened-but-still-parsing case).
func vulnXXEErrorHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "hyperz_undefined_xxe_canary") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("XML parsing error: Undefined entity: hyperz_undefined_xxe_canary at line 1 column 42"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestXXEDetectsErrorBased(t *testing.T) {
	srv := httptest.NewServer(vulnXXEErrorHandler())
	defer srv.Close()

	p := page.Page{
		URL: srv.URL + "/",
		Forms: []page.Form{
			{Method: http.MethodPost, Action: srv.URL + "/api"},
		},
	}
	findings, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high (error-based)", f.Severity)
	}
	if !strings.Contains(f.Title, "error-based") {
		t.Errorf("Title should mention error-based: %q", f.Title)
	}
}

// pageAlwaysShowsXXEError shows a libxml-shaped error regardless of input -
// to verify baseline subtraction suppresses it.
func pageAlwaysShowsXXEError() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Documentation: Undefined entity errors can occur when..."))
	})
}

func TestXXEBaselineSubtractionSuppressesFalsePositive(t *testing.T) {
	srv := httptest.NewServer(pageAlwaysShowsXXEError())
	defer srv.Close()

	p := page.Page{
		URL: srv.URL + "/",
		Forms: []page.Form{
			{Method: http.MethodPost, Action: srv.URL + "/api"},
		},
	}
	findings, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (baseline subtraction should suppress always-present error), got %d", len(findings))
	}
}

func TestXXENoFindingOnSafeServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("safe content"))
	}))
	defer srv.Close()

	p := page.Page{
		URL: srv.URL + "/",
		Forms: []page.Form{
			{Method: http.MethodPost, Action: srv.URL + "/api"},
		},
	}
	findings, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on safe server, got %d", len(findings))
	}
}

func TestXXENoProbeWhenNoCandidates(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Page with no XML hint, no forms, no SpecOps - nothing to probe at default level.
	p := page.FromURL(srv.URL + "/static.html")
	findings, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; no-candidate page must not be probed", got)
	}
}

func TestXXEProbesPageWhenContentTypeIsXML(t *testing.T) {
	srv := httptest.NewServer(vulnXXEFileHandler())
	defer srv.Close()

	p := page.Page{
		URL:     srv.URL + "/feed",
		Headers: http.Header{"Content-Type": []string{"application/xml; charset=utf-8"}},
	}
	findings, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when page advertises XML content-type, got %d", len(findings))
	}
}

func TestXXEProbesPageWhenPathEndsInXML(t *testing.T) {
	srv := httptest.NewServer(vulnXXEFileHandler())
	defer srv.Close()

	p := page.FromURL(srv.URL + "/api/data.xml")
	findings, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when path ends in .xml, got %d", len(findings))
	}
}

func TestXXEDefaultDoesNotProbeArbitraryPageURL(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// HTML page, no forms, no SpecOps, no XML content-type. At LevelDefault
	// the XXE check should NOT speculatively POST.
	p := page.Page{
		URL:     srv.URL + "/",
		Headers: http.Header{"Content-Type": []string{"text/html"}},
	}
	ctx := WithLevel(context.Background(), LevelDefault)
	findings, err := XXE{}.Run(ctx, newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings at LevelDefault on non-XML page, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; default scan must not POST to plain HTML pages", got)
	}
}

func TestXXEAggressiveProbesPageURL(t *testing.T) {
	srv := httptest.NewServer(vulnXXEFileHandler())
	defer srv.Close()

	// HTML-looking page, no forms - LevelAggressive should still speculatively POST.
	p := page.Page{
		URL:     srv.URL + "/",
		Headers: http.Header{"Content-Type": []string{"text/html"}},
	}
	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := XXE{}.Run(ctx, newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding at LevelAggressive on speculative page POST, got %d", len(findings))
	}
}

func TestXXERespectsScope(t *testing.T) {
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
	p := page.Page{
		URL: srv.URL + "/",
		Forms: []page.Form{
			{Method: http.MethodPost, Action: srv.URL + "/api"},
		},
	}
	findings, err := XXE{}.Run(context.Background(), newTestClient(t), sc, p)
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

func TestXXEDedupeKeyStable(t *testing.T) {
	srv := httptest.NewServer(vulnXXEFileHandler())
	defer srv.Close()

	run := func(pageURL string) string {
		p := page.Page{
			URL: pageURL,
			Forms: []page.Form{
				{Method: http.MethodPost, Action: srv.URL + "/api"},
			},
		}
		fs, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		return fs[0].DedupeKey
	}
	a := run(srv.URL + "/page-one")
	b := run(srv.URL + "/page-one")
	if a == "" {
		t.Fatal("DedupeKey empty")
	}
	if a != b {
		t.Errorf("same-endpoint keys drifted: %q vs %q", a, b)
	}
}

func TestXXEDedupeAcrossFormsToSameEndpoint(t *testing.T) {
	srv := httptest.NewServer(vulnXXEFileHandler())
	defer srv.Close()

	// Two forms on the same page that POST to the same action - the
	// check should only report one finding, not one per form.
	p := page.Page{
		URL: srv.URL + "/",
		Forms: []page.Form{
			{Method: http.MethodPost, Action: srv.URL + "/api"},
			{Method: http.MethodPost, Action: srv.URL + "/api"},
		},
	}
	findings, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(findings))
	}
}

func TestXXEProbesSpecOpsPostEndpoints(t *testing.T) {
	srv := httptest.NewServer(vulnXXEFileHandler())
	defer srv.Close()

	p := page.Page{
		URL: srv.URL + "/",
		SpecOps: []page.SpecOp{
			{Method: http.MethodPost, URL: srv.URL + "/api/spec"},
		},
	}
	findings, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from SpecOp candidate, got %d", len(findings))
	}
}

func TestXXESkipsGetFormsAndSpecOps(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := page.Page{
		URL: srv.URL + "/",
		Forms: []page.Form{
			{Method: http.MethodGet, Action: srv.URL + "/search"},
		},
		SpecOps: []page.SpecOp{
			{Method: http.MethodGet, URL: srv.URL + "/api/list"},
		},
	}
	findings, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (GET endpoints not XXE candidates), got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; GET endpoints should not be POSTed at", got)
	}
}

func TestXXESendsXMLContentType(t *testing.T) {
	var observedCT atomic.Value
	observedCT.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && observedCT.Load().(string) == "" {
			observedCT.Store(r.Header.Get("Content-Type"))
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := page.Page{
		URL: srv.URL + "/",
		Forms: []page.Form{
			{Method: http.MethodPost, Action: srv.URL + "/api"},
		},
	}
	_, err := XXE{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	ct, _ := observedCT.Load().(string)
	if !strings.Contains(ct, "xml") {
		t.Errorf("Content-Type sent = %q, want one containing xml", ct)
	}
}

func TestMatchXXEErrors(t *testing.T) {
	body := []byte("Error: org.xml.sax.SAXParseException at line 42")
	hits := matchXXEErrors(body)
	if len(hits) == 0 {
		t.Fatal("expected at least one hit on a known error pattern")
	}
	found := false
	for _, h := range hits {
		if strings.Contains(h, "saxparseexception") {
			found = true
		}
	}
	if !found {
		t.Errorf("hits = %+v, want one mentioning saxparseexception", hits)
	}
}

func TestMatchXXEErrorsEmpty(t *testing.T) {
	if got := matchXXEErrors(nil); got != nil {
		t.Errorf("empty body should yield nil hits, got %+v", got)
	}
	if got := matchXXEErrors([]byte("totally benign HTML")); got != nil {
		t.Errorf("clean body should yield nil hits, got %+v", got)
	}
}

func TestExtractSystemTarget(t *testing.T) {
	doc := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
	if got := extractSystemTarget(doc); got != "file:///etc/passwd" {
		t.Errorf("extractSystemTarget = %q, want file:///etc/passwd", got)
	}
	if got := extractSystemTarget("<no system here/>"); got != "external entity" {
		t.Errorf("extractSystemTarget fallback = %q, want \"external entity\"", got)
	}
}
