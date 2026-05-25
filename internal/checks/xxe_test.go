package checks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
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

// vulnXXEBase64Handler simulates a backend that resolves php://filter
// payloads, inlining the base64-encoded file contents. The encoded
// prefix of /etc/passwd ("cm9vdDp4OjA6MDo") is what the matcher fires
// on; we wrap it in a small XML response so the body looks plausible.
func vulnXXEBase64Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "php://filter") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("parsed: <foo>cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo=</foo>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestXXEDetectsPHPFilterBase64Disclosure(t *testing.T) {
	srv := httptest.NewServer(vulnXXEBase64Handler())
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
		t.Fatalf("expected 1 finding for base64-encoded disclosure, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if !strings.Contains(f.Title, "file disclosure") {
		t.Errorf("Title should mention file disclosure: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "php://filter") {
		t.Errorf("Detail should name the php://filter SYSTEM target: %q", f.Detail)
	}
}

func TestMatchXXEBase64Markers(t *testing.T) {
	// Continuous base64 of "root:x:0:0:root:..." - the first 12 chars
	// "cm9vdDp4OjA6" encode the stable prefix "root:x:0:".
	body := []byte("response wrapping... cm9vdDp4OjA6MDpyb290... more")
	hits := matchXXEBase64Markers(body)
	if len(hits) == 0 {
		t.Fatal("expected base64 marker hit on the canonical /etc/passwd prefix")
	}
	if hits[0] != "cm9vdDp4OjA6" {
		t.Errorf("hits[0] = %q, want base64 passwd prefix", hits[0])
	}
}

func TestMatchXXEBase64MarkersEmpty(t *testing.T) {
	if got := matchXXEBase64Markers(nil); got != nil {
		t.Errorf("empty body should yield nil hits, got %+v", got)
	}
	if got := matchXXEBase64Markers([]byte("benign content")); got != nil {
		t.Errorf("clean body should yield nil hits, got %+v", got)
	}
}

func TestExtractExfilData(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/<tok>?d=hostname.example", "hostname.example"},
		{"/<tok>?d=multi%20word", "multi word"},
		{"/<tok>", ""},
		{"/<tok>?other=x", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := extractExfilData(tc.path); got != tc.want {
			t.Errorf("extractExfilData(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestXXEOOBDTDExfilDetection exercises the full DTD-exfil chain:
// the synthetic target follows the DOCTYPE SYSTEM URL, fetches the
// DTD body the listener serves, executes the parameter-entity send
// step by GET-ing the exfil URL with a "d=" query, and the check's
// Drain emits a Critical finding with the captured payload.
func TestXXEOOBDTDExfilDetection(t *testing.T) {
	oobSrv := startOOB(t)
	srv := newOOBHostWrapper(oobSrv)

	// Synthetic target that walks the chain a real XXE parser would:
	// 1. Pull the DOCTYPE SYSTEM URL from the body, GET it (loads DTD).
	// 2. Pull the SYSTEM URL out of the served DTD, treating %file; as
	//    the literal probe filename so the test stays hermetic.
	// 3. GET the exfil URL with the probe filename in the d= query.
	dtdSysRe := regexp.MustCompile(`<!DOCTYPE foo SYSTEM "([^"]+)"`)
	exfilRe := regexp.MustCompile(`SYSTEM '([^']+)\?d=%file;'`)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m := dtdSysRe.FindStringSubmatch(string(body))
		if len(m) != 2 {
			w.WriteHeader(http.StatusOK)
			return
		}
		resp, err := http.Get(m[1])
		if err != nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		dtd, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		em := exfilRe.FindStringSubmatch(string(dtd))
		if len(em) == 2 {
			fileURL := "synthetic-hostname"
			resp2, err := http.Get(em[1] + "?d=" + fileURL)
			if err == nil {
				io.Copy(io.Discard, resp2.Body)
				resp2.Body.Close()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	ctx := WithOOB(context.Background(), srv)
	pg := page.Page{
		URL:     target.URL + "/upload.xml",
		Headers: http.Header{"Content-Type": []string{"application/xml"}},
	}
	if _, err := (XXE{}).Run(ctx, newTestClient(t), nil, pg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings := XXE{}.Drain(ctx)
	var exfilFinding Finding
	for _, f := range findings {
		if strings.Contains(f.Title, "OOB DTD exfiltration") {
			exfilFinding = f
			break
		}
	}
	if exfilFinding.Title == "" {
		t.Fatalf("expected OOB DTD exfiltration finding, got %+v", findings)
	}
	if exfilFinding.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", exfilFinding.Severity)
	}
	if exfilFinding.CWE != "CWE-611" {
		t.Errorf("CWE = %q, want CWE-611", exfilFinding.CWE)
	}
	if !strings.Contains(exfilFinding.Detail, "synthetic-hostname") {
		t.Errorf("detail should include the captured exfil payload: %q", exfilFinding.Detail)
	}
}

// TestXXEOOBDTDExfilLoaderOnlyFinding covers the "external DTD fetched
// but parameter entity callback didn't fire" branch - a parser that
// loads the DTD subset but blocks param-entity expansion is still
// worth reporting (High severity) because the basic OOB-system probe
// would have missed it entirely.
func TestXXEOOBDTDExfilLoaderOnlyFinding(t *testing.T) {
	oobSrv := startOOB(t)
	srv := newOOBHostWrapper(oobSrv)

	// Synthetic target fetches the DOCTYPE DTD but stops there - mimicking
	// a parser that loads external DTD subsets but blocks parameter
	// entity expansion. The basic SYSTEM-entity payload uses the
	// `<!ENTITY xxe SYSTEM "...">` shape, not DOCTYPE-SYSTEM, so the
	// target intentionally ignores that one to keep the OOB-system
	// canary clean.
	dtdSysRe := regexp.MustCompile(`<!DOCTYPE foo SYSTEM "([^"]+)"`)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if m := dtdSysRe.FindStringSubmatch(string(body)); len(m) == 2 {
			resp, err := http.Get(m[1])
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	ctx := WithOOB(context.Background(), srv)
	pg := page.Page{
		URL:     target.URL + "/upload.xml",
		Headers: http.Header{"Content-Type": []string{"application/xml"}},
	}
	if _, err := (XXE{}).Run(ctx, newTestClient(t), nil, pg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings := XXE{}.Drain(ctx)
	var loaderFinding Finding
	for _, f := range findings {
		if strings.Contains(f.Title, "external DTD fetched") {
			loaderFinding = f
			break
		}
	}
	if loaderFinding.Title == "" {
		t.Fatalf("expected external-DTD-fetched finding, got %+v", findings)
	}
	if loaderFinding.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high (loader-only)", loaderFinding.Severity)
	}
}

// TestXXEOOBDTDExfilReceiverNotEmittedAlone ensures the receiver
// registration never produces its own finding - the loader sibling
// emits the combined finding so the report doesn't duplicate the
// probe pair.
func TestXXEOOBDTDExfilReceiverNotEmittedAlone(t *testing.T) {
	oobSrv := startOOB(t)
	srv := newOOBHostWrapper(oobSrv)

	// Inert target: no callbacks anywhere. The check still mints both
	// loader + receiver registrations during Run.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	ctx := WithOOB(context.Background(), srv)
	pg := page.Page{
		URL:     target.URL + "/upload.xml",
		Headers: http.Header{"Content-Type": []string{"application/xml"}},
	}
	if _, err := (XXE{}).Run(ctx, newTestClient(t), nil, pg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// At least one receiver registration should exist - prove it doesn't
	// trip the Drain path.
	var sawReceiver bool
	for _, reg := range srv.Registrations("xxe") {
		if reg.Extra[xxeVariantKey] == xxeVariantDTDExfilRecv {
			sawReceiver = true
			break
		}
	}
	if !sawReceiver {
		t.Fatal("expected at least one exfil-receiver registration to be minted during Run")
	}

	got := (XXE{}).Drain(ctx)
	if len(got) != 0 {
		t.Errorf("Drain emitted findings without any callbacks: %+v", got)
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
