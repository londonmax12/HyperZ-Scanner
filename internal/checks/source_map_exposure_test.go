package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// validSourceMap is a minimal Source Map v3 document that satisfies
// looksLikeSourceMap. Real maps embed source bodies via sourcesContent;
// the check only inspects the leading shape so the smallest legal form
// is fine.
const validSourceMap = `{"version":3,"file":"app.js","sources":["webpack:///./src/app.js"],"names":["foo"],"mappings":"AAAA"}`

func sourceMapPage(rawurl, ct string, body []byte, hdrs map[string]string) page.Page {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	for k, v := range hdrs {
		h.Set(k, v)
	}
	return page.Page{
		URL:     rawurl,
		Status:  200,
		Headers: h,
		Body:    body,
		Fetched: true,
	}
}

// mapServer returns an httptest server that serves bodyByPath verbatim
// at the listed paths and 404 for anything else. The atomic counter
// records every request so tests can assert probe behavior (e.g. no
// extra fetch when the host JS has no marker).
type mapServer struct {
	srv     *httptest.Server
	hits    int64
	bodies  map[string][]byte
	ctMap   map[string]string
	hostJS  []byte
	hostCT  string
	jsPath  string
}

func newMapServer(t *testing.T, jsPath string, hostJS []byte, hostCT string, bodies map[string][]byte, ctMap map[string]string) *mapServer {
	t.Helper()
	ms := &mapServer{
		bodies: bodies,
		ctMap:  ctMap,
		hostJS: hostJS,
		hostCT: hostCT,
		jsPath: jsPath,
	}
	ms.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&ms.hits, 1)
		if r.URL.Path == jsPath {
			if hostCT != "" {
				w.Header().Set("Content-Type", hostCT)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(hostJS)
			return
		}
		body, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if ct, ok := ctMap[r.URL.Path]; ok && ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(ms.srv.Close)
	return ms
}

func runSourceMap(t *testing.T, p page.Page) []Finding {
	t.Helper()
	findings, err := SourceMapExposure{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

func runSourceMapWithClient(t *testing.T, p page.Page, sc *scope.Scope) []Finding {
	t.Helper()
	findings, err := SourceMapExposure{}.Run(context.Background(), newTestClient(t), sc, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

func TestSourceMapExposureName(t *testing.T) {
	if got := (SourceMapExposure{}).Name(); got != "source-map-exposure" {
		t.Fatalf("Name = %q, want source-map-exposure", got)
	}
}

func TestSourceMapExposureLevel(t *testing.T) {
	if got := (SourceMapExposure{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestSourceMapExposureSkipsNonJSContent(t *testing.T) {
	// HTML page with a sourceMappingURL-looking string inside the body
	// should not fire - the check only cares about JS / CSS responses.
	body := []byte(`<html><body><pre>//# sourceMappingURL=secret.map</pre></body></html>`)
	if got := runSourceMap(t, sourceMapPage("https://example.com/", "text/html", body, nil)); len(got) != 0 {
		t.Fatalf("HTML response must be skipped, got %d findings", len(got))
	}
}

func TestSourceMapExposureSkipsJSWithoutMarker(t *testing.T) {
	body := []byte(`var x = 1; console.log(x);`)
	p := sourceMapPage("https://example.com/app.js", "application/javascript", body, nil)
	if got := runSourceMap(t, p); len(got) != 0 {
		t.Fatalf("JS without sourceMappingURL must not fire, got %d", len(got))
	}
}

func TestSourceMapExposureDetectsCommentAndConfirmsProbe(t *testing.T) {
	hostJS := []byte("var x=1;\n//# sourceMappingURL=app.js.map\n")
	ms := newMapServer(t, "/app.js", hostJS, "application/javascript",
		map[string][]byte{"/app.js.map": []byte(validSourceMap)},
		map[string]string{"/app.js.map": "application/json"},
	)

	findings := runSourceMap(t, sourceMapPage(ms.srv.URL+"/app.js", "application/javascript", hostJS, nil))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
	if !strings.Contains(f.Title, "app.js.map") {
		t.Errorf("Title should name the map: %q", f.Title)
	}
	if !strings.Contains(f.URL, "/app.js.map") {
		t.Errorf("URL should point at the map: %q", f.URL)
	}
	if f.CWE != "CWE-540" {
		t.Errorf("CWE = %q, want CWE-540", f.CWE)
	}
	if f.OWASP == "" || f.Remediation == "" || f.DedupeKey == "" {
		t.Errorf("OWASP/Remediation/DedupeKey must be populated: %+v", f)
	}
}

func TestSourceMapExposureLegacyAtSyntaxFires(t *testing.T) {
	hostJS := []byte("var x=1;\n//@ sourceMappingURL=app.js.map\n")
	ms := newMapServer(t, "/app.js", hostJS, "application/javascript",
		map[string][]byte{"/app.js.map": []byte(validSourceMap)}, nil)

	if got := runSourceMap(t, sourceMapPage(ms.srv.URL+"/app.js", "application/javascript", hostJS, nil)); len(got) != 1 {
		t.Fatalf("legacy //@ form must fire, got %d", len(got))
	}
}

func TestSourceMapExposureCSSDetected(t *testing.T) {
	hostCSS := []byte("body { color: red; }\n/*# sourceMappingURL=style.css.map */\n")
	ms := newMapServer(t, "/style.css", hostCSS, "text/css",
		map[string][]byte{"/style.css.map": []byte(validSourceMap)}, nil)

	findings := runSourceMap(t, sourceMapPage(ms.srv.URL+"/style.css", "text/css", hostCSS, nil))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding for CSS, got %d", len(findings))
	}
	if !strings.Contains(findings[0].URL, "style.css.map") {
		t.Errorf("URL should point at css map: %q", findings[0].URL)
	}
}

func TestSourceMapExposureHeaderDetected(t *testing.T) {
	// No comment in the body, but the SourceMap response header alone
	// must trigger detection (and confirmation).
	hostJS := []byte(`var x=1;`)
	ms := newMapServer(t, "/app.js", hostJS, "application/javascript",
		map[string][]byte{"/app.js.map": []byte(validSourceMap)}, nil)

	p := sourceMapPage(ms.srv.URL+"/app.js", "application/javascript", hostJS,
		map[string]string{"SourceMap": "app.js.map"})

	if got := runSourceMap(t, p); len(got) != 1 {
		t.Fatalf("SourceMap header should trigger detection, got %d", len(got))
	}
}

func TestSourceMapExposureXSourceMapHeaderDetected(t *testing.T) {
	hostJS := []byte(`var x=1;`)
	ms := newMapServer(t, "/app.js", hostJS, "application/javascript",
		map[string][]byte{"/app.js.map": []byte(validSourceMap)}, nil)

	p := sourceMapPage(ms.srv.URL+"/app.js", "application/javascript", hostJS,
		map[string]string{"X-SourceMap": "app.js.map"})

	if got := runSourceMap(t, p); len(got) != 1 {
		t.Fatalf("X-SourceMap header should trigger detection, got %d", len(got))
	}
}

func TestSourceMapExposureSkipsWhenProbeReturns404(t *testing.T) {
	hostJS := []byte("var x=1;\n//# sourceMappingURL=app.js.map\n")
	// No bodies registered, so /app.js.map yields 404.
	ms := newMapServer(t, "/app.js", hostJS, "application/javascript", nil, nil)

	if got := runSourceMap(t, sourceMapPage(ms.srv.URL+"/app.js", "application/javascript", hostJS, nil)); len(got) != 0 {
		t.Fatalf("404 on map URL must suppress finding, got %d", len(got))
	}
}

func TestSourceMapExposureSkipsWhenProbeReturnsNonMapJSON(t *testing.T) {
	hostJS := []byte("var x=1;\n//# sourceMappingURL=app.js.map\n")
	ms := newMapServer(t, "/app.js", hostJS, "application/javascript",
		map[string][]byte{"/app.js.map": []byte(`{"hello":"world"}`)}, nil)

	if got := runSourceMap(t, sourceMapPage(ms.srv.URL+"/app.js", "application/javascript", hostJS, nil)); len(got) != 0 {
		t.Fatalf("non-map JSON body must suppress finding, got %d", len(got))
	}
}

func TestSourceMapExposureInlineDataURIFiresWithoutProbe(t *testing.T) {
	hostJS := []byte("var x=1;\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==\n")
	// No server: an inline map should fire without any probe at all,
	// so we can pass a page whose URL is not reachable.
	p := sourceMapPage("https://example.com/app.js", "application/javascript", hostJS, nil)

	findings := runSourceMap(t, p)
	if len(findings) != 1 {
		t.Fatalf("inline data URI must fire, got %d", len(findings))
	}
	if !strings.Contains(strings.ToLower(findings[0].Title), "inline") {
		t.Errorf("Title should mention inline: %q", findings[0].Title)
	}
	// Inline finding's URL is the bundle itself, not a data URI.
	if findings[0].URL != "https://example.com/app.js" {
		t.Errorf("URL should point at host bundle, got %q", findings[0].URL)
	}
}

func TestSourceMapExposureContentTypeWithCharsetStillDetected(t *testing.T) {
	hostJS := []byte("var x=1;\n//# sourceMappingURL=app.js.map\n")
	ms := newMapServer(t, "/app.js", hostJS, "application/javascript; charset=utf-8",
		map[string][]byte{"/app.js.map": []byte(validSourceMap)}, nil)

	p := sourceMapPage(ms.srv.URL+"/app.js", "application/javascript; charset=utf-8", hostJS, nil)
	if got := runSourceMap(t, p); len(got) != 1 {
		t.Fatalf("charset parameter on Content-Type must not block detection, got %d", len(got))
	}
}

func TestSourceMapExposureRelativeURLResolvedAgainstHost(t *testing.T) {
	hostJS := []byte("var x=1;\n//# sourceMappingURL=../maps/app.js.map\n")
	ms := newMapServer(t, "/static/app.js", hostJS, "application/javascript",
		map[string][]byte{"/maps/app.js.map": []byte(validSourceMap)}, nil)

	findings := runSourceMap(t, sourceMapPage(ms.srv.URL+"/static/app.js", "application/javascript", hostJS, nil))
	if len(findings) != 1 {
		t.Fatalf("relative ../ should resolve correctly, got %d findings", len(findings))
	}
	if !strings.HasSuffix(findings[0].URL, "/maps/app.js.map") {
		t.Errorf("resolved URL should be /maps/app.js.map, got %q", findings[0].URL)
	}
}

func TestSourceMapExposureRespectsScopeOnProbe(t *testing.T) {
	// Map URL points to a different host; scope blocks it -> no probe,
	// no finding. Without the scope guard the check would issue an
	// out-of-scope request.
	hostJS := []byte("var x=1;\n//# sourceMappingURL=https://other.example/app.js.map\n")
	p := sourceMapPage("https://allowed.example/app.js", "application/javascript", hostJS, nil)

	sc, err := scope.New(scope.Config{Hosts: []string{"allowed.example"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	if got := runSourceMapWithClient(t, p, sc); len(got) != 0 {
		t.Fatalf("out-of-scope map URL must not produce a finding, got %d", len(got))
	}
}

func TestSourceMapExposureFollowsRedirectToMap(t *testing.T) {
	// Production .map files commonly sit behind a redirect: an asset
	// path on the application host that 302s to a CDN / bucket URL.
	// A no-follow probe would silently miss the exposure even though
	// a real browser fetches the redirected target. Confirm the
	// probe follows.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("var x=1;\n//# sourceMappingURL=app.js.map\n"))
		case "/app.js.map":
			http.Redirect(w, r, "/cdn/real.map", http.StatusFound)
		case "/cdn/real.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(validSourceMap))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	hostJS := []byte("var x=1;\n//# sourceMappingURL=app.js.map\n")
	findings := runSourceMap(t, sourceMapPage(srv.URL+"/app.js", "application/javascript", hostJS, nil))
	if len(findings) != 1 {
		t.Fatalf("redirected map should still be detected, got %d findings: %+v", len(findings), findings)
	}
}

func TestSourceMapExposureRedirectOffScopeDropped(t *testing.T) {
	// The pre-flight scope check guards the resolved URL we hand to the
	// probe; once we follow redirects, the chain can land off-scope.
	// Re-check the final URL and drop the finding instead of reporting
	// against an out-of-scope host.
	//
	// Both httptest servers share the localhost hostname, so we scope
	// by port: the in-scope server's exact port is the only port the
	// scan is allowed to reach, putting the redirect target outside.
	offScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validSourceMap))
	}))
	t.Cleanup(offScope.Close)

	inScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("var x=1;\n//# sourceMappingURL=app.js.map\n"))
		case "/app.js.map":
			http.Redirect(w, r, offScope.URL+"/real.map", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(inScope.Close)

	inURL, err := url.Parse(inScope.URL)
	if err != nil {
		t.Fatalf("parse inScope.URL: %v", err)
	}
	sc, err := scope.New(scope.Config{
		Hosts: []string{inURL.Hostname()},
		Ports: inURL.Port() + "-" + inURL.Port(),
	})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}

	hostJS := []byte("var x=1;\n//# sourceMappingURL=app.js.map\n")
	p := sourceMapPage(inScope.URL+"/app.js", "application/javascript", hostJS, nil)
	if got := runSourceMapWithClient(t, p, sc); len(got) != 0 {
		t.Fatalf("redirect off-scope must drop finding, got %d", len(got))
	}
}

func TestSourceMapExposureDedupeAcrossPagesOfSameHost(t *testing.T) {
	hostJS := []byte("var x=1;\n//# sourceMappingURL=app.js.map\n")
	ms := newMapServer(t, "/app.js", hostJS, "application/javascript",
		map[string][]byte{"/app.js.map": []byte(validSourceMap)}, nil)

	a := runSourceMap(t, sourceMapPage(ms.srv.URL+"/app.js", "application/javascript", hostJS, nil))
	b := runSourceMap(t, sourceMapPage(ms.srv.URL+"/app.js", "application/javascript", hostJS, nil))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("want 1 finding per page, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeKey != b[0].DedupeKey {
		t.Errorf("DedupeKey should match across same-map repeats: %q vs %q", a[0].DedupeKey, b[0].DedupeKey)
	}
}

func TestSourceMapExposureCommentBeyondTailIgnored(t *testing.T) {
	// Bundlers always emit the marker on the last line. A marker buried
	// deep in the middle of a huge file (legacy stripped output left it
	// behind, or it appears inside a string literal) must NOT trigger:
	// the regex scans only the trailing window.
	prefix := strings.Repeat("var x=1;\n", 600) // ~5400 bytes - exceeds 4 KiB tail
	hostJS := []byte("//# sourceMappingURL=app.js.map\n" + prefix + "var y=2;")

	p := sourceMapPage("https://example.com/app.js", "application/javascript", hostJS, nil)
	if got := runSourceMap(t, p); len(got) != 0 {
		t.Fatalf("marker outside the trailing window must not fire, got %d", len(got))
	}
}

func TestLooksLikeSourceMap(t *testing.T) {
	cases := map[string]bool{
		validSourceMap:                            true,
		`{"version":3,"mappings":"AAAA"}`:         true,
		`{"version":3,"sources":["a.js"]}`:        true,
		`{"hello":"world"}`:                       false,
		`{"version":3}`:                           false, // no sources/mappings -> reject
		`<html></html>`:                           false,
		``:                                        false,
	}
	for body, want := range cases {
		if got := looksLikeSourceMap([]byte(body)); got != want {
			t.Errorf("looksLikeSourceMap(%q) = %v, want %v", body, got, want)
		}
	}
}

func TestSourceMappableKind(t *testing.T) {
	cases := map[string]struct {
		kind string
		ok   bool
	}{
		"application/javascript":             {"js", true},
		"text/javascript":                    {"js", true},
		"application/javascript; charset=utf-8": {"js", true},
		"text/css":                           {"css", true},
		"text/css; charset=utf-8":            {"css", true},
		"text/html":                          {"", false},
		"application/json":                   {"", false},
		"":                                   {"", false},
		"not a media type at all":            {"", false},
	}
	for ct, want := range cases {
		gotKind, gotOK := sourceMappableKind(ct)
		if gotKind != want.kind || gotOK != want.ok {
			t.Errorf("sourceMappableKind(%q) = (%q, %v), want (%q, %v)", ct, gotKind, gotOK, want.kind, want.ok)
		}
	}
}
