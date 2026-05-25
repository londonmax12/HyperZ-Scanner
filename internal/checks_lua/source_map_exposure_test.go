package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findSourceMap(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "source-map-exposure" {
			return c
		}
	}
	t.Fatal("source-map-exposure Lua check not found")
	return nil
}

const validSourceMapDoc = `{"version":3,"file":"app.js","sources":["webpack:///./src/app.js"],"names":["foo"],"mappings":"AAAA"}`

// mapSrv stands up a tiny http server: jsPath returns hostJS, and any
// other path is served from bodies/ctMap. Mirrors the helper in the
// Go check's tests so the parity scenarios stay equivalent.
type mapSrv struct {
	srv    *httptest.Server
	hits   int64
	url    string
	hostJS []byte
	hostCT string
	jsPath string
}

func newMapSrv(t *testing.T, jsPath string, hostJS []byte, hostCT string, bodies map[string][]byte, ctMap map[string]string) *mapSrv {
	t.Helper()
	ms := &mapSrv{hostJS: hostJS, hostCT: hostCT, jsPath: jsPath}
	ms.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&ms.hits, 1)
		if r.URL.Path == jsPath {
			if hostCT != "" {
				w.Header().Set("Content-Type", hostCT)
			}
			w.WriteHeader(http.StatusOK)
			w.Write(hostJS)
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
		w.Write(body)
	}))
	t.Cleanup(ms.srv.Close)
	ms.url = ms.srv.URL
	return ms
}

// TestLuaSourceMapParityExternalHit confirms the Lua port produces
// the same one-finding result the Go check does when the host JS
// advertises an external map that responds 200 with valid contents.
func TestLuaSourceMapParityExternalHit(t *testing.T) {
	hostJS := []byte("console.log('hi')\n//# sourceMappingURL=app.js.map\n")
	bodies := map[string][]byte{"/app.js.map": []byte(validSourceMapDoc)}
	cts := map[string]string{"/app.js.map": "application/json"}
	ms := newMapSrv(t, "/app.js", hostJS, "application/javascript", bodies, cts)

	p := page.Page{URL: ms.url + "/app.js", Status: 200,
		Headers: http.Header{"Content-Type": []string{"application/javascript"}},
		Body:    hostJS, Fetched: true}

	goFs, err := (checks.SourceMapExposure{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaFs, err := findSourceMap(t).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != len(luaFs) {
		t.Fatalf("count: go=%d lua=%d", len(goFs), len(luaFs))
	}
	if len(goFs) != 1 {
		t.Fatalf("want 1 finding, got %d (go) / %d (lua)", len(goFs), len(luaFs))
	}
	if goFs[0].DedupeKey != luaFs[0].DedupeKey {
		t.Errorf("dedupe drift: go=%q lua=%q", goFs[0].DedupeKey, luaFs[0].DedupeKey)
	}
	if goFs[0].Severity != luaFs[0].Severity {
		t.Errorf("severity drift: go=%q lua=%q", goFs[0].Severity, luaFs[0].Severity)
	}
}

func TestLuaSourceMapParityInline(t *testing.T) {
	body := []byte("console.log('hi')\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==\n")
	p := page.Page{URL: "https://example.com/app.js", Status: 200,
		Headers: http.Header{"Content-Type": []string{"application/javascript"}},
		Body:    body, Fetched: true}

	goFs, err := (checks.SourceMapExposure{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaFs, err := findSourceMap(t).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != len(luaFs) {
		t.Fatalf("count: go=%d lua=%d", len(goFs), len(luaFs))
	}
	if len(goFs) != 1 {
		t.Fatalf("want 1 inline finding, got %d (go)", len(goFs))
	}
	if !strings.Contains(luaFs[0].Title, "inline") {
		t.Errorf("Lua title should mention inline: %q", luaFs[0].Title)
	}
	if goFs[0].DedupeKey != luaFs[0].DedupeKey {
		t.Errorf("dedupe: go=%q lua=%q", goFs[0].DedupeKey, luaFs[0].DedupeKey)
	}
}

func TestLuaSourceMapParityNoMarkerNoFinding(t *testing.T) {
	body := []byte("console.log('no source map here')\n")
	p := page.Page{URL: "https://example.com/app.js", Status: 200,
		Headers: http.Header{"Content-Type": []string{"application/javascript"}},
		Body:    body, Fetched: true}
	fs, err := findSourceMap(t).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("want 0 findings, got %d", len(fs))
	}
}

func TestLuaSourceMapParityNonJSContent(t *testing.T) {
	body := []byte(`<html><body><pre>//# sourceMappingURL=secret.map</pre></body></html>`)
	p := page.Page{URL: "https://example.com/page", Status: 200,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    body, Fetched: true}
	fs, err := findSourceMap(t).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("want 0 findings on HTML page, got %d", len(fs))
	}
}

func TestLuaSourceMapParityMissingMap(t *testing.T) {
	// JS with marker but the map URL 404s -> non-finding (stale ref
	// is not exposure).
	hostJS := []byte("console.log('hi')\n//# sourceMappingURL=gone.map\n")
	ms := newMapSrv(t, "/app.js", hostJS, "application/javascript", nil, nil)
	p := page.Page{URL: ms.url + "/app.js", Status: 200,
		Headers: http.Header{"Content-Type": []string{"application/javascript"}},
		Body:    hostJS, Fetched: true}
	fs, err := findSourceMap(t).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("404 map should produce no finding, got %d", len(fs))
	}
}
