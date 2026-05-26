package checks_lua

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findStoredXSS(t *testing.T) checks.TwoPhaseCheck {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "stored-xss" {
			tp, ok := c.(checks.TwoPhaseCheck)
			if !ok {
				t.Fatalf("stored-xss Lua check is not a TwoPhaseCheck: %T", c)
			}
			return tp
		}
	}
	t.Fatal("stored-xss Lua check not found")
	return nil
}

// storedXSSServerLua simulates an app that stores POSTed comments and
// renders them on GET /post. Mirrors the Go-side stored-xss test
// server so parity tests probe identical wire behaviour.
type storedXSSServerLua struct {
	mu       sync.Mutex
	comments []string
	hits     map[string]*atomic.Int64
}

func newStoredXSSServerLua() *storedXSSServerLua {
	return &storedXSSServerLua{hits: map[string]*atomic.Int64{}}
}

func (s *storedXSSServerLua) tick(path string) {
	s.mu.Lock()
	if s.hits[path] == nil {
		s.hits[path] = &atomic.Int64{}
	}
	c := s.hits[path]
	s.mu.Unlock()
	c.Add(1)
}

func (s *storedXSSServerLua) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		s.tick("/post")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		var b strings.Builder
		b.WriteString(`<html><body><h1>Post</h1>`)
		b.WriteString(`<form method="POST" action="/comments"><input name="body" type="text"><button>Submit</button></form>`)
		b.WriteString(`<ul>`)
		s.mu.Lock()
		for _, c := range s.comments {
			fmt.Fprintf(&b, `<li>%s</li>`, c)
		}
		s.mu.Unlock()
		b.WriteString(`</ul></body></html>`)
		_, _ = w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/comments", func(w http.ResponseWriter, r *http.Request) {
		s.tick("/comments")
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body := r.PostFormValue("body")
		s.mu.Lock()
		s.comments = append(s.comments, body)
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func pageWithFormLua(pageURL, actionURL string) page.Page {
	return page.Page{
		URL: pageURL,
		Forms: []page.Form{
			{
				Method: http.MethodPost,
				Action: actionURL,
				Inputs: []page.FormInput{
					{Name: "body", Type: "text"},
				},
			},
		},
		Fetched: true,
	}
}

func fetchDetectLua(t *testing.T, u string) page.Page {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("fetchDetect %s: %v", u, err)
	}
	defer resp.Body.Close()
	body := make([]byte, 0)
	buf := make([]byte, 8192)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return page.Page{
		URL:     u,
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
		Body:    body,
		Fetched: true,
	}
}

// TestLuaStoredXSSMetadata locks in the metadata fields the loader
// parses out of the .lua file: name, level, and (critically) the
// two-phase opt-in. A regression here would either drop the check
// from the catalog or force-promote a single-phase check to two-
// phase, fanning out phase-2 re-fetches across the whole crawl.
func TestLuaStoredXSSMetadata(t *testing.T) {
	luaC := findStoredXSS(t)
	if luaC.Name() != "stored-xss" {
		t.Errorf("Name = %q, want stored-xss", luaC.Name())
	}
	if luaC.Level() != checks.LevelDefault {
		t.Errorf("Level = %v, want default", luaC.Level())
	}
}

// TestLuaStoredXSSRunReturnsNothingParity asserts the single-phase
// fallback returns nil findings on both impls. Two-phase checks
// produce their verdict via Plant+Detect; Run is the older-scanner
// safety net and must not double-fire what the phase path already
// emits.
func TestLuaStoredXSSRunReturnsNothingParity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<svg onload=alert(1)>hpzc000000000000</svg>`))
	}))
	defer srv.Close()

	luaC := findStoredXSS(t)
	got, err := luaC.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("lua run: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("lua: Run returned %d findings; want 0", len(got))
	}
	goGot, err := (&checks.StoredXSS{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("go run: %v", err)
	}
	if len(goGot) != 0 {
		t.Errorf("go: Run returned %d findings; want 0", len(goGot))
	}
}

// TestLuaStoredXSSPlantThenDetectFiresHighFindingParity locks in the
// end-to-end happy path on both impls: Plant submits via the form,
// Detect sees the stored payload on /post, both fire one High
// finding with CWE-79 and Target=plant URL, URL=detect URL.
func TestLuaStoredXSSPlantThenDetectFiresHighFindingParity(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T) []checks.Finding
	}{
		{
			name: "go",
			run: func(t *testing.T) []checks.Finding {
				srv := httptest.NewServer(newStoredXSSServerLua().handler())
				t.Cleanup(srv.Close)
				c := &checks.StoredXSS{}
				if _, err := c.Plant(context.Background(), newTestClient(t), nil, pageWithFormLua(srv.URL+"/post", srv.URL+"/comments")); err != nil {
					t.Fatalf("Plant: %v", err)
				}
				got, err := c.Detect(context.Background(), newTestClient(t), nil, fetchDetectLua(t, srv.URL+"/post"))
				if err != nil {
					t.Fatalf("Detect: %v", err)
				}
				return got
			},
		},
		{
			name: "lua",
			run: func(t *testing.T) []checks.Finding {
				srv := httptest.NewServer(newStoredXSSServerLua().handler())
				t.Cleanup(srv.Close)
				c := findStoredXSS(t)
				if _, err := c.Plant(context.Background(), newTestClient(t), nil, pageWithFormLua(srv.URL+"/post", srv.URL+"/comments")); err != nil {
					t.Fatalf("Plant: %v", err)
				}
				got, err := c.Detect(context.Background(), newTestClient(t), nil, fetchDetectLua(t, srv.URL+"/post"))
				if err != nil {
					t.Fatalf("Detect: %v", err)
				}
				return got
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.run(t)
			if len(got) != 1 {
				t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
			}
			f := got[0]
			if f.Severity != checks.SeverityHigh {
				t.Errorf("Severity = %q, want high", f.Severity)
			}
			if f.CWE != "CWE-79" {
				t.Errorf("CWE = %q, want CWE-79", f.CWE)
			}
			if !strings.Contains(f.Title, `"body"`) {
				t.Errorf("Title should name the sink param body: %q", f.Title)
			}
			if !strings.Contains(f.Detail, "/post") {
				t.Errorf("Detail should reference the detect URL: %q", f.Detail)
			}
			if !strings.Contains(f.Detail, "/comments") {
				t.Errorf("Detail should reference the plant URL: %q", f.Detail)
			}
			if !strings.Contains(f.Target, "/comments") {
				t.Errorf("Target = %q, want plant URL (/comments)", f.Target)
			}
			if !strings.Contains(f.URL, "/post") {
				t.Errorf("URL = %q, want detect URL (/post)", f.URL)
			}
			if f.DedupeKey == "" {
				t.Error("DedupeKey must be set so duplicate detections collapse")
			}
		})
	}
}

// TestLuaStoredXSSDetectURLsHarvestsSameOriginLinksParity drives a
// full Plant on both impls against a server whose form-action
// returns a body laced with same-origin and cross-origin links;
// after the plant, DetectURLs must surface every same-origin
// navigable target and drop the cross-origin one. The Lua port
// routes harvest through the same Go-side parser so behaviour
// aligns byte-for-byte.
func TestLuaStoredXSSDetectURLsHarvestsSameOriginLinksParity(t *testing.T) {
	body := `<a href="/thanks">x</a><form action="/another"></form><a href="https://evil.example.com/x">y</a><meta http-equiv="refresh" content="0; url=/redirect">`
	mk := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(body))
		}))
	}

	goSrv := mk()
	defer goSrv.Close()
	goC := &checks.StoredXSS{}
	if _, err := goC.Plant(context.Background(), newTestClient(t), nil, pageWithFormLua(goSrv.URL+"/post", goSrv.URL+"/comments")); err != nil {
		t.Fatalf("go plant: %v", err)
	}
	goURLs := map[string]bool{}
	for _, u := range goC.DetectURLs() {
		goURLs[u] = true
	}

	luaSrv := mk()
	defer luaSrv.Close()
	luaC := findStoredXSS(t)
	if _, err := luaC.Plant(context.Background(), newTestClient(t), nil, pageWithFormLua(luaSrv.URL+"/post", luaSrv.URL+"/comments")); err != nil {
		t.Fatalf("lua plant: %v", err)
	}
	luaURLs := map[string]bool{}
	for _, u := range luaC.DetectURLs() {
		luaURLs[u] = true
	}

	for _, want := range []string{"/thanks", "/another", "/redirect"} {
		matchGo := false
		matchLua := false
		for u := range goURLs {
			if strings.HasSuffix(u, want) {
				matchGo = true
			}
		}
		for u := range luaURLs {
			if strings.HasSuffix(u, want) {
				matchLua = true
			}
		}
		if !matchGo {
			t.Errorf("go: missing harvested URL ending in %s; got %v", want, goURLs)
		}
		if !matchLua {
			t.Errorf("lua: missing harvested URL ending in %s; got %v", want, luaURLs)
		}
	}
	for u := range goURLs {
		if strings.Contains(u, "evil.example.com") {
			t.Errorf("go: cross-origin URL leaked: %s", u)
		}
	}
	for u := range luaURLs {
		if strings.Contains(u, "evil.example.com") {
			t.Errorf("lua: cross-origin URL leaked: %s", u)
		}
	}
}
