package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findSSE(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "sse-audit" {
			return c
		}
	}
	t.Fatal("sse-audit Lua check not found")
	return nil
}

// sseHandler returns a handler that serves text/event-stream on
// /stream with the given CORS headers, and any other path returns an
// HTML page whose body links to /stream via EventSource. acaoMode
// selects how the server populates ACAO:
//   - "wildcard": "*"
//   - "echo": echo the request's Origin
//   - "null": literal "null"
//   - "off": no ACAO header
func sseHandler(acaoMode string, withCreds bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			switch acaoMode {
			case "wildcard":
				w.Header().Set("Access-Control-Allow-Origin", "*")
			case "echo":
				if o := r.Header.Get("Origin"); o != "" {
					w.Header().Set("Access-Control-Allow-Origin", o)
				}
			case "null":
				w.Header().Set("Access-Control-Allow-Origin", "null")
			}
			if withCreds {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("event: hello\ndata: world\n\n"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script>new EventSource("/stream")</script></body></html>`))
	})
}

// TestLuaSSEAuditParity mounts an HTML page that references an SSE
// endpoint with various CORS postures and asserts the Go check + Lua
// port emit identical findings on each one.
func TestLuaSSEAuditParity(t *testing.T) {
	cases := []struct {
		name      string
		acaoMode  string
		withCreds bool
	}{
		{"wildcard_no_creds", "wildcard", false},
		{"wildcard_with_creds", "wildcard", true},
		{"reflect_origin_no_creds", "echo", false},
		{"reflect_origin_with_creds", "echo", true},
		{"null_origin", "null", false},
		{"no_cors_header", "off", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(sseHandler(tc.acaoMode, tc.withCreds))
			defer srv.Close()

			pageURL := srv.URL + "/"
			// Pre-fetch the page so the check sees the EventSource literal.
			p := page.FromURL(pageURL)
			resp, err := http.Get(pageURL)
			if err != nil {
				t.Fatalf("prefetch: %v", err)
			}
			defer resp.Body.Close()
			buf := make([]byte, 1<<16)
			n, _ := resp.Body.Read(buf)
			p.Body = buf[:n]
			p.Headers = resp.Header
			p.Status = resp.StatusCode
			p.Fetched = true

			client := newTestClient(t)
			goFs, err := (checks.SSEAudit{}).Run(context.Background(), client, nil, p)
			if err != nil {
				t.Fatalf("go: %v", err)
			}
			luaC := findSSE(t)
			luaFs, err := luaC.Run(context.Background(), client, nil, p)
			if err != nil {
				t.Fatalf("lua: %v", err)
			}
			if len(goFs) != len(luaFs) {
				t.Fatalf("count: go=%d lua=%d\ngo=%+v\nlua=%+v", len(goFs), len(luaFs), goFs, luaFs)
			}
			for i, gf := range goFs {
				lf := luaFs[i]
				if gf.Severity != lf.Severity {
					t.Errorf("[%d] severity drift: go=%q lua=%q", i, gf.Severity, lf.Severity)
				}
				if gf.Title != lf.Title {
					t.Errorf("[%d] title drift:\n go=%q\nlua=%q", i, gf.Title, lf.Title)
				}
				if gf.CWE != lf.CWE {
					t.Errorf("[%d] CWE drift: go=%q lua=%q", i, gf.CWE, lf.CWE)
				}
				if gf.OWASP != lf.OWASP {
					t.Errorf("[%d] OWASP drift: go=%q lua=%q", i, gf.OWASP, lf.OWASP)
				}
				if gf.DedupeKey != lf.DedupeKey {
					t.Errorf("[%d] dedupe drift:\n go=%q\nlua=%q", i, gf.DedupeKey, lf.DedupeKey)
				}
				if !strings.HasSuffix(lf.URL, "/stream") {
					t.Errorf("[%d] lua URL = %q, want suffix /stream", i, lf.URL)
				}
			}
		})
	}
}

// TestLuaSSEAuditNoEndpoint asserts no findings when the page neither
// is an SSE stream nor references one.
func TestLuaSSEAuditNoEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>nothing here</body></html>"))
	}))
	defer srv.Close()

	pageURL := srv.URL + "/"
	p := page.FromURL(pageURL)
	resp, _ := http.Get(pageURL)
	defer resp.Body.Close()
	buf := make([]byte, 1<<16)
	n, _ := resp.Body.Read(buf)
	p.Body = buf[:n]
	p.Headers = resp.Header
	p.Status = resp.StatusCode
	p.Fetched = true

	client := newTestClient(t)
	goFs, err := (checks.SSEAudit{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %+v", goFs)
	}
	luaC := findSSE(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %+v", luaFs)
	}
}
