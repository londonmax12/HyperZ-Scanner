package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func findSSRF(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "ssrf" {
			return c
		}
	}
	t.Fatal("ssrf Lua check not found")
	return nil
}

// ssrfErrorReflectingHandler echoes an HTTP-library error signature
// whenever the request carries the canary URL the SSRF check plants.
// The signature ("getaddrinfo failed") is one of the patterns the
// checker recognizes, so a hit on this handler triggers a finding from
// both the Go and Lua implementations.
func ssrfErrorReflectingHandler() http.Handler {
	canary := checks.SSRFCanaryLua()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		body := ""
		if r.URL.Query().Get("url") == canary {
			body = "<html><body>Fetch error: getaddrinfo failed for host internal.example</body></html>"
		} else {
			body = "<html><body>hello</body></html>"
		}
		_, _ = w.Write([]byte(body))
	})
}

func TestLuaSSRFParity(t *testing.T) {
	t.Run("error_signature_detected", func(t *testing.T) {
		srv := httptest.NewServer(ssrfErrorReflectingHandler())
		defer srv.Close()
		target := srv.URL + "/fetch?url=https://example.org/"

		client := newTestClient(t)
		var sc *scope.Scope
		luaC := findSSRF(t)

		goFs, err := (checks.SSRF{}).Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("go: %v", err)
		}
		luaFs, err := luaC.Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("lua: %v", err)
		}
		if len(goFs) == 0 || len(luaFs) == 0 {
			t.Fatalf("expected findings from both; go=%d lua=%d", len(goFs), len(luaFs))
		}
		// The Go check probes the specific param list first; the Lua
		// port produces the same probe ordering via sweep_params, so
		// both implementations fire their first finding on the same
		// (loc, param) and yield identical dedupe keys.
		if goFs[0].Severity != luaFs[0].Severity {
			t.Errorf("severity drift: go=%q lua=%q", goFs[0].Severity, luaFs[0].Severity)
		}
		if goFs[0].Title != luaFs[0].Title {
			t.Errorf("title drift:\n go=%q\nlua=%q", goFs[0].Title, luaFs[0].Title)
		}
		if goFs[0].DedupeKey != luaFs[0].DedupeKey {
			t.Errorf("dedupe drift: go=%q lua=%q", goFs[0].DedupeKey, luaFs[0].DedupeKey)
		}
		if goFs[0].CWE != luaFs[0].CWE {
			t.Errorf("CWE drift: go=%q lua=%q", goFs[0].CWE, luaFs[0].CWE)
		}
	})

	t.Run("clean_response_no_findings", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<html><body>ok</body></html>"))
		}))
		defer srv.Close()
		target := srv.URL + "/fetch?url=https://example.org/"

		client := newTestClient(t)
		var sc *scope.Scope
		luaC := findSSRF(t)

		goFs, err := (checks.SSRF{}).Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("go: %v", err)
		}
		luaFs, err := luaC.Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("lua: %v", err)
		}
		if len(goFs) != 0 {
			t.Errorf("go: expected 0 findings, got %d", len(goFs))
		}
		if len(luaFs) != 0 {
			t.Errorf("lua: expected 0 findings, got %d", len(luaFs))
		}
	})
}
