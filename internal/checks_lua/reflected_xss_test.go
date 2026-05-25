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

func findReflectedXSS(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "reflected-xss" {
			return c
		}
	}
	t.Fatal("reflected-xss Lua check not found")
	return nil
}

// xssTextHandlerLua echoes ?q= verbatim into HTML text - the canonical
// reflected-XSS-in-text bug. Mirrors the Go check's test fixture so
// both implementations see the same wire behavior.
func xssTextHandlerLua() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body><p>You searched for: " + q + "</p></body></html>"))
	})
}

func TestLuaReflectedXSSParity(t *testing.T) {
	luaC := findReflectedXSS(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("text_reflection_detected", func(t *testing.T) {
		srv := httptest.NewServer(xssTextHandlerLua())
		defer srv.Close()
		target := srv.URL + "/search?q=hello"

		goFs, err := (checks.ReflectedXSS{}).Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("go: %v", err)
		}
		luaFs, err := luaC.Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("lua: %v", err)
		}
		if len(goFs) != len(luaFs) {
			t.Fatalf("count: go=%d lua=%d", len(goFs), len(luaFs))
		}
		for i := range goFs {
			if goFs[i].DedupeKey != luaFs[i].DedupeKey {
				t.Errorf("dedupe drift: go=%q lua=%q", goFs[i].DedupeKey, luaFs[i].DedupeKey)
			}
			if goFs[i].Severity != luaFs[i].Severity {
				t.Errorf("severity drift: go=%q lua=%q", goFs[i].Severity, luaFs[i].Severity)
			}
		}
	})

	t.Run("safe_handler_no_finding", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<p>safe</p>"))
		}))
		defer srv.Close()
		target := srv.URL + "/?q=hello"

		goFs, err := (checks.ReflectedXSS{}).Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("go: %v", err)
		}
		luaFs, err := luaC.Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("lua: %v", err)
		}
		if len(goFs) != 0 || len(luaFs) != 0 {
			t.Fatalf("expected no findings: go=%d lua=%d", len(goFs), len(luaFs))
		}
	})
}
