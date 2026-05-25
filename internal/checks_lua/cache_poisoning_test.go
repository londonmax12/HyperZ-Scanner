package checks_lua

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func findCachePoisoning(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "cache-poisoning" {
			return c
		}
	}
	t.Fatal("cache-poisoning Lua check not found")
	return nil
}

// vulnUnkeyedHostHandlerLua echoes X-Forwarded-Host into a canonical
// link tag and advertises itself as cacheable but does NOT list the
// header in Vary - the textbook unkeyed-header poisoning primitive.
// Mirrors the Go check's test fixture.
func vulnUnkeyedHostHandlerLua() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Age", "0")
		w.Header().Set("X-Cache", "MISS")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><head><link rel=\"canonical\" href=\"https://%s/\"></head><body>ok</body></html>", host)
	})
}

func TestLuaCachePoisoningParity(t *testing.T) {
	luaC := findCachePoisoning(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("unkeyed_host_detected", func(t *testing.T) {
		srv := httptest.NewServer(vulnUnkeyedHostHandlerLua())
		defer srv.Close()
		target := srv.URL

		goFs, err := (checks.CachePoisoning{}).Run(context.Background(), client, sc, page.FromURL(target))
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
		// Findings are emitted in probe order on both sides, so a per-
		// index comparison is the right way to lock in dedupe + severity.
		for i := range goFs {
			if goFs[i].DedupeKey != luaFs[i].DedupeKey {
				t.Errorf("dedupe drift [%d]: go=%q lua=%q", i, goFs[i].DedupeKey, luaFs[i].DedupeKey)
			}
			if goFs[i].Severity != luaFs[i].Severity {
				t.Errorf("severity drift [%d]: go=%q lua=%q", i, goFs[i].Severity, luaFs[i].Severity)
			}
		}
	})

	t.Run("safe_host_no_finding", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>nothing dynamic</body></html>"))
		}))
		defer srv.Close()

		goFs, err := (checks.CachePoisoning{}).Run(context.Background(), client, sc, page.FromURL(srv.URL))
		if err != nil {
			t.Fatalf("go: %v", err)
		}
		luaFs, err := luaC.Run(context.Background(), client, sc, page.FromURL(srv.URL))
		if err != nil {
			t.Fatalf("lua: %v", err)
		}
		if len(goFs) != 0 || len(luaFs) != 0 {
			t.Fatalf("expected no findings: go=%d lua=%d", len(goFs), len(luaFs))
		}
	})
}
