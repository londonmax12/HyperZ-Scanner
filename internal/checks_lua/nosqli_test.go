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

func findNoSQLi(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "nosqli" {
			return c
		}
	}
	t.Fatal("nosqli Lua check not found")
	return nil
}

// vulnMongoHandlerLua simulates an Express+Mongoose stack that parses
// bracket-notation query params into operator objects. `id=42`,
// `id[$eq]=42`, and `id[$in][0]=42` all collapse to the same equality.
func vulnMongoHandlerLua() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		q := r.URL.Query()
		target := q.Get("id")
		if target == "" {
			target = q.Get("id[$eq]")
		}
		if target == "" {
			target = q.Get("id[$in][0]")
		}
		if target == "42" {
			_, _ = w.Write([]byte("<html><body><p>User: alice (id=42)</p></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><p>No matching records.</p></body></html>"))
	})
}

func TestLuaNoSQLiParity(t *testing.T) {
	luaC := findNoSQLi(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("operator_injection_detected", func(t *testing.T) {
		srv := httptest.NewServer(vulnMongoHandlerLua())
		defer srv.Close()
		target := srv.URL + "/user?id=42"

		goFs, err := (checks.NoSQLi{}).Run(context.Background(), client, sc, page.FromURL(target))
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
			_, _ = w.Write([]byte("<p>fixed safe content</p>"))
		}))
		defer srv.Close()
		target := srv.URL + "/?id=42"

		goFs, err := (checks.NoSQLi{}).Run(context.Background(), client, sc, page.FromURL(target))
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
