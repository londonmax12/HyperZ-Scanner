package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func findSQLiBoolean(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "sqli-boolean" {
			return c
		}
	}
	t.Fatal("sqli-boolean Lua check not found")
	return nil
}

// vulnBooleanHandler echoes truthy responses unless the payload makes
// the WHERE clause false. Mirrors internal/checks/sqli_boolean_test.go's
// fixture so the Go and Lua checks see identical wire behavior.
func vulnBooleanHandlerLua() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		falsy := strings.Contains(id, "1=2") || strings.Contains(id, "'1'='2'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if falsy {
			_, _ = w.Write([]byte("<html><body><p>No matching records.</p></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><p>User: alice (id=42)</p></body></html>"))
	})
}

func TestLuaSQLiBooleanParity(t *testing.T) {
	luaC := findSQLiBoolean(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("vuln_handler_detected", func(t *testing.T) {
		srv := httptest.NewServer(vulnBooleanHandlerLua())
		defer srv.Close()
		target := srv.URL + "/user?id=42"

		goFs, err := (checks.SQLiBoolean{}).Run(context.Background(), client, sc, page.FromURL(target))
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

	t.Run("robust_handler_no_finding", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<p>fixed safe content</p>"))
		}))
		defer srv.Close()
		target := srv.URL + "/x?id=42"

		goFs, err := (checks.SQLiBoolean{}).Run(context.Background(), client, sc, page.FromURL(target))
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
