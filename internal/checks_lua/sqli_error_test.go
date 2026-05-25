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

func findSQLiError(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "sqli-error" {
			return c
		}
	}
	t.Fatal("sqli-error Lua check not found")
	return nil
}

// vulnMySQL leaks a MariaDB syntax error verbatim whenever the `id`
// query value carries a bare single quote / backtick. Benign canary
// values come back clean, exercising the baseline-subtraction path.
func vulnMySQL() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, "'\"`") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Error: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version near '" + id + "' at line 1"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("user details for " + id))
	})
}

// TestLuaSQLiErrorParity feeds a contrived MySQL-leaking handler and
// a safe handler through both implementations and locks in identical
// finding count + dedupe key + severity. The Go check's new-match
// scanner is the parity oracle, exposed to Lua via the body bridge.
func TestLuaSQLiErrorParity(t *testing.T) {
	luaC := findSQLiError(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("mysql_syntax_error_detected", func(t *testing.T) {
		srv := httptest.NewServer(vulnMySQL())
		defer srv.Close()
		target := srv.URL + "/user?id=42"

		goFs, err := (checks.SQLiError{}).Run(context.Background(), client, sc, page.FromURL(target))
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
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
		defer srv.Close()
		target := srv.URL + "/x?id=42"

		goFs, err := (checks.SQLiError{}).Run(context.Background(), client, sc, page.FromURL(target))
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
