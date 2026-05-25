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

func findLDAPi(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "ldapi" {
			return c
		}
	}
	t.Fatal("ldapi Lua check not found")
	return nil
}

// vulnLDAPHandlerLua mirrors internal/checks/ldap_injection_test.go's
// fixture: rebuilt-filter heuristic that flips between baseline and
// "no records" depending on whether the injection added an always-match
// or never-match operand. Lets both implementations see the same wire
// behavior and verdict in lockstep.
func vulnLDAPHandlerLua() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		id := r.URL.Query().Get("id")

		alwaysMatch := strings.Contains(id, "objectClass=*") || strings.Contains(id, "cn=*")
		neverMatch := strings.Contains(id, "objectClass=hpzc") || strings.Contains(id, "cn=hpzc")

		switch {
		case neverMatch:
			_, _ = w.Write([]byte("<html><body><p>No matching records.</p></body></html>"))
		case alwaysMatch && strings.HasPrefix(id, "admin"):
			_, _ = w.Write([]byte("<html><body><p>User: alice (cn=admin)</p></body></html>"))
		case id == "admin":
			_, _ = w.Write([]byte("<html><body><p>User: alice (cn=admin)</p></body></html>"))
		default:
			_, _ = w.Write([]byte("<html><body><p>No matching records.</p></body></html>"))
		}
	})
}

func TestLuaLDAPiParity(t *testing.T) {
	luaC := findLDAPi(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("filter_break_detected", func(t *testing.T) {
		srv := httptest.NewServer(vulnLDAPHandlerLua())
		defer srv.Close()
		target := srv.URL + "/user?id=admin"

		goFs, err := (checks.LDAPi{}).Run(context.Background(), client, sc, page.FromURL(target))
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
		target := srv.URL + "/?id=admin"

		goFs, err := (checks.LDAPi{}).Run(context.Background(), client, sc, page.FromURL(target))
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
