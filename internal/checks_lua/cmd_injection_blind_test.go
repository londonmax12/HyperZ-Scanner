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

func findCmdInjectionBlind(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "cmd-injection-blind" {
			return c
		}
	}
	t.Fatal("cmd-injection-blind Lua check not found")
	return nil
}

func TestLuaCmdInjectionBlindParity(t *testing.T) {
	luaC := findCmdInjectionBlind(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("error_based_detected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.URL.Query().Get("host")
			if strings.Contains(host, "nonexistent_cmd") {
				_, _ = w.Write([]byte("Error output: sh: " + host + ": command not found\n"))
				return
			}
			_, _ = w.Write([]byte("Success"))
		}))
		defer srv.Close()
		target := srv.URL + "/ping?host=example.com"

		goFs, err := (checks.CmdInjectionBlind{}).Run(context.Background(), client, sc, page.FromURL(target))
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
			_, _ = w.Write([]byte("Success"))
		}))
		defer srv.Close()
		target := srv.URL + "/?host=example.com"

		goFs, err := (checks.CmdInjectionBlind{}).Run(context.Background(), client, sc, page.FromURL(target))
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
