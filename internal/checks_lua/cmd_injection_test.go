package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func findCmdInjection(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "cmd-injection" {
			return c
		}
	}
	t.Fatal("cmd-injection Lua check not found")
	return nil
}

func sleepFromShellPayloadLua(s string) time.Duration {
	for _, marker := range []string{"sleep ", "ping -n "} {
		if i := strings.Index(s, marker); i >= 0 {
			rest := s[i+len(marker):]
			n, end := 0, 0
			for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
				n = n*10 + int(rest[end]-'0')
				end++
			}
			if end > 0 {
				return time.Duration(n) * time.Second
			}
		}
	}
	return 0
}

func TestLuaCmdInjectionParity(t *testing.T) {
	restore := checks.SetCmdInjectionTuningForTest(1, 0.5)
	defer restore()

	luaC := findCmdInjection(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("sleepy_shell_detected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.URL.Query().Get("host")
			if d := sleepFromShellPayloadLua(host); d > 0 {
				time.Sleep(d)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		target := srv.URL + "/?host=localhost"

		goFs, err := (checks.CmdInjection{}).Run(context.Background(), client, sc, page.FromURL(target))
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

	t.Run("fast_handler_no_finding", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		target := srv.URL + "/?host=localhost"

		goFs, err := (checks.CmdInjection{}).Run(context.Background(), client, sc, page.FromURL(target))
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
