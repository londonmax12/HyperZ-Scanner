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

func findSQLiTime(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "sqli-time" {
			return c
		}
	}
	t.Fatal("sqli-time Lua check not found")
	return nil
}

// sleepFromPayloadLua mirrors sqli_time_test.go's helper so the Lua-
// side fixture handler sleeps when our wire payload asks it to. Keeping
// the helper local to this package avoids an internal/checks export
// just to make tests cleaner.
func sleepFromPayloadLua(s string) time.Duration {
	for _, marker := range []string{"SLEEP(", "sleep(", "pg_sleep("} {
		i := strings.Index(s, marker)
		if i < 0 {
			continue
		}
		rest := s[i+len(marker):]
		end := strings.Index(rest, ")")
		if end < 0 {
			continue
		}
		if n, ok := parseDigitsLua(rest[:end]); ok {
			return time.Duration(n) * time.Second
		}
	}
	if i := strings.Index(s, "0:0:"); i >= 0 {
		rest := s[i+len("0:0:"):]
		end := strings.IndexAny(rest, "'\"")
		if end < 0 {
			end = len(rest)
		}
		if n, ok := parseDigitsLua(rest[:end]); ok {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}

func parseDigitsLua(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func TestLuaSQLiTimeParity(t *testing.T) {
	restore := checks.SetSQLiTimeTuningForTest(1, 0.5)
	defer restore()

	luaC := findSQLiTime(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("sleepy_handler_detected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.URL.Query().Get("id")
			if d := sleepFromPayloadLua(id); d > 0 {
				time.Sleep(d)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("done"))
		}))
		defer srv.Close()
		target := srv.URL + "/user?id=42"

		goFs, err := (checks.SQLiTime{}).Run(context.Background(), client, sc, page.FromURL(target))
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
		target := srv.URL + "/x?id=42"

		goFs, err := (checks.SQLiTime{}).Run(context.Background(), client, sc, page.FromURL(target))
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
