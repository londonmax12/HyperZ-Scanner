package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func findSSTI(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "ssti" {
			return c
		}
	}
	t.Fatal("ssti Lua check not found")
	return nil
}

// jinja2EvalReLua mirrors the Go test helper so the Lua-side fixture
// handler evaluates `{{N*M}}` to the integer product. Without this the
// detection oracle would not see canary+expected+canary in the body.
var jinja2EvalReLua = regexp.MustCompile(`\{\{(\d+)\*(\d+)\}\}`)

func evalJinja2(s string) string {
	return jinja2EvalReLua.ReplaceAllStringFunc(s, func(match string) string {
		m := jinja2EvalReLua.FindStringSubmatch(match)
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		return strconv.Itoa(a * b)
	})
}

func TestLuaSSTIParity(t *testing.T) {
	luaC := findSSTI(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("jinja2_eval_detected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			param := r.URL.Query().Get("template")
			result := evalJinja2(param)
			_, _ = w.Write([]byte("result: " + result))
		}))
		defer srv.Close()
		target := srv.URL + "/?template=x"

		goFs, err := (checks.SSTI{}).Run(context.Background(), client, sc, page.FromURL(target))
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
			_, _ = w.Write([]byte("static body"))
		}))
		defer srv.Close()
		target := srv.URL + "/?template=x"

		goFs, err := (checks.SSTI{}).Run(context.Background(), client, sc, page.FromURL(target))
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
