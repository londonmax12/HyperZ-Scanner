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

func findPathTraversal(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "path-traversal" {
			return c
		}
	}
	t.Fatal("path-traversal Lua check not found")
	return nil
}

// vulnFileReader echoes /etc/passwd to any request whose `file`
// parameter contains the canonical "../" escape. Benign / canary values
// come back clean, so the baseline-subtraction path exercises here too.
func vulnFileReader() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "..") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		_, _ = w.Write([]byte("nothing to see"))
	})
}

// TestLuaPathTraversalParity locks in identical finding shape between
// the Go check and the Lua port. The Go check is the parity oracle.
func TestLuaPathTraversalParity(t *testing.T) {
	luaC := findPathTraversal(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("vuln_handler_detected", func(t *testing.T) {
		srv := httptest.NewServer(vulnFileReader())
		defer srv.Close()
		target := srv.URL + "/read?file=report.txt"

		goFs, err := (checks.PathTraversal{}).Run(context.Background(), client, sc, page.FromURL(target))
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
			_, _ = w.Write([]byte("ok"))
		}))
		defer srv.Close()
		target := srv.URL + "/x?file=report.txt"

		goFs, err := (checks.PathTraversal{}).Run(context.Background(), client, sc, page.FromURL(target))
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
