package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findJSLibsKnownVuln(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "js-libs-known-vuln" {
			return c
		}
	}
	t.Fatal("js-libs-known-vuln Lua check not found")
	return nil
}

// TestLuaJSLibsKnownVulnParity loads the same HTML pages through both
// the Go original and the Lua port and asserts identical findings.
// The Go check is the parity oracle - same library list, same per-
// finding severity + CWE + dedupe key.
func TestLuaJSLibsKnownVulnParity(t *testing.T) {
	cases := []struct {
		name string
		body string
		ct   string
	}{
		{"no_scripts", `<!DOCTYPE html><html><body>nothing</body></html>`, "text/html; charset=utf-8"},
		{
			"vulnerable_jquery_1_6",
			`<!DOCTYPE html><html><head><script src="https://code.jquery.com/jquery-1.6.0.min.js"></script></head></html>`,
			"text/html; charset=utf-8",
		},
		{
			"current_jquery_3_6",
			`<!DOCTYPE html><html><head><script src="/static/jquery-3.6.0.min.js"></script></head></html>`,
			"text/html; charset=utf-8",
		},
		{
			"multiple_libs",
			`<!DOCTYPE html><html><head>
<script src="/static/jquery-1.6.0.min.js"></script>
<script src="/static/jquery-ui-1.10.0.min.js"></script>
</head></html>`,
			"text/html; charset=utf-8",
		},
		{
			"non_html_skipped",
			`{"jquery": "1.6.0"}`,
			"application/json",
		},
	}

	luaC := findJSLibsKnownVuln(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.ct)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := newTestClient(t)
			goFs, err := (checks.JSLibsKnownVuln{}).Run(context.Background(), c, nil, page.FromURL(srv.URL))
			if err != nil {
				t.Fatalf("go: %v", err)
			}
			luaFs, err := luaC.Run(context.Background(), c, nil, page.FromURL(srv.URL))
			if err != nil {
				t.Fatalf("lua: %v", err)
			}
			if len(goFs) != len(luaFs) {
				t.Fatalf("count: go=%d lua=%d", len(goFs), len(luaFs))
			}
			goKeys := make([]string, 0, len(goFs))
			luaKeys := make([]string, 0, len(luaFs))
			for _, f := range goFs {
				goKeys = append(goKeys, f.DedupeKey)
			}
			for _, f := range luaFs {
				luaKeys = append(luaKeys, f.DedupeKey)
			}
			sort.Strings(goKeys)
			sort.Strings(luaKeys)
			for i := range goKeys {
				if goKeys[i] != luaKeys[i] {
					t.Errorf("dedupe drift @%d: go=%q lua=%q", i, goKeys[i], luaKeys[i])
				}
			}
		})
	}
}
