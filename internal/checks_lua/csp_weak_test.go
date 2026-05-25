package checks_lua

import (
	"context"
	"net/http"
	"sort"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findCSPWeak(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "csp-weak" {
			return c
		}
	}
	t.Fatal("csp-weak Lua check not found")
	return nil
}

// TestLuaCSPWeakParity feeds representative CSP shapes through both
// implementations and locks in identical (finding count, dedupe key,
// max severity, details list). The Go check's CSP analyzer is the
// parity oracle - the Lua port consumes its result via the bridge so
// any rule drift would only happen on the Lua orchestration side.
func TestLuaCSPWeakParity(t *testing.T) {
	cases := []struct {
		name   string
		policy string
	}{
		{"unsafe_inline_critical", "script-src 'unsafe-inline'; object-src 'none'; base-uri 'none'"},
		{"unsafe_eval_high", "script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'none'"},
		{"wildcard_script_src", "default-src 'self'; script-src *; object-src 'none'; base-uri 'none'"},
		{"missing_object_and_base", "default-src 'self'; script-src 'self'"},
		{"clean_strict_policy", "default-src 'none'; script-src 'nonce-abc'; style-src 'nonce-abc'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"},
		{"scheme_only_https", "default-src 'self'; script-src 'self' https:; object-src 'none'; base-uri 'none'"},
		{"no_csp_no_finding", ""},
	}

	luaC := findCSPWeak(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.policy != "" {
				h.Set("Content-Security-Policy", tc.policy)
			}
			p := page.Page{URL: "https://example.com/", Status: 200, Headers: h, Fetched: true}

			goFs, err := (checks.CSPWeak{}).Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("go: %v", err)
			}
			luaFs, err := luaC.Run(context.Background(), nil, nil, p)
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
				if goFs[i].Title != luaFs[i].Title {
					t.Errorf("title drift: go=%q lua=%q", goFs[i].Title, luaFs[i].Title)
				}
				goSorted := append([]string{}, goFs[i].Details...)
				luaSorted := append([]string{}, luaFs[i].Details...)
				sort.Strings(goSorted)
				sort.Strings(luaSorted)
				if len(goSorted) != len(luaSorted) {
					t.Errorf("details count: go=%d lua=%d", len(goSorted), len(luaSorted))
					continue
				}
				for j := range goSorted {
					if goSorted[j] != luaSorted[j] {
						t.Errorf("details drift @%d: go=%q lua=%q", j, goSorted[j], luaSorted[j])
					}
				}
			}
		})
	}
}
