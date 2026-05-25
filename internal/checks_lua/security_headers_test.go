package checks_lua

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findSecurityHeaders(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "security-headers" {
			return c
		}
	}
	t.Fatal("security-headers Lua check not found")
	return nil
}

// TestLuaSecurityHeadersParity locks in identical finding count + dedupe
// key + missing-header bullets between the Go original and the Lua port.
// The Go check's own tests are the parity oracle.
func TestLuaSecurityHeadersParity(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		ct      string
		headers map[string]string
	}{
		{
			name:    "all_present_no_findings",
			status:  200,
			ct:      "text/html; charset=utf-8",
			headers: map[string]string{
				"Content-Security-Policy":   "default-src 'self'",
				"Strict-Transport-Security": "max-age=31536000",
				"X-Content-Type-Options":    "nosniff",
				"X-Frame-Options":           "DENY",
				"Referrer-Policy":           "no-referrer",
			},
		},
		{
			name:    "all_missing",
			status:  200,
			ct:      "text/html",
			headers: map[string]string{},
		},
		{
			name:    "one_missing_xfo",
			status:  200,
			ct:      "text/html",
			headers: map[string]string{
				"Content-Security-Policy":   "default-src 'self'",
				"Strict-Transport-Security": "max-age=31536000",
				"X-Content-Type-Options":    "nosniff",
				"Referrer-Policy":           "no-referrer",
			},
		},
		{
			name:    "non_html_skipped",
			status:  200,
			ct:      "application/json",
			headers: map[string]string{},
		},
		{
			name:    "non_200_skipped",
			status:  404,
			ct:      "text/html",
			headers: map[string]string{},
		},
		{
			name:    "xhtml_treated_as_html",
			status:  200,
			ct:      "application/xhtml+xml",
			headers: map[string]string{},
		},
	}

	luaC := findSecurityHeaders(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("Content-Type", tc.ct)
			for k, v := range tc.headers {
				h.Set(k, v)
			}
			p := page.Page{
				URL:     "https://example.com/",
				Status:  tc.status,
				Headers: h,
				Fetched: true,
			}

			goFs, err := (checks.SecurityHeaders{}).Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("go: %v", err)
			}
			luaFs, err := luaC.Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("lua: %v", err)
			}
			if len(goFs) != len(luaFs) {
				t.Fatalf("count: go=%d lua=%d (go=%+v lua=%+v)", len(goFs), len(luaFs), goFs, luaFs)
			}
			for i, gf := range goFs {
				lf := luaFs[i]
				if gf.DedupeKey != lf.DedupeKey {
					t.Errorf("dedupe key drift: go=%q lua=%q", gf.DedupeKey, lf.DedupeKey)
				}
				if gf.Severity != lf.Severity {
					t.Errorf("severity drift: go=%q lua=%q", gf.Severity, lf.Severity)
				}
				if gf.CWE != lf.CWE {
					t.Errorf("CWE drift: go=%q lua=%q", gf.CWE, lf.CWE)
				}
				goSorted := append([]string{}, gf.Details...)
				luaSorted := append([]string{}, lf.Details...)
				sort.Strings(goSorted)
				sort.Strings(luaSorted)
				if strings.Join(goSorted, "|") != strings.Join(luaSorted, "|") {
					t.Errorf("details drift:\n go=%v\nlua=%v", goSorted, luaSorted)
				}
			}
		})
	}
}
