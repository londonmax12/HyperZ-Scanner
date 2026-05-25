package checks_lua

import (
	"context"
	"net/http"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findCORSConfig(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "cors-config" {
			return c
		}
	}
	t.Fatal("cors-config Lua check not found")
	return nil
}

// TestLuaCORSConfigParity runs every ACAO/ACAC shape through both the
// Go and Lua implementations and asserts the same finding count plus
// matching dedupe keys + severities. The Go check is the parity oracle.
func TestLuaCORSConfigParity(t *testing.T) {
	cases := []struct {
		name string
		url  string
		acao string
		acac string
	}{
		{"no_acao_no_finding", "https://example.com/", "", ""},
		{"wildcard_no_creds", "https://example.com/", "*", ""},
		{"wildcard_with_creds", "https://example.com/", "*", "true"},
		{"null_origin_no_creds", "https://example.com/", "null", ""},
		{"null_origin_with_creds", "https://example.com/", "null", "true"},
		{"specific_same_origin_with_creds", "https://example.com/", "https://example.com", "true"},
		{"specific_foreign_no_creds", "https://example.com/", "https://other.test", ""},
		{"specific_foreign_with_creds", "https://example.com/", "https://other.test", "true"},
		{"specific_foreign_case_insensitive_match", "https://EXAMPLE.com/", "https://example.com", "true"},
	}

	luaC := findCORSConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.acao != "" {
				h.Set("Access-Control-Allow-Origin", tc.acao)
			}
			if tc.acac != "" {
				h.Set("Access-Control-Allow-Credentials", tc.acac)
			}
			p := page.Page{URL: tc.url, Status: 200, Headers: h, Fetched: true}

			goFs, err := (checks.CORSConfig{}).Run(context.Background(), nil, nil, p)
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
					t.Errorf("sev drift: go=%q lua=%q", goFs[i].Severity, luaFs[i].Severity)
				}
				if goFs[i].Title != luaFs[i].Title {
					t.Errorf("title drift: go=%q lua=%q", goFs[i].Title, luaFs[i].Title)
				}
			}
		})
	}
}
