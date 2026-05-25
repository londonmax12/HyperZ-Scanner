package checks_lua

import (
	"context"
	"net/http"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findHSTS(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "hsts-weak" {
			return c
		}
	}
	t.Fatal("hsts-weak Lua check not found")
	return nil
}

func hstsPage(rawurl string, values []string) page.Page {
	h := http.Header{}
	for _, v := range values {
		h.Add("Strict-Transport-Security", v)
	}
	return page.Page{URL: rawurl, Status: 200, Headers: h, Fetched: true}
}

// TestLuaHSTSParity sweeps the directive variants the Go check is
// tested against and locks finding-count + dedupe key + severity
// parity. The HSTS detail strings are long and brittle to compare
// verbatim, so we assert on the structural fields the dedupe key
// already encodes (which is what downstream tools key off).
func TestLuaHSTSParity(t *testing.T) {
	cases := []struct {
		name   string
		values []string
	}{
		{name: "no_header", values: nil},
		{name: "ideal", values: []string{"max-age=63072000; includeSubDomains"}},
		{name: "max_age_zero", values: []string{"max-age=0"}},
		{name: "max_age_tiny", values: []string{"max-age=60"}},
		{name: "max_age_short", values: []string{"max-age=1000000"}},
		{name: "max_age_below_year", values: []string{"max-age=20000000"}},
		{name: "missing_max_age", values: []string{"includeSubDomains"}},
		{name: "max_age_invalid", values: []string{"max-age=abc"}},
		{name: "multi_header", values: []string{"max-age=63072000; includeSubDomains", "max-age=10"}},
		{name: "duplicate_directive", values: []string{"max-age=63072000; max-age=120; includeSubDomains"}},
	}

	lua := findHSTS(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := hstsPage("https://example.com/", tc.values)
			goFs, err := (checks.HSTSWeak{}).Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("go: %v", err)
			}
			luaFs, err := lua.Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("lua: %v", err)
			}
			if len(goFs) != len(luaFs) {
				t.Fatalf("count: go=%d lua=%d (go=%+v lua=%+v)", len(goFs), len(luaFs), goFs, luaFs)
			}
			for i := range goFs {
				if goFs[i].DedupeKey != luaFs[i].DedupeKey {
					t.Errorf("[%d] dedupe: go=%q lua=%q", i, goFs[i].DedupeKey, luaFs[i].DedupeKey)
				}
				if goFs[i].Severity != luaFs[i].Severity {
					t.Errorf("[%d] severity: go=%q lua=%q", i, goFs[i].Severity, luaFs[i].Severity)
				}
				if goFs[i].Title != luaFs[i].Title {
					t.Errorf("[%d] title: go=%q lua=%q", i, goFs[i].Title, luaFs[i].Title)
				}
				if len(goFs[i].Details) != len(luaFs[i].Details) {
					t.Errorf("[%d] details count: go=%d lua=%d", i, len(goFs[i].Details), len(luaFs[i].Details))
				}
			}
		})
	}
}

func TestLuaHSTSOverHTTPFires(t *testing.T) {
	p := hstsPage("http://example.com/", []string{"max-age=63072000; includeSubDomains"})
	fs, err := findHSTS(t).Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 finding for HTTP-served HSTS, got %d", len(fs))
	}
}
