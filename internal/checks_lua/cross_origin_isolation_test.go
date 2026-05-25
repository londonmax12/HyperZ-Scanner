package checks_lua

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findCOI(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "cross-origin-isolation" {
			return c
		}
	}
	t.Fatal("cross-origin-isolation Lua check not found")
	return nil
}

func coiPageHTML(rawurl string, h http.Header) page.Page {
	hh := h.Clone()
	if hh == nil {
		hh = http.Header{}
	}
	if hh.Get("Content-Type") == "" {
		hh.Set("Content-Type", "text/html; charset=utf-8")
	}
	return page.Page{URL: rawurl, Status: 200, Headers: hh, Fetched: true}
}

// TestLuaCOIParity runs the same COOP/COEP shapes the Go check is
// tested against and asserts identical finding counts and dedupe
// keys. The Go test file is the parity oracle.
func TestLuaCOIParity(t *testing.T) {
	cases := []struct {
		name string
		coop []string
		coep []string
	}{
		{name: "both_absent", coop: nil, coep: nil},
		{name: "coop_unsafe_none", coop: []string{"unsafe-none"}, coep: nil},
		{name: "coep_unsafe_none", coop: nil, coep: []string{"unsafe-none"}},
		{name: "coop_invalid", coop: []string{"bogus"}, coep: nil},
		{name: "coep_invalid", coop: nil, coep: []string{"bogus-coep"}},
		{name: "coep_only_require_corp", coop: nil, coep: []string{"require-corp"}},
		{name: "allow_popups_with_coep", coop: []string{"same-origin-allow-popups"}, coep: []string{"require-corp"}},
		{name: "isolated_pair_no_finding", coop: []string{"same-origin"}, coep: []string{"require-corp"}},
		{name: "duplicate_coop", coop: []string{"same-origin", "unsafe-none"}, coep: []string{"require-corp"}},
		{name: "duplicate_coep", coop: []string{"same-origin"}, coep: []string{"require-corp", "unsafe-none"}},
	}

	lua := findCOI(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range tc.coop {
				h.Add("Cross-Origin-Opener-Policy", v)
			}
			for _, v := range tc.coep {
				h.Add("Cross-Origin-Embedder-Policy", v)
			}
			p := coiPageHTML("https://example.com/page", h)

			goFs, err := (checks.CrossOriginIsolation{}).Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("go Run: %v", err)
			}
			luaFs, err := lua.Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("lua Run: %v", err)
			}
			if len(goFs) != len(luaFs) {
				t.Fatalf("count mismatch: go=%d lua=%d", len(goFs), len(luaFs))
			}
			for i := range goFs {
				if goFs[i].DedupeKey != luaFs[i].DedupeKey {
					t.Errorf("[%d] dedupe drift: go=%q lua=%q", i, goFs[i].DedupeKey, luaFs[i].DedupeKey)
				}
				if goFs[i].Severity != luaFs[i].Severity {
					t.Errorf("[%d] severity drift: go=%q lua=%q", i, goFs[i].Severity, luaFs[i].Severity)
				}
				if goFs[i].Title != luaFs[i].Title {
					t.Errorf("[%d] title drift: go=%q lua=%q", i, goFs[i].Title, luaFs[i].Title)
				}
				if len(goFs[i].Details) != len(luaFs[i].Details) {
					t.Errorf("[%d] details count drift: go=%d lua=%d (go=%v lua=%v)", i, len(goFs[i].Details), len(luaFs[i].Details), goFs[i].Details, luaFs[i].Details)
				}
			}
		})
	}
}

// TestLuaCOIShortCircuits sanity-checks the non-HTML and non-200
// gating paths produce no findings, matching the Go behavior.
func TestLuaCOIShortCircuits(t *testing.T) {
	lua := findCOI(t)
	h := http.Header{}
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Content-Type", "application/json")
	p := page.Page{URL: "https://example.com/api", Status: 200, Headers: h, Fetched: true}
	fs, err := lua.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("non-HTML should produce no findings, got %d", len(fs))
	}
	p404 := coiPageHTML("https://example.com/x", h)
	p404.Status = 404
	fs2, err := lua.Run(context.Background(), nil, nil, p404)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs2) != 0 {
		t.Errorf("non-200 should produce no findings, got %d", len(fs2))
	}
}

// TestLuaCOIDetailsContainSeverityTag confirms the bracketed severity
// prefix from the Go check carries over - reporters parse this to
// render the per-weakness chip in the finding table.
func TestLuaCOIDetailsContainSeverityTag(t *testing.T) {
	h := http.Header{}
	h.Set("Cross-Origin-Embedder-Policy", "require-corp")
	p := coiPageHTML("https://example.com/page", h)
	fs, err := findCOI(t).Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if !strings.Contains(strings.Join(fs[0].Details, "\n"), "[medium]") {
		t.Errorf("details should carry [severity] tag; got %v", fs[0].Details)
	}
}
