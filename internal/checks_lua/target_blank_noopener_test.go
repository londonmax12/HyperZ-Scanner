package checks_lua

import (
	"context"
	"net/http"
	"sort"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findTargetBlank(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "target-blank-noopener" {
			return c
		}
	}
	t.Fatal("target-blank-noopener Lua check not found")
	return nil
}

func tbpage(body string) page.Page {
	return page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte(body),
		Fetched: true,
	}
}

func TestLuaTargetBlankParity(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "noopener_present_no_finding",
			body: `<a href="https://other.example.org/" target="_blank" rel="noopener">x</a>`,
		},
		{
			name: "cross_origin_anchor_flags_medium",
			body: `<a href="https://other.example.org/" target="_blank">x</a>`,
		},
		{
			name: "same_origin_anchor_flags_low",
			body: `<a href="https://example.com/inner" target="_blank">x</a>`,
		},
		{
			name: "form_target_blank_flags",
			body: `<form action="https://other.example.org/" target="_blank"><input name="x"></form>`,
		},
		{
			name: "noreferrer_also_safe",
			body: `<a href="https://other.example.org/" target="_blank" rel="noreferrer">x</a>`,
		},
		{
			name: "javascript_skipped",
			body: `<a href="javascript:void(0)" target="_blank">x</a>`,
		},
		{
			name: "fragment_skipped",
			body: `<a href="#section" target="_blank">x</a>`,
		},
		{
			name: "duplicate_dedupe",
			body: `<a href="https://other.example.org/" target="_blank">x</a><a href="https://other.example.org/" target="_blank">y</a>`,
		},
		{
			name: "base_href_relative_resolves",
			body: `<base href="https://cdn.example.org/"><a href="docs" target="_blank">x</a>`,
		},
	}

	luaC := findTargetBlank(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tbpage(tc.body)
			goFs, err := (checks.TargetBlankNoopener{}).Run(context.Background(), nil, nil, p)
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
			// Severity sets should match too
			goSevs := make([]string, 0, len(goFs))
			luaSevs := make([]string, 0, len(luaFs))
			for _, f := range goFs {
				goSevs = append(goSevs, string(f.Severity))
			}
			for _, f := range luaFs {
				luaSevs = append(luaSevs, string(f.Severity))
			}
			sort.Strings(goSevs)
			sort.Strings(luaSevs)
			for i := range goSevs {
				if goSevs[i] != luaSevs[i] {
					t.Errorf("severity drift @%d: go=%q lua=%q", i, goSevs[i], luaSevs[i])
				}
			}
		})
	}
}
