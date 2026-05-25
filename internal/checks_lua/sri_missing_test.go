package checks_lua

import (
	"context"
	"net/http"
	"sort"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findSRIMissing(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "sri-missing" {
			return c
		}
	}
	t.Fatal("sri-missing Lua check not found")
	return nil
}

func htmlPage(rawurl, body string) page.Page {
	return page.Page{
		URL:     rawurl,
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte(body),
		Fetched: true,
	}
}

// TestLuaSRIParity sweeps tag shapes the Go check is tested against
// and asserts identical finding count + dedupe keys.
func TestLuaSRIParity(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "clean_with_integrity",
			body: `<html><body>
<script src="https://cdn.example.org/app.js" integrity="sha384-abc"></script>
</body></html>`,
		},
		{
			name: "cross_origin_script_no_integrity",
			body: `<html><body>
<script src="https://cdn.example.org/app.js"></script>
</body></html>`,
		},
		{
			name: "same_origin_script_skipped",
			body: `<html><body>
<script src="https://example.com/local.js"></script>
</body></html>`,
		},
		{
			name: "cross_origin_stylesheet",
			body: `<html><body>
<link rel="stylesheet" href="https://cdn.example.org/style.css">
</body></html>`,
		},
		{
			name: "ineligible_link_rel_skipped",
			body: `<html><body>
<link rel="icon" href="https://cdn.example.org/favicon.ico">
</body></html>`,
		},
		{
			name: "multiple_cross_origin_dedupe_by_url",
			body: `<html><body>
<script src="https://cdn.example.org/a.js"></script>
<script src="https://cdn.example.org/a.js"></script>
<script src="https://cdn.example.org/b.js"></script>
</body></html>`,
		},
		{
			name: "protocol_relative_resolved",
			body: `<html><body>
<script src="//cdn.example.org/x.js"></script>
</body></html>`,
		},
	}

	luaC := findSRIMissing(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := htmlPage("https://example.com/page", tc.body)
			goFs, err := (checks.SRIMissing{}).Run(context.Background(), nil, nil, p)
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
					t.Errorf("dedupe key drift @%d: go=%q lua=%q", i, goKeys[i], luaKeys[i])
				}
			}
		})
	}
}
