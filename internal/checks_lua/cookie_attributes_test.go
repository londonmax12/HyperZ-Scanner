package checks_lua

import (
	"context"
	"net/http"
	"sort"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findCookieAttrs(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "cookie-attributes" {
			return c
		}
	}
	t.Fatal("cookie-attributes Lua check not found")
	return nil
}

// TestLuaCookieAttrParity runs Set-Cookie shapes through both checks
// and locks in identical finding counts + per-finding dedupe keys.
// The Go test (cookie_attributes_test.go) is the parity oracle.
func TestLuaCookieAttrParity(t *testing.T) {
	cases := []struct {
		name      string
		setCookie []string
		https     bool
	}{
		{
			name:      "fully_secure_no_findings",
			setCookie: []string{"session=abc; Secure; HttpOnly; SameSite=Strict; Path=/"},
			https:     true,
		},
		{
			name:      "missing_all_attrs_https",
			setCookie: []string{"session=abc; Path=/"},
			https:     true,
		},
		{
			name:      "missing_all_attrs_http_no_secure_flag",
			setCookie: []string{"session=abc; Path=/"},
			https:     false,
		},
		{
			name: "two_cookies_two_attrs_each",
			setCookie: []string{
				"a=1; HttpOnly; Path=/",
				"b=2; Secure; Path=/",
			},
			https: true,
		},
		{
			name:      "same_site_lax_ok",
			setCookie: []string{"s=v; Secure; HttpOnly; SameSite=Lax"},
			https:     true,
		},
		{
			name:      "same_site_none_ok",
			setCookie: []string{"s=v; Secure; HttpOnly; SameSite=None"},
			https:     true,
		},
	}

	luaC := findCookieAttrs(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use a synthetic in-memory Page so the check sees the
			// exact Set-Cookie set without needing a TLS test server.
			h := http.Header{}
			for _, c := range tc.setCookie {
				h.Add("Set-Cookie", c)
			}
			scheme := "https"
			if !tc.https {
				scheme = "http"
			}
			p := page.Page{
				URL:     scheme + "://example.com/",
				Status:  200,
				Headers: h,
				Fetched: true,
			}

			goFs, err := (checks.CookieAttributes{}).Run(context.Background(), nil, nil, p)
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
