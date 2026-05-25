package checks_lua

import (
	"context"
	"net/http"
	"sort"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findFormAuto(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "form-autocomplete" {
			return c
		}
	}
	t.Fatal("form-autocomplete Lua check not found")
	return nil
}

// formAutoPage builds an in-memory HTML page; the check reads p.Body
// directly so no test server is needed.
func formAutoPage(body string) page.Page {
	return page.Page{
		URL:     "https://example.com/login",
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte(body),
		Fetched: true,
	}
}

func TestLuaFormAutocompleteParity(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "password_off_no_finding",
			body: `<form><input type="password" name="pwd" autocomplete="off"></form>`,
		},
		{
			name: "password_no_autocomplete_flags",
			body: `<form><input type="password" name="pwd"></form>`,
		},
		{
			name: "email_no_autocomplete_flags",
			body: `<form><input type="email" name="email"></form>`,
		},
		{
			name: "credit_card_name_pattern_flags",
			body: `<form><input type="text" name="cardNumber"></form>`,
		},
		{
			name: "two_fields_two_findings",
			body: `<form><input type="password" name="pwd"><input type="email" name="email"></form>`,
		},
		{
			name: "same_field_twice_dedupes",
			body: `<form><input type="password" name="pwd"></form><form><input type="password" name="pwd"></form>`,
		},
		{
			name: "no_sensitive_inputs_no_finding",
			body: `<form><input type="text" name="comment"></form>`,
		},
	}

	luaC := findFormAuto(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := formAutoPage(tc.body)
			goFs, err := (checks.FormAutocomplete{}).Run(context.Background(), nil, nil, p)
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
		})
	}
}
