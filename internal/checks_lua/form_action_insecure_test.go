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

func findFormActionInsecure(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "form-action-insecure" {
			return c
		}
	}
	t.Fatal("form-action-insecure Lua check not found")
	return nil
}

// TestLuaFormActionInsecureParity feeds the same HTTPS pages through
// both implementations and asserts identical finding count + per-
// finding dedupe key + severity. The Go check is the parity oracle;
// its tokenizer (form/formaction/base-href, sensitive-field heuristic)
// is the single source of truth via the bridge helper.
func TestLuaFormActionInsecureParity(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "https_only_action_no_finding",
			body: `<form action="https://example.com/login" method="POST"><input name="pwd" type="password"></form>`,
		},
		{
			name: "http_action_with_credential",
			body: `<form action="http://evil.test/" method="POST"><input name="pwd" type="password"></form>`,
		},
		{
			name: "http_action_no_credential",
			body: `<form action="http://evil.test/" method="GET"><input name="q" type="text"></form>`,
		},
		{
			name: "button_formaction_override",
			body: `<form action="https://example.com/" method="POST"><input name="email" type="email"><button formaction="http://evil.test/" type="submit">Go</button></form>`,
		},
		{
			name: "two_forms_one_http_one_https",
			body: `<form action="https://example.com/" method="POST"><input name="a" type="text"></form><form action="http://insecure.test/" method="POST"><input name="b" type="text"></form>`,
		},
		{
			name: "base_href_overrides_relative_action",
			body: `<head><base href="http://insecure.test/"></head><body><form action="/submit" method="POST"><input name="x" type="text"></form></body>`,
		},
	}

	luaC := findFormActionInsecure(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("<!DOCTYPE html><html>" + tc.body + "</html>"))
			}))
			defer srv.Close()
			c := srv.Client()
			_ = c
			// Synthetic page: use the server URL as the HTTPS base.
			p := page.FromURL(srv.URL + "/")
			p.Headers = http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}
			p.Body = []byte("<!DOCTYPE html><html>" + tc.body + "</html>")
			p.Status = 200
			p.Fetched = true

			goFs, err := (checks.FormActionInsecure{}).Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("go: %v", err)
			}
			luaFs, err := luaC.Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("lua: %v", err)
			}
			if len(goFs) != len(luaFs) {
				t.Fatalf("count: go=%d lua=%d\ngo=%+v\nlua=%+v", len(goFs), len(luaFs), goFs, luaFs)
			}
			goKeys := make([]string, 0, len(goFs))
			luaKeys := make([]string, 0, len(luaFs))
			goSev := map[string]string{}
			luaSev := map[string]string{}
			for _, f := range goFs {
				goKeys = append(goKeys, f.DedupeKey)
				goSev[f.DedupeKey] = string(f.Severity)
			}
			for _, f := range luaFs {
				luaKeys = append(luaKeys, f.DedupeKey)
				luaSev[f.DedupeKey] = string(f.Severity)
			}
			sort.Strings(goKeys)
			sort.Strings(luaKeys)
			for i := range goKeys {
				if goKeys[i] != luaKeys[i] {
					t.Errorf("dedupe drift @%d: go=%q lua=%q", i, goKeys[i], luaKeys[i])
					continue
				}
				if goSev[goKeys[i]] != luaSev[luaKeys[i]] {
					t.Errorf("severity drift for %q: go=%q lua=%q", goKeys[i], goSev[goKeys[i]], luaSev[luaKeys[i]])
				}
			}
		})
	}
}
