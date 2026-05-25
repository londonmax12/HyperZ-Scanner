package checks_lua

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findOAuthDiscovery(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "oauth-discovery" {
			return c
		}
	}
	t.Fatal("oauth-discovery Lua check not found")
	return nil
}

// TestLuaOAuthDiscoveryParity mounts a synthetic OIDC discovery
// handler and runs the Go check + Lua port side-by-side against it.
// The Go check is the parity oracle: identical finding count and
// per-finding shape (severity, title, CWE, dedupe key) must come out
// of both implementations for every weakness case.
func TestLuaOAuthDiscoveryParity(t *testing.T) {
	baseline := func(issuer string) map[string]any {
		return map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"userinfo_endpoint":                     issuer + "/userinfo",
			"jwks_uri":                              issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "private_key_jwt"},
			"code_challenge_methods_supported":      []string{"S256"},
		}
	}

	cases := []struct {
		name string
		mut  func(doc map[string]any)
	}{
		{
			name: "alg_none",
			mut: func(doc map[string]any) {
				doc["id_token_signing_alg_values_supported"] = []string{"RS256", "none"}
			},
		},
		{
			name: "symmetric_alg",
			mut: func(doc map[string]any) {
				doc["id_token_signing_alg_values_supported"] = []string{"RS256", "HS256"}
			},
		},
		{
			name: "token_auth_none_only",
			mut: func(doc map[string]any) {
				doc["token_endpoint_auth_methods_supported"] = []string{"none"}
			},
		},
		{
			name: "pkce_missing",
			mut: func(doc map[string]any) {
				delete(doc, "code_challenge_methods_supported")
			},
		},
		{
			name: "pkce_plain_only",
			mut: func(doc map[string]any) {
				doc["code_challenge_methods_supported"] = []string{"plain"}
			},
		},
		{
			name: "implicit_flow",
			mut: func(doc map[string]any) {
				doc["response_types_supported"] = []string{"code", "token", "id_token"}
			},
		},
		{
			name: "plain_http_endpoint",
			mut: func(doc map[string]any) {
				doc["token_endpoint"] = "http://internal.example/token"
			},
		},
		{
			name: "all_weaknesses_together",
			mut: func(doc map[string]any) {
				doc["authorization_endpoint"] = "http://internal.example/auth"
				doc["response_types_supported"] = []string{"code", "token"}
				doc["id_token_signing_alg_values_supported"] = []string{"none", "HS256"}
				doc["token_endpoint_auth_methods_supported"] = []string{"none"}
				doc["code_challenge_methods_supported"] = []string{"plain"}
			},
		},
		{
			name: "clean_doc_no_findings",
			mut:  func(doc map[string]any) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(nil)
			defer srv.Close()
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/openid-configuration" {
					http.NotFound(w, r)
					return
				}
				doc := baseline(srv.URL)
				tc.mut(doc)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(doc)
			})

			client := newTestClient(t)
			pageURL := srv.URL + "/login"

			goFs, err := (&checks.OAuthDiscovery{}).Run(context.Background(), client, nil, page.FromURL(pageURL))
			if err != nil {
				t.Fatalf("go: %v", err)
			}
			// Each All() call mints fresh LuaChecks so the Lua port's
			// bridge-side OAuthDiscovery evaluator starts with an empty
			// per-host cache, matching the freshly constructed Go check.
			luaC := findOAuthDiscovery(t)
			luaFs, err := luaC.Run(context.Background(), client, nil, page.FromURL(pageURL))
			if err != nil {
				t.Fatalf("lua: %v", err)
			}

			if len(goFs) != len(luaFs) {
				t.Fatalf("count: go=%d lua=%d\ngo=%+v\nlua=%+v", len(goFs), len(luaFs), goFs, luaFs)
			}
			for i, gf := range goFs {
				lf := luaFs[i]
				if gf.Severity != lf.Severity {
					t.Errorf("[%d] severity drift: go=%q lua=%q", i, gf.Severity, lf.Severity)
				}
				if gf.Title != lf.Title {
					t.Errorf("[%d] title drift:\n go=%q\nlua=%q", i, gf.Title, lf.Title)
				}
				if gf.CWE != lf.CWE {
					t.Errorf("[%d] CWE drift: go=%q lua=%q", i, gf.CWE, lf.CWE)
				}
				if gf.OWASP != lf.OWASP {
					t.Errorf("[%d] OWASP drift: go=%q lua=%q", i, gf.OWASP, lf.OWASP)
				}
				if gf.DedupeKey != lf.DedupeKey {
					t.Errorf("[%d] dedupe drift: go=%q lua=%q", i, gf.DedupeKey, lf.DedupeKey)
				}
				if !strings.HasSuffix(lf.URL, "/login") {
					t.Errorf("[%d] lua URL = %q, want suffix /login", i, lf.URL)
				}
			}
		})
	}
}

// TestLuaOAuthDiscoveryNoDocument asserts the clean / 404 path returns
// no findings from either implementation - the well-known paths 404,
// no document parses, no findings.
func TestLuaOAuthDiscoveryNoDocument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := newTestClient(t)
	goFs, err := (&checks.OAuthDiscovery{}).Run(context.Background(), client, nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %+v", goFs)
	}
	luaC := findOAuthDiscovery(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %+v", luaFs)
	}
}
