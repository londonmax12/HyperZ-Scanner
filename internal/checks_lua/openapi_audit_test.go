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

func findOpenAPI(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "openapi-audit" {
			return c
		}
	}
	t.Fatal("openapi-audit Lua check not found")
	return nil
}

// baselineOpenAPISpec returns a minimal OAS3 spec with one declared
// security scheme and one explicitly-public operation. Per-test
// mutators layer the audit-trigger conditions on top so each case
// exercises exactly one weakness in isolation.
func baselineOpenAPISpec() map[string]any {
	return map[string]any{
		"openapi": "3.0.0",
		"info": map[string]any{
			"title":   "test",
			"version": "1.0.0",
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":   "http",
					"scheme": "bearer",
				},
			},
		},
		"paths": map[string]any{
			"/health": map[string]any{
				"get": map[string]any{
					"summary":  "health",
					"security": []any{},
				},
			},
		},
	}
}

// TestLuaOpenAPIAuditParity mounts a synthetic OpenAPI handler and
// runs the Go check + Lua port side-by-side against it. Per-finding
// shape (severity, title, CWE, OWASP, dedupe key) must match for
// every weakness case.
func TestLuaOpenAPIAuditParity(t *testing.T) {
	cases := []struct {
		name string
		mut  func(doc map[string]any)
	}{
		{
			name: "embedded_credentials",
			mut: func(doc map[string]any) {
				// AKIA-prefixed AWS key in an example: triggers the
				// secrets_in_body catalogue's aws-access-key-id pattern.
				paths := doc["paths"].(map[string]any)
				paths["/aws"] = map[string]any{
					"get": map[string]any{
						"parameters": []any{
							map[string]any{
								"name":    "key",
								"in":      "query",
								"example": "AKIAIOSFODNN7EXAMPLE",
							},
						},
					},
				}
			},
		},
		{
			name: "example_auth_tokens",
			mut: func(doc map[string]any) {
				// 20+ char tokens trigger openAPIExampleHeaderRe; the
				// example: key satisfies the nearby-context filter.
				paths := doc["paths"].(map[string]any)
				paths["/login"] = map[string]any{
					"post": map[string]any{
						"parameters": []any{
							map[string]any{
								"name":    "Authorization",
								"in":      "header",
								"example": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
							},
						},
					},
				}
			},
		},
		{
			name: "authless_operations",
			mut: func(doc map[string]any) {
				// /users/{id} GET has no security: key, no global
				// default -> inherits to "no auth required" while the
				// spec declares bearerAuth.
				paths := doc["paths"].(map[string]any)
				paths["/users/{id}"] = map[string]any{
					"get": map[string]any{
						"summary": "fetch user",
					},
				}
			},
		},
		{
			name: "all_three_weaknesses",
			mut: func(doc map[string]any) {
				paths := doc["paths"].(map[string]any)
				paths["/aws"] = map[string]any{
					"get": map[string]any{
						"parameters": []any{
							map[string]any{
								"name":    "key",
								"in":      "query",
								"example": "AKIAIOSFODNN7EXAMPLE",
							},
						},
					},
				}
				paths["/login"] = map[string]any{
					"post": map[string]any{
						"parameters": []any{
							map[string]any{
								"name":    "Authorization",
								"in":      "header",
								"example": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
							},
						},
					},
				}
				paths["/users/{id}"] = map[string]any{
					"get": map[string]any{
						"summary": "fetch user",
					},
				}
			},
		},
		{
			name: "clean_spec_no_findings",
			mut:  func(doc map[string]any) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/openapi.json" {
					http.NotFound(w, r)
					return
				}
				doc := baselineOpenAPISpec()
				tc.mut(doc)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(doc)
			}))
			defer srv.Close()

			client := newTestClient(t)
			pageURL := srv.URL + "/some-page"

			goFs, err := (&checks.OpenAPIAudit{}).Run(context.Background(), client, nil, page.FromURL(pageURL))
			if err != nil {
				t.Fatalf("go: %v", err)
			}
			luaC := findOpenAPI(t)
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
					t.Errorf("[%d] dedupe drift:\n go=%q\nlua=%q", i, gf.DedupeKey, lf.DedupeKey)
				}
				if !strings.HasSuffix(lf.URL, "/some-page") {
					t.Errorf("[%d] lua URL = %q, want suffix /some-page", i, lf.URL)
				}
			}
		})
	}
}

// TestLuaOpenAPIAuditNoSpec asserts the clean / 404 path returns no
// findings from either implementation - the well-known paths 404,
// no spec parses, no audit runs.
func TestLuaOpenAPIAuditNoSpec(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := newTestClient(t)
	goFs, err := (&checks.OpenAPIAudit{}).Run(context.Background(), client, nil, page.FromURL(srv.URL+"/some-page"))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %+v", goFs)
	}
	luaC := findOpenAPI(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, page.FromURL(srv.URL+"/some-page"))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %+v", luaFs)
	}
}
