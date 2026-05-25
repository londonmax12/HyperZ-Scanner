package checks_lua

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findGraphQLAudit(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "graphql-audit" {
			return c
		}
	}
	t.Fatal("graphql-audit Lua check not found")
	return nil
}

// graphqlMockConfig mirrors the Go test's graphqlHandlerConfig. Each
// toggle scopes the synthetic server to surface exactly one weakness.
type graphqlMockConfig struct {
	IsGraphQL     bool
	Introspection bool
	Suggestions   bool
	Batch         bool
	AliasCap      int
}

func graphqlMockServer(t *testing.T, cfg graphqlMockConfig) *httptest.Server {
	t.Helper()
	loginCandidates := []string{
		"login", "signIn", "authenticate", "loginUser", "userLogin",
		"signin", "logIn", "verifyOtp", "requestPasswordReset",
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.IsGraphQL {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		var arr []map[string]any
		if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 1 {
			w.Header().Set("Content-Type", "application/json")
			isMutBatch, mutField := graphqlClassifyMutationBatch(arr, loginCandidates)
			if isMutBatch {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errors": []map[string]any{{"message": "batched mutations are not allowed: " + mutField}},
				})
				return
			}
			if cfg.Batch {
				out := make([]map[string]any, len(arr))
				for i := range arr {
					out[i] = map[string]any{"data": map[string]any{"__typename": "Query"}}
				}
				_ = json.NewEncoder(w).Encode(out)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errors": []map[string]any{{"message": "batching disabled"}},
			})
			return
		}

		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		query, _ := body["query"].(string)
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(query, "__schema") {
			if !cfg.Introspection {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errors": []map[string]any{{"message": "GraphQL introspection is not allowed"}},
				})
				return
			}
			nested := strings.Count(query, "ofType")
			if nested >= 2 {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errors": []map[string]any{{
						"message": fmt.Sprintf("Query exceeds maximum depth of 5 (depth %d)", nested),
					}},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"__schema": map[string]any{
						"queryType": map[string]any{"name": "Query"},
						"types":     []map[string]any{{"name": "Query", "kind": "OBJECT"}},
					},
				},
			})
			return
		}

		aliasCount := strings.Count(query, "__typename")
		if aliasCount > 1 {
			if cfg.AliasCap > 0 && aliasCount > cfg.AliasCap {
				aliasCount = cfg.AliasCap
			}
			data := map[string]any{}
			for i := 0; i < aliasCount; i++ {
				key := fmt.Sprintf("a%d", i)
				data[key] = "Query"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
			return
		}

		if strings.Contains(query, "usre") {
			if cfg.Suggestions {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errors": []map[string]any{{"message": `Cannot query field "usre" on type "Query". Did you mean "user"?`}},
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errors": []map[string]any{{"message": `Cannot query field "usre" on type "Query".`}},
				})
			}
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"__typename": "Query"},
		})
	}))
}

func graphqlClassifyMutationBatch(arr []map[string]any, fields []string) (bool, string) {
	if len(arr) == 0 {
		return false, ""
	}
	for _, field := range fields {
		needle := field + "("
		all := true
		for _, item := range arr {
			q, _ := item["query"].(string)
			if !strings.Contains(q, "mutation") || !strings.Contains(q, needle) {
				all = false
				break
			}
		}
		if all {
			return true, field
		}
	}
	return false, ""
}

// TestLuaGraphQLAuditAllConfigFindings runs both checks against a
// fully-vulnerable handler (Introspection + Suggestions + Batch +
// AliasCap=0). Both must report all four config-class findings at
// LevelDefault, and per-finding shape (severity / title / CWE / OWASP
// / dedupe key) must match across the two implementations.
func TestLuaGraphQLAuditAllConfigFindings(t *testing.T) {
	srv := graphqlMockServer(t, graphqlMockConfig{
		IsGraphQL:     true,
		Introspection: true,
		Suggestions:   true,
		Batch:         true,
		AliasCap:      0,
	})
	defer srv.Close()

	pageURL := srv.URL + "/graphql"
	p := page.FromURL(pageURL)
	client := newTestClient(t)

	goFs, err := (checks.GraphQLAudit{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findGraphQLAudit(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != 4 {
		t.Fatalf("go: expected 4 findings, got %d: %+v", len(goFs), goFs)
	}
	if len(luaFs) != 4 {
		t.Fatalf("lua: expected 4 findings, got %d: %+v", len(luaFs), luaFs)
	}

	sortKey := func(fs []checks.Finding) {
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].DedupeKey < fs[j].DedupeKey })
	}
	sortKey(goFs)
	sortKey(luaFs)

	for i := range goFs {
		g := &goFs[i]
		l := &luaFs[i]
		if g.Severity != l.Severity {
			t.Errorf("[%d] severity drift: go=%q lua=%q", i, g.Severity, l.Severity)
		}
		if g.Title != l.Title {
			t.Errorf("[%d] title drift:\n go=%q\nlua=%q", i, g.Title, l.Title)
		}
		if g.CWE != l.CWE {
			t.Errorf("[%d] CWE drift: go=%q lua=%q", i, g.CWE, l.CWE)
		}
		if g.OWASP != l.OWASP {
			t.Errorf("[%d] OWASP drift: go=%q lua=%q", i, g.OWASP, l.OWASP)
		}
		if g.DedupeKey != l.DedupeKey {
			t.Errorf("[%d] dedupe drift:\n go=%q\nlua=%q", i, g.DedupeKey, l.DedupeKey)
		}
	}
}

// TestLuaGraphQLAuditCleanEndpoint asserts both implementations emit
// zero findings against a hardened endpoint (introspection /
// suggestions / batching / alias-amp all off).
func TestLuaGraphQLAuditCleanEndpoint(t *testing.T) {
	srv := graphqlMockServer(t, graphqlMockConfig{
		IsGraphQL: true,
		AliasCap:  1,
	})
	defer srv.Close()

	p := page.FromURL(srv.URL + "/graphql")
	client := newTestClient(t)

	goFs, err := (checks.GraphQLAudit{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %d: %+v", len(goFs), goFs)
	}
	luaC := findGraphQLAudit(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %d: %+v", len(luaFs), luaFs)
	}
}

// TestLuaGraphQLAuditSkipsNonGraphQLPath asserts both implementations
// skip an off-path URL with no GraphQL fingerprint - and crucially do
// not probe the server (a single probe would mean the path gate
// regressed).
func TestLuaGraphQLAuditSkipsNonGraphQLPath(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := page.FromURL(srv.URL + "/api/users")
	client := newTestClient(t)

	goFs, err := (checks.GraphQLAudit{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %d", len(goFs))
	}
	hits = 0

	luaC := findGraphQLAudit(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %d", len(luaFs))
	}
	if hits != 0 {
		t.Fatalf("server hit %d times; off-path page must not be probed", hits)
	}
}
