package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestGraphQLAuditName(t *testing.T) {
	if got := (GraphQLAudit{}).Name(); got != "graphql-audit" {
		t.Fatalf("Name = %q, want graphql-audit", got)
	}
}

func TestGraphQLAuditLevel(t *testing.T) {
	if got := (GraphQLAudit{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// graphqlHandlerConfig drives the synthetic GraphQL server. Each toggle
// turns one finding's signal on, so a single test can scope to the
// exact issue it cares about without dragging the others in.
type graphqlHandlerConfig struct {
	// IsGraphQL: respond to any POST body with a valid GraphQL shape.
	// When false the handler returns 404 / plain text so discovery
	// fails.
	IsGraphQL bool
	// Introspection: respond to introspection queries with a populated
	// __schema. Off by default; production endpoints should disable it.
	Introspection bool
	// Suggestions: respond to unknown fields with "Did you mean ..."
	// in the errors[].message body.
	Suggestions bool
	// Batch: when the request body is a JSON array, return an array
	// response. Off means the server rejects array bodies with a
	// single error envelope.
	Batch bool
	// AliasCap caps the number of resolved aliases. 0 means uncapped
	// (alias-amplification accepted); any positive value caps at that
	// number so the alias probe sees only that many keys in data.
	AliasCap int
	// AliasAuthBypass: when true, the synthetic server resolves login
	// mutation aliases independently and returns one credential-
	// failure error per alias (with path = ["a0"], ["a1"], ...). When
	// false the server rejects the operation with a single global
	// validation error ("Cannot query field login on type Mutation").
	AliasAuthBypass bool
	// BatchMutationsAccepted: when true, batched arrays of mutation
	// operations are processed per-element and the server returns one
	// response per mutation (each with errors[].path = [field]). When
	// false the server rejects mutation batches with a single global
	// error.
	BatchMutationsAccepted bool
	// NoDepthLimit: when true, the synthetic server resolves nested
	// introspection queries to any depth the probe asks for. Default
	// (false) treats queries with >= 2 ofType selections as exceeding
	// the gateway's depth limit and returns a depth-exceeded error.
	NoDepthLimit bool
}

func graphqlServer(t *testing.T, cfg graphqlHandlerConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.IsGraphQL {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		// Detect batch request (top-level JSON array).
		var arr []map[string]any
		if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 1 {
			w.Header().Set("Content-Type", "application/json")
			// Distinguish mutation batches from query batches: when
			// every element carries a mutation against one of the
			// candidate login fields, gate on BatchMutationsAccepted
			// so the probeBatchMutations toggle is independent of the
			// generic batch-of-queries probe.
			isMutationBatch, mutationField := classifyMutationBatch(arr)
			if isMutationBatch {
				if cfg.BatchMutationsAccepted {
					out := make([]map[string]any, len(arr))
					for i := range arr {
						out[i] = map[string]any{
							"data": nil,
							"errors": []map[string]any{{
								"message": "Invalid credentials",
								"path":    []any{mutationField},
							}},
						}
					}
					_ = json.NewEncoder(w).Encode(out)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errors": []map[string]any{{"message": "batched mutations are not allowed"}},
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

		// Alias-based auth-bypass: a mutation that aliases one of the
		// candidate login fields multiple times. The probe's sub-
		// selection contains __typename, so this branch must run
		// before the generic __typename alias-counter below.
		if field, n := classifyAliasAuthQuery(query); n > 0 {
			if cfg.AliasAuthBypass {
				errs := make([]map[string]any, 0, n)
				for i := 0; i < n; i++ {
					errs = append(errs, map[string]any{
						"message": "Invalid credentials",
						"path":    []any{fmt.Sprintf("a%d", i)},
					})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data":   nil,
					"errors": errs,
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errors": []map[string]any{{
						"message": fmt.Sprintf(`Cannot query field %q on type "Mutation".`, field),
					}},
				})
			}
			return
		}

		// Introspection (regular and depth-probe variants).
		if strings.Contains(query, "__schema") {
			if !cfg.Introspection {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errors": []map[string]any{{"message": "GraphQL introspection is not allowed"}},
				})
				return
			}
			// Depth probe: the query nests ofType selections to
			// stress the depth limit. Gate on NoDepthLimit so the
			// default behaviour (limit enforced) keeps existing
			// "introspection enabled" tests from also flagging
			// depth.
			nested := strings.Count(query, "ofType")
			if nested >= 2 {
				if !cfg.NoDepthLimit {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"errors": []map[string]any{{
							"message": fmt.Sprintf("Query exceeds maximum depth of 5 (depth %d)", nested),
						}},
					})
					return
				}
				deepest := map[string]any{"name": "String"}
				for i := 0; i < nested; i++ {
					deepest = map[string]any{"ofType": deepest}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"__schema": map[string]any{
							"types": []map[string]any{{
								"fields": []map[string]any{{"type": deepest}},
							}},
						},
					},
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

		// Alias amplification: count the alias keys in the query and
		// return that many in data (or cap at AliasCap).
		aliasCount := strings.Count(query, "__typename")
		if aliasCount > 1 {
			if cfg.AliasCap > 0 && aliasCount > cfg.AliasCap {
				aliasCount = cfg.AliasCap
			}
			data := map[string]any{}
			for i := 0; i < aliasCount; i++ {
				key := "a"
				// Compact integer suffix without importing strconv into the test.
				if i > 0 {
					key += string(rune('0' + i))
				} else {
					key += "0"
				}
				data[key] = "Query"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
			return
		}

		// Field suggestions on misspelled fields.
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

		// Default discovery probe ({__typename}).
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"__typename": "Query"},
		})
	}))
}

// classifyMutationBatch returns (true, fieldName) when arr is a batch
// whose every element carries a mutation against the same candidate
// login field. Used by the synthetic server so the BatchMutationsAccepted
// toggle is independent of the generic Batch toggle: a "query batch"
// (every element is a __typename / introspection query) keeps using
// Batch, a "mutation batch" goes through the new gate. Iterates the
// production loginMutationCandidates list so new candidates added there
// route through the mutation-batch gate automatically.
func classifyMutationBatch(arr []map[string]any) (bool, string) {
	if len(arr) == 0 {
		return false, ""
	}
	for _, field := range loginMutationCandidates {
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

// classifyAliasAuthQuery returns (field, aliasCount) when query is a
// mutation aliasing one of the candidate login fields. aliasCount is
// the number of alias entries (counted by occurrences of "field("
// with a word boundary so "login(" does not match "loginUser(").
// Returns ("", 0) when query does not match the alias-auth-bypass
// shape, so the existing __typename-alias branch and the rest of the
// handler keep working unchanged. Iterates the production
// loginMutationCandidates list so the synthetic server stays in sync
// with the probe.
func classifyAliasAuthQuery(query string) (string, int) {
	if !strings.Contains(query, "mutation") {
		return "", 0
	}
	for _, field := range loginMutationCandidates {
		// Word-boundary check: "loginUser(" must not register as a
		// match for field "login". The probe writes the field name
		// followed by `(` and preceded by ` ` (after the alias colon),
		// so requiring a leading space disambiguates without needing a
		// real regex.
		needle := " " + field + "("
		n := strings.Count(query, needle)
		if n >= 2 {
			return field, n
		}
	}
	return "", 0
}

func TestGraphQLAuditSkipsNonGraphQLPath(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/api/users"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings off-path, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; off-path page must not be probed", got)
	}
}

func TestGraphQLAuditSkipsWhenDiscoveryFails(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: false})
	defer srv.Close()

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when discovery fails, got %d: %+v", len(findings), findings)
	}
}

func TestGraphQLAuditDetectsIntrospection(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, Introspection: true})
	defer srv.Close()

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected an introspection finding, got none")
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "introspection") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no introspection finding in %+v", findings)
	}
	if got.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", got.Severity)
	}
	if got.CWE != "CWE-200" {
		t.Errorf("CWE = %q, want CWE-200", got.CWE)
	}
	if got.Evidence == nil || got.Evidence.Exchange == nil {
		t.Errorf("Evidence/Exchange must be populated: %+v", got.Evidence)
	}
}

func TestGraphQLAuditDoesNotFlagIntrospectionWhenDisabled(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, Introspection: false})
	defer srv.Close()

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "introspection") {
			t.Errorf("unexpected introspection finding when feature is off: %+v", f)
		}
	}
}

func TestGraphQLAuditDetectsSuggestions(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, Suggestions: true})
	defer srv.Close()

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "suggestions") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no suggestions finding in %+v", findings)
	}
	if got.Severity != SeverityLow {
		t.Errorf("severity = %q, want low", got.Severity)
	}
	if got.CWE != "CWE-200" {
		t.Errorf("CWE = %q, want CWE-200", got.CWE)
	}
}

func TestGraphQLAuditDetectsBatching(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, Batch: true})
	defer srv.Close()

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "batching") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no batching finding in %+v", findings)
	}
	if got.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", got.Severity)
	}
	if got.CWE != "CWE-770" {
		t.Errorf("CWE = %q, want CWE-770", got.CWE)
	}
}

func TestGraphQLAuditDoesNotFlagBatchingWhenRejected(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, Batch: false})
	defer srv.Close()

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "batching") {
			t.Errorf("unexpected batching finding when rejected: %+v", f)
		}
	}
}

func TestGraphQLAuditDetectsAliasAmplification(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true})
	defer srv.Close()

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "alias") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no alias finding in %+v", findings)
	}
	if got.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", got.Severity)
	}
	if got.CWE != "CWE-770" {
		t.Errorf("CWE = %q, want CWE-770", got.CWE)
	}
}

func TestGraphQLAuditDoesNotFlagAliasWhenCapped(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, AliasCap: 3})
	defer srv.Close()

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "alias") {
			t.Errorf("unexpected alias finding when capped: %+v", f)
		}
	}
}

func TestGraphQLAuditDetectsAliasAuthBypass(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, AliasAuthBypass: true})
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := GraphQLAudit{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "alias-based auth bypass") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no alias-auth-bypass finding in %+v", findings)
	}
	if got.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", got.Severity)
	}
	if got.CWE != "CWE-307" {
		t.Errorf("CWE = %q, want CWE-307", got.CWE)
	}
	if got.Evidence == nil || got.Evidence.Exchange == nil {
		t.Errorf("Evidence/Exchange must be populated: %+v", got.Evidence)
	}
}

func TestGraphQLAuditDoesNotFlagAliasAuthBypassWhenRejected(t *testing.T) {
	// AliasAuthBypass off: server returns a single global validation
	// error for the login mutation, no per-alias execution. Run at
	// LevelAggressive so the probe actually fires - at LevelDefault it
	// would skip entirely and the test would pass vacuously.
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true})
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := GraphQLAudit{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "alias-based auth bypass") {
			t.Errorf("unexpected alias-auth-bypass finding when rejected: %+v", f)
		}
	}
}

func TestGraphQLAuditDetectsBatchMutations(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, BatchMutationsAccepted: true})
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := GraphQLAudit{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "batched mutations") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no batched-mutations finding in %+v", findings)
	}
	if got.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", got.Severity)
	}
	if got.CWE != "CWE-770" {
		t.Errorf("CWE = %q, want CWE-770", got.CWE)
	}
}

func TestGraphQLAuditDoesNotFlagBatchMutationsWhenRejected(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, Batch: true})
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := GraphQLAudit{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "batched mutations") {
			t.Errorf("unexpected batched-mutations finding when rejected: %+v", f)
		}
	}
}

func TestGraphQLAuditDetectsDepth(t *testing.T) {
	srv := graphqlServer(t, graphqlHandlerConfig{
		IsGraphQL:     true,
		Introspection: true,
		NoDepthLimit:  true,
	})
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := GraphQLAudit{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "depth") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no depth finding in %+v", findings)
	}
	if got.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", got.Severity)
	}
	if got.CWE != "CWE-770" {
		t.Errorf("CWE = %q, want CWE-770", got.CWE)
	}
}

func TestGraphQLAuditDoesNotFlagDepthWhenCapped(t *testing.T) {
	// Introspection on but NoDepthLimit off: the synthetic server
	// returns "exceeds maximum depth" for deeply nested queries.
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, Introspection: true})
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := GraphQLAudit{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "depth") {
			t.Errorf("unexpected depth finding when limit enforced: %+v", f)
		}
	}
}

func TestGraphQLAuditDoesNotFlagDepthWhenIntrospectionOff(t *testing.T) {
	// Without introspection the depth probe cannot measure depth
	// (the server short-circuits with "introspection not allowed"
	// before the nested chain resolves). Probe must stay silent.
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, NoDepthLimit: true})
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := GraphQLAudit{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "depth") {
			t.Errorf("unexpected depth finding when introspection is disabled: %+v", f)
		}
	}
}

func TestGraphQLAuditAllFourConfigFindings(t *testing.T) {
	// All four legacy configuration probes lit; new exploitation
	// toggles are off. Verifies the original four-finding contract.
	srv := graphqlServer(t, graphqlHandlerConfig{
		IsGraphQL:     true,
		Introspection: true,
		Suggestions:   true,
		Batch:         true,
		// AliasCap=0 means uncapped.
	})
	defer srv.Close()

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d: %+v", len(findings), findings)
	}
}

func TestGraphQLAuditAllSevenFindings(t *testing.T) {
	// Configuration and exploitation toggles all on: every probe
	// must fire exactly once. Aggressive level required for the
	// three exploitation probes to run.
	srv := graphqlServer(t, graphqlHandlerConfig{
		IsGraphQL:              true,
		Introspection:          true,
		Suggestions:            true,
		Batch:                  true,
		AliasAuthBypass:        true,
		BatchMutationsAccepted: true,
		NoDepthLimit:           true,
	})
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := GraphQLAudit{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/graphql"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 7 {
		t.Fatalf("expected 7 findings, got %d: %+v", len(findings), findings)
	}
	// Sanity-check the titles cover every probe so a future
	// regression that merges two findings into one is caught.
	want := []string{"introspection", "suggestions", "batching", "alias amplification", "alias-based auth bypass", "batched mutations", "depth"}
	for _, needle := range want {
		matched := false
		for _, f := range findings {
			if strings.Contains(strings.ToLower(f.Title), needle) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("no finding with title containing %q in %+v", needle, findings)
		}
	}
}

func TestGraphQLAuditGatesOnGraphiQLBody(t *testing.T) {
	// A page mounted at an unusual path (/api/data) that nonetheless
	// serves the GraphiQL UI in its body should still trigger the
	// probes - body evidence overrides the path heuristic.
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, Introspection: true})
	defer srv.Close()

	pg := page.FromURL(srv.URL + "/api/data")
	pg.Body = []byte(`<!doctype html><html><head><title>GraphiQL</title></head><body><div id="graphiql"></div></body></html>`)

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings when body has GraphiQL UI; got none")
	}
}

func TestGraphQLAuditGatesOnGraphQLErrorEnvelopeBody(t *testing.T) {
	// A GET against a GraphQL POST endpoint typically returns a JSON
	// error envelope like {"errors":[{"message":"Must provide query string."}]}.
	// That body is enough to identify the endpoint without a discovery POST.
	srv := graphqlServer(t, graphqlHandlerConfig{IsGraphQL: true, Introspection: true})
	defer srv.Close()

	pg := page.FromURL(srv.URL + "/api/data")
	pg.Body = []byte(`{"errors":[{"message":"Must provide query string."}]}`)

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings when body has GraphQL error envelope; got none")
	}
}

func TestGraphQLAuditSkipsWhenBodyAndPathBothInconclusive(t *testing.T) {
	// Body shows generic JSON, path is not GraphQL-shaped: the check
	// must not probe and must not send a discovery POST.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pg := page.FromURL(srv.URL + "/api/users")
	pg.Body = []byte(`{"users":[{"id":1}]}`)

	findings, err := GraphQLAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; inconclusive page must not be probed", got)
	}
}

func TestPageBodyLooksGraphQL(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"graphiql ui", `<html><div id="graphiql"></div></html>`, true},
		{"graphiql casing", `<title>GraphiQL Playground</title>`, true},
		{"apollo sandbox", `<script src="https://embeddable-sandbox.cdn.apollographql.com/_latest/embeddable-sandbox.umd.production.min.js"></script>`, true},
		{"graphql playground", `<title>GraphQL Playground</title>`, true},
		{"yoga landing", `<h1>Welcome to GraphQL-Yoga</h1>`, true},
		{"error envelope", `{"errors":[{"message":"Must provide query string."}]}`, true},
		{"apollo error", `{"errors":[{"message":"Must provide a query."}]}`, true},
		{"plain html", `<html><body>Welcome</body></html>`, false},
		{"rest api", `{"users":[{"id":1,"name":"alice"}]}`, false},
		{"hasura body without headers", `{"x-hasura-role":"admin"}`, false},
		{"empty body", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pg := page.Page{Body: []byte(tc.body)}
			if got := pageBodyLooksGraphQL(pg); got != tc.want {
				t.Errorf("pageBodyLooksGraphQL = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPageHeadersLookGraphQL(t *testing.T) {
	cases := []struct {
		name    string
		headers http.Header
		want    bool
	}{
		{"hasura role header", http.Header{"X-Hasura-Role": {"admin"}}, true},
		{"hasura user-id header", http.Header{"X-Hasura-User-Id": {"42"}}, true},
		{"hasura lowercase", http.Header{"x-hasura-admin-secret": {"shh"}}, true},
		{"plain rest api", http.Header{"Content-Type": {"application/json"}}, false},
		{"no headers", nil, false},
		{"empty headers", http.Header{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pg := page.Page{Headers: tc.headers}
			if got := pageHeadersLookGraphQL(pg); got != tc.want {
				t.Errorf("pageHeadersLookGraphQL = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPerAliasResolveCount(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{
			"data with n alias keys",
			`{"data":{"a0":"Q","a1":"Q","a2":"Q","a3":"Q","a4":"Q"}}`,
			5,
		},
		{
			"errors with per-alias paths",
			`{"data":null,"errors":[{"message":"Invalid","path":["a0"]},{"message":"Invalid","path":["a1"]},{"message":"Invalid","path":["a2"]}]}`,
			3,
		},
		{
			"errors with duplicate paths collapse to unique count",
			`{"data":null,"errors":[{"message":"Invalid","path":["a0"]},{"message":"Invalid","path":["a0"]}]}`,
			1,
		},
		{
			"global validation error has empty path",
			`{"errors":[{"message":"Cannot query field \"login\" on type \"Mutation\"."}]}`,
			0,
		},
		{
			"malformed json",
			`not-json`,
			0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := perAliasResolveCount([]byte(tc.body)); got != tc.want {
				t.Errorf("perAliasResolveCount = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestBatchMutationsExecuted(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		field string
		want  bool
	}{
		{
			"per-element execution via errors[].path",
			`[{"data":null,"errors":[{"path":["login"]}]},{"data":null,"errors":[{"path":["login"]}]}]`,
			"login",
			true,
		},
		{
			"per-element execution via data key",
			`[{"data":{"login":null}},{"data":{"login":null}}]`,
			"login",
			true,
		},
		{
			"global validation error per element (no path, no data key)",
			`[{"errors":[{"message":"Cannot query field login"}]},{"errors":[{"message":"Cannot query field login"}]}]`,
			"login",
			false,
		},
		{
			"single-element array does not prove batching",
			`[{"data":null,"errors":[{"path":["login"]}]}]`,
			"login",
			false,
		},
		{
			"non-array response",
			`{"errors":[{"message":"batching disabled"}]}`,
			"login",
			false,
		},
		{
			"element missing data/errors envelope",
			`[{"foo":"bar"},{"foo":"bar"}]`,
			"login",
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := batchMutationsExecuted([]byte(tc.body), tc.field); got != tc.want {
				t.Errorf("batchMutationsExecuted = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDepthResolved(t *testing.T) {
	// Synthesise a response with N ofType keys; the probe expects at
	// least the requested count to call depth "resolved".
	deep := func(n int) string {
		var b strings.Builder
		b.WriteString(`{"data":{"__schema":{"types":[{"fields":[{"type":`)
		for i := 0; i < n; i++ {
			b.WriteString(`{"ofType":`)
		}
		b.WriteString(`{"name":"String"}`)
		for i := 0; i < n; i++ {
			b.WriteByte('}')
		}
		b.WriteString(`}]}]}}}`)
		return b.String()
	}
	cases := []struct {
		name      string
		body      string
		requested int
		want      bool
	}{
		{"resolved at exactly requested depth", deep(8), 8, true},
		{"resolved beyond requested depth", deep(12), 8, true},
		{"truncated below requested depth", deep(4), 8, false},
		{
			"depth-exceeded error suppresses finding",
			`{"errors":[{"message":"Query exceeds maximum depth of 5"}]}`,
			8,
			false,
		},
		{
			"complexity-exceeded error suppresses finding",
			`{"errors":[{"message":"Query complexity 999 exceeds 100"}]}`,
			8,
			false,
		},
		{
			"introspection-disabled error suppresses finding",
			`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`,
			8,
			false,
		},
		{"empty body", ``, 8, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := depthResolved([]byte(tc.body), tc.requested); got != tc.want {
				t.Errorf("depthResolved = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildDepthQuery(t *testing.T) {
	q := buildDepthQuery(8)
	// The probe relies on the server returning >= requested ofType
	// keys; the query must also request at least that many for the
	// shape to be realistic.
	if strings.Count(q, "ofType") != 8 {
		t.Errorf("buildDepthQuery(8) has %d ofType selections, want 8: %s", strings.Count(q, "ofType"), q)
	}
	if !strings.Contains(q, "__schema") {
		t.Errorf("buildDepthQuery must traverse __schema: %s", q)
	}
	// Balanced braces - a malformed query would be rejected at the
	// parser before depth checks, masking the probe's intent.
	if strings.Count(q, "{") != strings.Count(q, "}") {
		t.Errorf("buildDepthQuery has unbalanced braces: %s", q)
	}
}

func TestGraphQLAuditPathGate(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/graphql", true},
		{"/GraphQL", true},
		{"/api/graphql", true},
		{"/v1/graphql", true},
		{"/graphiql", true},
		{"/playground", true},
		{"/altair", true},
		{"/api/v1/graphql/healthz", true},
		{"/api/users", false},
		{"/login", false},
		{"/", false},
	}
	for _, tc := range cases {
		if got := looksGraphQLPath(tc.path); got != tc.want {
			t.Errorf("looksGraphQLPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
