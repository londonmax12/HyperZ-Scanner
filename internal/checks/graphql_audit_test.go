package checks

import (
	"context"
	"encoding/json"
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

		// Introspection.
		if strings.Contains(query, "__schema") {
			if cfg.Introspection {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"__schema": map[string]any{
							"queryType": map[string]any{"name": "Query"},
							"types":     []map[string]any{{"name": "Query", "kind": "OBJECT"}},
						},
					},
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errors": []map[string]any{{"message": "GraphQL introspection is not allowed"}},
				})
			}
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

func TestGraphQLAuditAllFourFindings(t *testing.T) {
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
