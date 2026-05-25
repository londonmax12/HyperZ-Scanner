package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestOpenAPIAuditName(t *testing.T) {
	if got := (&OpenAPIAudit{}).Name(); got != "openapi-audit" {
		t.Fatalf("Name = %q, want openapi-audit", got)
	}
}

func TestOpenAPIAuditLevel(t *testing.T) {
	if got := (&OpenAPIAudit{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

// openAPIAuditServer mounts spec at the first well-known path the
// audit probes. Returns the httptest.Server (caller must Close) and
// a counter of how many requests landed on the spec path - used to
// confirm the per-host cache short-circuits subsequent runs.
func openAPIAuditServer(t *testing.T, spec string) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi.json" {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(spec))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestOpenAPIAuditNoSpecHostProducesNoFindings(t *testing.T) {
	// Every well-known path 404s. Audit must come back clean rather
	// than fabricate a finding from the 404 envelopes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings, err := (&OpenAPIAudit{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got: %+v", titles(findings))
	}
}

func TestOpenAPIAuditRejectsNonSpecBody(t *testing.T) {
	// The well-known path returns valid JSON but it isn't a spec.
	// The looksLikeOpenAPIDoc gate should drop it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"links":["/a","/b"]}`))
	}))
	defer srv.Close()

	findings, err := (&OpenAPIAudit{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on non-spec JSON, got: %+v", titles(findings))
	}
}

func TestOpenAPIAuditFindsEmbeddedCredential(t *testing.T) {
	// A real-shaped AWS access key id baked into an example default
	// must produce a critical embedded-credential finding.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "leaky", "version": "1"},
		"paths": {
			"/upload": {
				"post": {
					"parameters": [
						{
							"name": "X-AWS-Access-Key",
							"in": "header",
							"schema": {"type": "string"},
							"example": "AKIAIOSFODNN7EXAMPLE"
						}
					]
				}
			}
		}
	}`
	srv, _ := openAPIAuditServer(t, spec)

	findings, err := (&OpenAPIAudit{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f := findingByTitle(findings, "embeds a credential")
	if f.Title == "" {
		t.Fatalf("expected embedded-credential finding, got: %+v", titles(findings))
	}
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if !strings.Contains(strings.Join(f.Details, "\n"), "AKIA") {
		t.Errorf("Details should reference the AWS key (redacted form keeps AKIA), got: %v", f.Details)
	}
	if f.URL != srv.URL+"/" {
		t.Errorf("URL = %q, want stamped onto the visited page %q", f.URL, srv.URL+"/")
	}
}

func TestOpenAPIAuditFindsExampleBearerToken(t *testing.T) {
	// A Bearer Authorization example must produce the example-token
	// finding at Low severity. The token here is too short / lacks
	// vendor prefix to be hit by a secretPattern, so this verifies
	// the example-token path stands on its own.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "demo", "version": "1"},
		"paths": {
			"/me": {
				"get": {
					"parameters": [
						{
							"name": "Authorization",
							"in": "header",
							"schema": {"type": "string"},
							"example": "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
						}
					]
				}
			}
		}
	}`
	srv, _ := openAPIAuditServer(t, spec)

	findings, err := (&OpenAPIAudit{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f := findingByTitle(findings, "example Authorization tokens")
	if f.Title == "" {
		t.Fatalf("expected example-token finding, got: %+v", titles(findings))
	}
	if f.Severity != SeverityLow {
		t.Errorf("Severity = %q, want low", f.Severity)
	}
	joined := strings.Join(f.Details, "\n")
	if !strings.Contains(joined, "Bearer example") {
		t.Errorf("Details should label the scheme as Bearer, got: %v", f.Details)
	}
}

func TestOpenAPIAuditIgnoresAuthHeaderOutsideExampleBlock(t *testing.T) {
	// A Bearer-shaped string sitting in a free-text description (no
	// example/default/value key nearby) must NOT trip the example-
	// token finding - the contextRE gate exists exactly for this.
	spec := `{
		"openapi": "3.0.0",
		"info": {
			"title": "demo",
			"description": "Send the token Bearer abcdefghijklmnopqrstuvwxyz0123456789 to authenticate. See docs."
		},
		"paths": {
			"/ping": {"get": {"responses": {"200": {"description": "ok"}}}}
		}
	}`
	srv, _ := openAPIAuditServer(t, spec)

	findings, err := (&OpenAPIAudit{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findingsContainTitle(findings, "example Authorization tokens") {
		t.Fatalf("did not expect example-token finding for prose mention, got: %+v", titles(findings))
	}
}

func TestOpenAPIAuditFindsAuthlessOperations(t *testing.T) {
	// Spec declares a Bearer auth scheme and applies it to /secure
	// but leaves /open uncovered with no global default. The audit
	// must list /open in the auth-less finding and not /secure.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "mixed", "version": "1"},
		"components": {
			"securitySchemes": {
				"bearerAuth": {"type": "http", "scheme": "bearer"}
			}
		},
		"paths": {
			"/secure": {
				"get": {
					"security": [{"bearerAuth": []}],
					"responses": {"200": {"description": "ok"}}
				}
			},
			"/open": {
				"get": {
					"responses": {"200": {"description": "ok"}}
				}
			}
		}
	}`
	srv, _ := openAPIAuditServer(t, spec)

	findings, err := (&OpenAPIAudit{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f := findingByTitle(findings, "unauthenticated operations")
	if f.Title == "" {
		t.Fatalf("expected auth-less operations finding, got: %+v", titles(findings))
	}
	if f.Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
	joined := strings.Join(f.Details, "\n")
	if !strings.Contains(joined, "GET /open") {
		t.Errorf("Details should list GET /open, got: %v", f.Details)
	}
	if strings.Contains(joined, "GET /secure") {
		t.Errorf("Details should NOT list the secured /secure operation, got: %v", f.Details)
	}
}

func TestOpenAPIAuditRespectsGlobalSecurityDefault(t *testing.T) {
	// A global security default protects every operation that
	// doesn't override it. The audit must come back clean here.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "globally-secured", "version": "1"},
		"security": [{"bearerAuth": []}],
		"components": {
			"securitySchemes": {
				"bearerAuth": {"type": "http", "scheme": "bearer"}
			}
		},
		"paths": {
			"/a": {"get": {"responses": {"200": {"description": "ok"}}}},
			"/b": {"post": {"responses": {"200": {"description": "ok"}}}}
		}
	}`
	srv, _ := openAPIAuditServer(t, spec)

	findings, err := (&OpenAPIAudit{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findingsContainTitle(findings, "unauthenticated operations") {
		t.Fatalf("did not expect auth-less finding under a global default, got: %+v", titles(findings))
	}
}

func TestOpenAPIAuditOperationOverridesGlobalToEmpty(t *testing.T) {
	// Operation-level `security: []` is the canonical way to opt one
	// endpoint out of the global default. That overridden operation
	// counts as auth-less and must appear in the finding.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "mixed-override", "version": "1"},
		"security": [{"bearerAuth": []}],
		"components": {
			"securitySchemes": {
				"bearerAuth": {"type": "http", "scheme": "bearer"}
			}
		},
		"paths": {
			"/health": {
				"get": {
					"security": [],
					"responses": {"200": {"description": "ok"}}
				}
			},
			"/private": {
				"get": {"responses": {"200": {"description": "ok"}}}
			}
		}
	}`
	srv, _ := openAPIAuditServer(t, spec)

	findings, err := (&OpenAPIAudit{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f := findingByTitle(findings, "unauthenticated operations")
	if f.Title == "" {
		t.Fatalf("expected auth-less finding for overridden operation, got: %+v", titles(findings))
	}
	joined := strings.Join(f.Details, "\n")
	if !strings.Contains(joined, "GET /health") {
		t.Errorf("Details should list the explicitly-overridden /health, got: %v", f.Details)
	}
	if strings.Contains(joined, "GET /private") {
		t.Errorf("Details should NOT list /private (inherits global), got: %v", f.Details)
	}
}

func TestOpenAPIAuditSpecWithNoSchemesProducesNoAuthlessFinding(t *testing.T) {
	// When the spec never declares an auth scheme at all, the audit
	// has no opinion - the API might be deliberately public, or the
	// spec author may have omitted the scheme entirely. Either way
	// the auth-less finding must stay quiet.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "open-api", "version": "1"},
		"paths": {
			"/a": {"get": {"responses": {"200": {"description": "ok"}}}},
			"/b": {"get": {"responses": {"200": {"description": "ok"}}}}
		}
	}`
	srv, _ := openAPIAuditServer(t, spec)

	findings, err := (&OpenAPIAudit{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findingsContainTitle(findings, "unauthenticated operations") {
		t.Fatalf("did not expect auth-less finding for spec without schemes, got: %+v", titles(findings))
	}
}

func TestOpenAPIAuditCachesPerHost(t *testing.T) {
	// Two Run() calls against pages on the same host must produce
	// exactly one HTTP hit on the spec path. The second call is
	// served entirely from the per-host cache.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "cached", "version": "1"},
		"paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}}
	}`
	srv, hits := openAPIAuditServer(t, spec)

	check := &OpenAPIAudit{}
	_, err := check.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/first"))
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	_, err = check.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/second"))
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("spec fetched %d times, want 1 (per-host cache should suppress the second probe)", got)
	}
}

func TestOpenAPIAuditRestampsCachedFindingsAgainstNewPage(t *testing.T) {
	// The first Run() seeds the cache against /first; the second
	// call against /second must surface the same finding but with
	// Target / URL updated so the report ties the finding to the
	// page the user actually visited.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "leaky", "version": "1"},
		"paths": {
			"/upload": {
				"post": {
					"parameters": [
						{
							"name": "X-AWS-Access-Key",
							"in": "header",
							"schema": {"type": "string"},
							"example": "AKIAIOSFODNN7EXAMPLE"
						}
					]
				}
			}
		}
	}`
	srv, _ := openAPIAuditServer(t, spec)

	check := &OpenAPIAudit{}
	_, err := check.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/first"))
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	second, err := check.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/second"))
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	f := findingByTitle(second, "embeds a credential")
	if f.Title == "" {
		t.Fatalf("expected cached embedded-credential finding to re-emit, got: %+v", titles(second))
	}
	if f.URL != srv.URL+"/second" {
		t.Errorf("URL = %q, want re-stamped onto the second page", f.URL)
	}
	if f.Target != srv.URL+"/second" {
		t.Errorf("Target = %q, want re-stamped onto the second page", f.Target)
	}
}

func TestLooksLikeOpenAPIDoc(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"json openapi 3", `{"openapi":"3.0.0","paths":{}}`, true},
		{"json swagger 2", `{"swagger":"2.0","paths":{}}`, true},
		{"yaml openapi", "openapi: 3.0.0\npaths: {}\n", true},
		{"yaml swagger", "swagger: \"2.0\"\npaths: {}\n", true},
		{"plain json", `{"foo":"bar"}`, false},
		{"empty", ``, false},
	}
	for _, c := range cases {
		if got := looksLikeOpenAPIDoc([]byte(c.body)); got != c.want {
			t.Errorf("%s: looksLikeOpenAPIDoc = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRequirementIsAuthenticated(t *testing.T) {
	cases := []struct {
		name string
		req  []map[string][]string
		want bool
	}{
		{"nil", nil, false},
		{"explicitly empty list", []map[string][]string{}, false},
		{"empty map entry", []map[string][]string{{}}, false},
		{"named scheme", []map[string][]string{{"bearerAuth": {}}}, true},
		{"blank name", []map[string][]string{{"   ": {}}}, false},
	}
	for _, c := range cases {
		if got := requirementIsAuthenticated(c.req); got != c.want {
			t.Errorf("%s: requirementIsAuthenticated = %v, want %v", c.name, got, c.want)
		}
	}
}
