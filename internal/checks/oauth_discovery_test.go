package checks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestOAuthDiscoveryName(t *testing.T) {
	if got := (&OAuthDiscovery{}).Name(); got != "oauth-discovery" {
		t.Fatalf("Name = %q, want oauth-discovery", got)
	}
}

func TestOAuthDiscoveryLevel(t *testing.T) {
	if got := (&OAuthDiscovery{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

// oauthDiscoveryServer mounts a synthetic OIDC discovery handler at
// /.well-known/openid-configuration. cfg controls which weaknesses
// appear in the document; missing fields are omitted entirely so we
// can exercise the "PKCE not advertised" branch.
func oauthDiscoveryServer(t *testing.T, cfg map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func baselineGoodDoc(issuer string) map[string]any {
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

func TestOAuthDiscoveryGoodConfigProducesNoConfigFindings(t *testing.T) {
	// Verifies that none of the five configuration-related rules
	// fire on a baseline-good doc. The httptest server binds plain
	// HTTP, so the plain-HTTP-endpoint finding fires legitimately and
	// is excluded from this assertion - it is exercised in its own
	// test.
	srv := httptest.NewServer(nil)
	defer srv.Close()
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(baselineGoodDoc(srv.URL))
	})

	findings, err := (&OAuthDiscovery{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		title := strings.ToLower(f.Title)
		if strings.Contains(title, "plain http") {
			continue
		}
		t.Errorf("unexpected finding on good doc: %s (%s)", f.Title, f.Severity)
	}
}

func TestOAuthDiscoveryFlagsAlgNone(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	doc := baselineGoodDoc(srv.URL)
	doc["id_token_signing_alg_values_supported"] = []string{"RS256", "none"}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	findings, err := (&OAuthDiscovery{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "alg=none") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no alg=none finding in %+v", findings)
	}
	if got.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", got.Severity)
	}
	if got.CWE != "CWE-327" {
		t.Errorf("CWE = %q, want CWE-327", got.CWE)
	}
}

func TestOAuthDiscoveryFlagsSymmetricAlg(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	doc := baselineGoodDoc(srv.URL)
	doc["id_token_signing_alg_values_supported"] = []string{"RS256", "HS256"}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	findings, err := (&OAuthDiscovery{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "symmetric") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no symmetric-alg finding in %+v", findings)
	}
	if got.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", got.Severity)
	}
}

func TestOAuthDiscoveryFlagsTokenEndpointAuthNoneOnly(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	doc := baselineGoodDoc(srv.URL)
	doc["token_endpoint_auth_methods_supported"] = []string{"none"}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	findings, err := (&OAuthDiscovery{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "unauthenticated") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no token-endpoint-auth-none finding in %+v", findings)
	}
	if got.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", got.Severity)
	}
}

func TestOAuthDiscoveryFlagsPKCEMissing(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	doc := baselineGoodDoc(srv.URL)
	delete(doc, "code_challenge_methods_supported")
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	findings, err := (&OAuthDiscovery{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "pkce") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no PKCE finding in %+v", findings)
	}
	if got.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", got.Severity)
	}
}

func TestOAuthDiscoveryFlagsPKCEPlainOnly(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	doc := baselineGoodDoc(srv.URL)
	doc["code_challenge_methods_supported"] = []string{"plain"}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	findings, err := (&OAuthDiscovery{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "pkce") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no PKCE finding in %+v", findings)
	}
	if !strings.Contains(got.Detail, "plain") {
		t.Errorf("PKCE plain finding should mention 'plain' in Detail: %q", got.Detail)
	}
}

func TestOAuthDiscoveryFlagsImplicitFlow(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	doc := baselineGoodDoc(srv.URL)
	doc["response_types_supported"] = []string{"code", "token", "id_token"}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	findings, err := (&OAuthDiscovery{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "implicit") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no implicit-flow finding in %+v", findings)
	}
	if got.Severity != SeverityLow {
		t.Errorf("severity = %q, want low", got.Severity)
	}
}

func TestOAuthDiscoveryFlagsPlainHTTPEndpoints(t *testing.T) {
	// Issuer is HTTPS but token_endpoint accidentally references the
	// internal-only HTTP URL (a classic proxy-misconfig). The check
	// flags any plain-HTTP endpoint regardless of the issuer's own
	// scheme.
	srv := httptest.NewServer(nil)
	defer srv.Close()
	doc := baselineGoodDoc(srv.URL)
	doc["token_endpoint"] = "http://internal.example/token"
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	findings, err := (&OAuthDiscovery{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "plain http") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no plain-HTTP-endpoint finding in %+v", findings)
	}
	if got.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", got.Severity)
	}
	if !strings.Contains(got.Detail, "token_endpoint") {
		t.Errorf("finding should name token_endpoint: %q", got.Detail)
	}
}

func TestOAuthDiscoveryNoFindingsOn404(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings, err := (&OAuthDiscovery{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on 404, got %d: %+v", len(findings), findings)
	}
	if got := hits.Load(); got < 1 {
		t.Fatalf("expected at least 1 well-known probe, got %d", got)
	}
}

func TestOAuthDiscoveryRejectsDocWithoutIssuer(t *testing.T) {
	// A JSON body that lacks the issuer field is not a real metadata
	// document - probably a generic JSON 404 envelope. The check must
	// not parse it as a discovery doc.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token_signing_alg_values_supported":["none"]}`))
	}))
	defer srv.Close()

	findings, err := (&OAuthDiscovery{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on doc without issuer, got %d: %+v", len(findings), findings)
	}
}

func TestOAuthDiscoveryCachesPerHost(t *testing.T) {
	// A 50-page crawl on the same host should hit the well-known
	// endpoint exactly once, no matter how many pages the check
	// processes. The cache lives on the check struct.
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			probes.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(baselineGoodDoc("http://" + r.Host))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	check := &OAuthDiscovery{}
	for i := 0; i < 5; i++ {
		_, err := check.Run(context.Background(), newTestClient(t),
			nil, page.FromURL(srv.URL+"/page"+string(rune('a'+i))))
		if err != nil {
			t.Fatalf("Run #%d: %v", i, err)
		}
	}
	if got := probes.Load(); got != 1 {
		t.Errorf("well-known probed %d times across 5 pages on same host; want 1", got)
	}
}

func TestOAuthDiscoveryRestampsCachedFindingsAgainstNewPage(t *testing.T) {
	// A second page on the same host should receive the cached
	// findings stamped against the new URL, not the original probe
	// URL. This keeps the report tied to URLs the user actually saw.
	srv := httptest.NewServer(nil)
	defer srv.Close()
	doc := baselineGoodDoc(srv.URL)
	doc["id_token_signing_alg_values_supported"] = []string{"none"}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	check := &OAuthDiscovery{}
	first, err := check.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	second, err := check.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/dashboard"))
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if len(first) == 0 || len(second) == 0 {
		t.Fatalf("expected findings on both runs; first=%d second=%d", len(first), len(second))
	}
	if !strings.HasSuffix(first[0].URL, "/login") {
		t.Errorf("first URL = %q, want suffix /login", first[0].URL)
	}
	if !strings.HasSuffix(second[0].URL, "/dashboard") {
		t.Errorf("second URL = %q, want suffix /dashboard", second[0].URL)
	}
}

func TestOAuthDiscoveryEmitsAllFindingsTogether(t *testing.T) {
	// One document that trips all six rules should produce six
	// distinct findings. Verifies the rules are independent and
	// don't short-circuit each other.
	srv := httptest.NewServer(nil)
	defer srv.Close()
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                "http://internal.example/auth",
			"token_endpoint":                        srv.URL + "/token",
			"response_types_supported":              []string{"code", "token"},
			"id_token_signing_alg_values_supported": []string{"none", "HS256"},
			"token_endpoint_auth_methods_supported": []string{"none"},
			"code_challenge_methods_supported":      []string{"plain"},
		})
	})

	findings, err := (&OAuthDiscovery{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/login"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 6 {
		t.Fatalf("expected 6 findings (alg-none, symmetric, token-auth-none, pkce, implicit, plain-http), got %d: %+v",
			len(findings), findings)
	}
}

func TestPKCEWeaknessHelper(t *testing.T) {
	cases := []struct {
		name    string
		methods map[string]struct{}
		want    bool
	}{
		{"s256-only", lowerSet([]string{"S256"}), false},
		{"s256-plus-plain", lowerSet([]string{"S256", "plain"}), false},
		{"plain-only", lowerSet([]string{"plain"}), true},
		{"empty", lowerSet(nil), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pkceWeakness(tc.methods)
			if (got != "") != tc.want {
				t.Errorf("pkceWeakness => %q; want weakness=%v", got, tc.want)
			}
		})
	}
}
