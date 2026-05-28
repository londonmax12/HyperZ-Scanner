package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/scope"
)

// OAuthDiscovery audits the public OAuth 2.0 Authorization Server
// Metadata (RFC 8414) and OpenID Connect Discovery 1.0 documents an
// identity provider publishes at well-known paths on its issuer host.
// The documents declare which signing algorithms, client-auth methods,
// PKCE methods, and response types the AS accepts; misconfigurations
// in these advertised values produce real attacker primitives even
// before any login flow is exercised.
//
// What the check looks for (one finding per hit):
//
//  1. id_token_signing_alg_values_supported contains "none" - the AS
//     advertises that it will issue unsigned id_tokens, which a
//     validator pinning alg against the advertised set will accept.
//     Critical.
//  2. id_token_signing_alg_values_supported contains a symmetric
//     algorithm (HS256/HS384/HS512) - the secret is shared with every
//     RP, which is the wrong trust model for a federation. Medium.
//  3. token_endpoint_auth_methods_supported is { "none" } only - the
//     AS will issue tokens to any caller that presents a code, making
//     every public client interchangeable with every other. High.
//  4. code_challenge_methods_supported missing or { "plain" } only -
//     PKCE is not enforced, or only a no-op "transformation" is
//     offered. Medium.
//  5. response_types_supported includes "token" or "id_token" (the
//     implicit flow) - deprecated by RFC 9700 / OAuth 2.1 because
//     tokens land in the URL fragment and leak to history, logs, and
//     referrers. Low.
//  6. Any AS endpoint URL (authorization, token, userinfo, jwks_uri,
//     introspection, revocation) advertised over plain HTTP - the
//     entire flow becomes interceptable. High.
//
// Per-host: the check fetches each well-known path at most once per
// scan, caches the result, and re-emits cached findings against
// subsequent pages on the same host with the new page URL attached so
// the report ties the finding to a page the user actually saw.
//
// Out of scope (require operator-supplied client credentials to test):
//   - state parameter validation
//   - redirect_uri strict matching
//   - end-to-end PKCE enforcement (vs. the advertised method support)
//   - actual id_token signature verification by RP
//
// These would need a real client_id and redirect_uri to drive a
// flow; the check intentionally limits itself to evidence the
// discovery document already publishes.
//
// Passive (LevelPassive) check.
type OAuthDiscovery struct {
	once  sync.Once
	mu    sync.Mutex
	cache map[string]oauthDiscoveryCacheEntry
}

// oauthDiscoveryCacheEntry memoizes the per-host probe result. A nil
// facts pointer represents a confirmed negative (well-known paths
// 404, malformed JSON, no document); a populated facts is re-used
// across every page on the host so the well-known endpoint is hit at
// most once per scan.
type oauthDiscoveryCacheEntry struct {
	facts *OAuthDiscoveryFacts
}

// OAuthDiscoveryFacts is the raw scan-facts shape the bridge returns
// to the Lua port. Mirrors the subset of the discovery document the
// audit policy actually reads plus the probe metadata needed for
// evidence rendering. The audit (alg=none, symmetric algs, PKCE
// weakness, implicit flow, plain-HTTP endpoints) lives in the .lua
// file; this struct is the algorithm output, not a finding shape.
type OAuthDiscoveryFacts struct {
	Issuer                            string
	AuthorizationEndpoint             string
	TokenEndpoint                     string
	UserinfoEndpoint                  string
	JwksURI                           string
	IntrospectionEndpoint             string
	RevocationEndpoint                string
	ResponseTypesSupported            []string
	IDTokenSigningAlgValuesSupported  []string
	TokenEndpointAuthMethodsSupported []string
	CodeChallengeMethodsSupported     []string
	ProbeURL                          string
	Status                            int
	Body                              []byte
}

const (
	// oauthDiscoveryBodyCap bounds the JSON body the check buffers.
	// Real-world OIDC discovery documents (Google, Okta, Auth0, Azure
	// AD) all land well under 16 KiB; 64 KiB clears even the
	// pathological pretty-printed cases without letting a misbehaving
	// edge pin the worker on a slow stream.
	oauthDiscoveryBodyCap = 64 << 10
)

// oauthDiscoveryPaths are the well-known suffixes the canonical
// "oidc" catalogue probes on the issuer host. The two specs share
// a path convention; both are tried because some servers expose one
// and not the other (Okta publishes OIDC discovery only, certain
// plain-OAuth-only deployments publish RFC 8414 only). Kept as a
// package-level slice so the "oidc" catalogue refers to it by
// name rather than re-defining the strings inline.
var oauthDiscoveryPaths = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
}

// oauthDiscoveryCatalogue is a named bundle of well-known paths an
// OAuth-discovery-shaped check probes per host. The Lua bridge takes
// the name as ctx.oauth.discover's first argument and resolves it
// through resolveOAuthDiscoveryCatalogue. A future check that needs
// to probe a non-standard discovery surface (a vendor-specific
// well-known suffix, an RFC-9728 OAuth-protected-resource document)
// registers its own catalogue here instead of editing the canonical
// probe path list.
type oauthDiscoveryCatalogue struct {
	paths []string
}

// oauthDiscoveryCatalogues is the named-catalogue registry. "oidc"
// covers the canonical RFC 8414 + OIDC discovery 1.0 well-known
// paths; sibling catalogues add themselves to this map and the Lua
// bridge surfaces them automatically.
var oauthDiscoveryCatalogues = map[string]oauthDiscoveryCatalogue{
	"oidc": {paths: oauthDiscoveryPaths},
}

// resolveOAuthDiscoveryCatalogue returns the named catalogue, falling
// back to "oidc" when name is empty or unknown. Same typo-tolerance
// rule resolveDiscoveryCatalogue and resolveSmugglingCatalogue use.
func resolveOAuthDiscoveryCatalogue(name string) oauthDiscoveryCatalogue {
	if cat, ok := oauthDiscoveryCatalogues[name]; ok {
		return cat
	}
	return oauthDiscoveryCatalogues["oidc"]
}

// oauthDiscoveryDoc is the subset of fields the check inspects.
// Unknown fields are ignored; the document carries dozens of values
// but only these have actionable security signal at the metadata level.
type oauthDiscoveryDoc struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// DiscoverFacts returns the cached or freshly fetched discovery facts
// for the host implied by pageURL, or nil when no well-known path
// served a parseable document. catalogue selects which registered
// well-known path bundle to probe ("oidc" for the canonical RFC
// 8414 + OIDC discovery surface); unknown names fall back to
// "oidc" via resolveOAuthDiscoveryCatalogue. Per-host cache
// lifetime matches this receiver's lifetime (one *OAuthDiscovery per
// scan registration).
//
// The Lua port reads these facts and composes the finding catalog
// itself (title / severity / detail / CWE / OWASP / remediation /
// dedupe key / evidence); the algorithm input (HTTP fetch + JSON
// parse) stays in Go so per-host work happens at most once per scan
// regardless of which implementation runs at scan time.
func (c *OAuthDiscovery) DiscoverFacts(ctx context.Context, client *httpclient.Client, sc *scope.Scope, pageURL, catalogue string) (*OAuthDiscoveryFacts, error) {
	c.once.Do(func() {
		c.cache = map[string]oauthDiscoveryCacheEntry{}
	})

	u, err := url.Parse(pageURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if !sc.Allows(u) {
		return nil, nil
	}
	hostKey := strings.ToLower(u.Scheme + "://" + u.Host)

	c.mu.Lock()
	entry, cached := c.cache[hostKey]
	c.mu.Unlock()
	if cached {
		return entry.facts, nil
	}

	facts := c.probeHost(ctx, client, sc, u, resolveOAuthDiscoveryCatalogue(catalogue))
	c.mu.Lock()
	c.cache[hostKey] = oauthDiscoveryCacheEntry{facts: facts}
	c.mu.Unlock()
	return facts, nil
}

// probeHost fetches each well-known path in the resolved catalogue
// against u's host until one returns a parseable discovery document.
// Returns the parsed facts, or nil if no path was reachable /
// parseable.
func (c *OAuthDiscovery) probeHost(ctx context.Context, client *httpclient.Client, sc *scope.Scope, u *url.URL, cat oauthDiscoveryCatalogue) *OAuthDiscoveryFacts {
	base := u.Scheme + "://" + u.Host
	for _, path := range cat.paths {
		probeURL := base + path
		probeU, err := url.Parse(probeURL)
		if err != nil {
			continue
		}
		if !sc.Allows(probeU) {
			continue
		}
		doc, status, body, ok := c.fetchDoc(ctx, client, probeURL)
		if !ok {
			continue
		}
		return &OAuthDiscoveryFacts{
			Issuer:                            doc.Issuer,
			AuthorizationEndpoint:             doc.AuthorizationEndpoint,
			TokenEndpoint:                     doc.TokenEndpoint,
			UserinfoEndpoint:                  doc.UserinfoEndpoint,
			JwksURI:                           doc.JwksURI,
			IntrospectionEndpoint:             doc.IntrospectionEndpoint,
			RevocationEndpoint:                doc.RevocationEndpoint,
			ResponseTypesSupported:            doc.ResponseTypesSupported,
			IDTokenSigningAlgValuesSupported:  doc.IDTokenSigningAlgValuesSupported,
			TokenEndpointAuthMethodsSupported: doc.TokenEndpointAuthMethodsSupported,
			CodeChallengeMethodsSupported:     doc.CodeChallengeMethodsSupported,
			ProbeURL:                          probeURL,
			Status:                            status,
			Body:                              body,
		}
	}
	return nil
}

// fetchDoc GETs probeURL and parses the body as an OIDC / OAuth
// discovery document. Returns ok=false on transport error, non-200,
// non-JSON, or a JSON object that does not carry the issuer field
// (the one MUST in both specs - its presence confirms we hit a real
// metadata document rather than a generic JSON 404).
func (c *OAuthDiscovery) fetchDoc(ctx context.Context, client *httpclient.Client, probeURL string) (*oauthDiscoveryDoc, int, []byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, 0, nil, false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, 0, nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain a small chunk to release the connection cleanly. We
		// don't surface non-200 as an error - both well-known paths
		// are expected to 404 on non-IdP hosts.
		_, _, _ = httpclient.ReadBodyCapped(resp, 1<<10)
		return nil, resp.StatusCode, nil, false
	}
	body, _, err := httpclient.ReadBodyCapped(resp, oauthDiscoveryBodyCap)
	if err != nil {
		return nil, resp.StatusCode, nil, false
	}
	var doc oauthDiscoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, resp.StatusCode, nil, false
	}
	if doc.Issuer == "" {
		// The issuer claim is REQUIRED in both RFC 8414 and OIDC
		// Discovery. A "document" without it is almost certainly a
		// generic JSON 404 / WAF interstitial; treat it as a miss
		// rather than emit findings against fabricated nil-array
		// values.
		return nil, resp.StatusCode, nil, false
	}
	return &doc, resp.StatusCode, body, true
}
