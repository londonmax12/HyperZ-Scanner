package lua_engine

import (
	"context"
	"encoding/json"
	"fmt"
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

// oauthDiscoveryPaths are the well-known suffixes the check probes on
// the issuer host. The two specs share a path convention; both are
// tried because some servers expose one and not the other (Okta
// publishes OIDC discovery only, certain plain-OAuth-only deployments
// publish RFC 8414 only).
var oauthDiscoveryPaths = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
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
// served a parseable document. Per-host cache lifetime matches this
// receiver's lifetime (one *OAuthDiscovery per scan registration).
//
// The Lua port reads these facts and composes the finding catalog
// itself (title / severity / detail / CWE / OWASP / remediation /
// dedupe key / evidence); the algorithm input (HTTP fetch + JSON
// parse) stays in Go so per-host work happens at most once per scan
// regardless of which implementation runs at scan time.
func (c *OAuthDiscovery) DiscoverFacts(ctx context.Context, client *httpclient.Client, sc *scope.Scope, pageURL string) (*OAuthDiscoveryFacts, error) {
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

	facts := c.probeHost(ctx, client, sc, u)
	c.mu.Lock()
	c.cache[hostKey] = oauthDiscoveryCacheEntry{facts: facts}
	c.mu.Unlock()
	return facts, nil
}

// probeHost fetches each well-known path on u's host until one returns
// a parseable discovery document. Returns the parsed facts, or nil if
// no path was reachable / parseable.
func (c *OAuthDiscovery) probeHost(ctx context.Context, client *httpclient.Client, sc *scope.Scope, u *url.URL) *OAuthDiscoveryFacts {
	base := u.Scheme + "://" + u.Host
	for _, path := range oauthDiscoveryPaths {
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

// auditDoc walks the parsed discovery facts and emits one finding
// per detected weakness. Each finding carries the probe URL and the
// raw document snippet for evidence so the report can show exactly
// which advertised value tripped the rule.
func (c *OAuthDiscovery) auditDoc(f *OAuthDiscoveryFacts) []Finding {
	var out []Finding

	algs := lowerSet(f.IDTokenSigningAlgValuesSupported)
	if _, ok := algs["none"]; ok {
		out = append(out, c.findingAlgNone(f))
	}
	if symAlgs := symmetricAlgs(algs); len(symAlgs) > 0 {
		out = append(out, c.findingSymmetricAlg(f, symAlgs))
	}

	authMethods := lowerSet(f.TokenEndpointAuthMethodsSupported)
	if len(authMethods) > 0 && onlyContains(authMethods, "none") {
		out = append(out, c.findingTokenEndpointAuthNone(f))
	}

	pkceMethods := lowerSet(f.CodeChallengeMethodsSupported)
	if pkceWeak := pkceWeakness(pkceMethods); pkceWeak != "" {
		out = append(out, c.findingPKCEWeak(f, pkceWeak))
	}

	respTypes := lowerSet(f.ResponseTypesSupported)
	if implicitTypes := implicitFlowTypes(respTypes); len(implicitTypes) > 0 {
		out = append(out, c.findingImplicitFlow(f, implicitTypes))
	}

	if plain := plainHTTPEndpointsFromFacts(f); len(plain) > 0 {
		out = append(out, c.findingPlainHTTPEndpoint(f, plain))
	}

	return out
}

// findingAlgNone reports id_token_signing_alg_values_supported
// containing "none". This is the strongest signal the discovery
// document can produce - an AS that advertises alg=none is announcing
// it will accept (and possibly issue) unsigned tokens, which makes
// every id_token-consuming RP forgeable.
func (c *OAuthDiscovery) findingAlgNone(f *OAuthDiscoveryFacts) Finding {
	return Finding{
		Check:    "oauth-discovery",
		Target:   f.ProbeURL,
		URL:      f.ProbeURL,
		Severity: SeverityCritical,
		Title:    "OAuth/OIDC discovery advertises alg=none for id_token",
		Detail: fmt.Sprintf(
			"The authorization server at %s lists \"none\" in id_token_signing_alg_values_supported "+
				"(values: %v). An RP that pins acceptable algorithms against the advertised set will accept "+
				"unsigned id_tokens, letting any caller forge claims by sending an alg=none token with an empty "+
				"signature. The vulnerability lives in every RP that trusts this AS, not just one client.",
			f.Issuer, f.IDTokenSigningAlgValuesSupported),
		CWE:   "CWE-327",
		OWASP: "A02:2021 Cryptographic Failures",
		Remediation: "Remove \"none\" from id_token_signing_alg_values_supported. There is no production use case " +
			"for unsigned id_tokens; an unsigned token provides no integrity guarantee and an attacker can substitute " +
			"arbitrary claims. Configure the AS to advertise only asymmetric algorithms (RS256, ES256, EdDSA) and " +
			"reissue rotated keys via jwks_uri.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: f.ProbeURL,
			Status:     f.Status,
			Snippet:    snippetJSON(f.Body),
		},
		DedupeKey: MakeKey("oauth-discovery", ScopeHost, f.ProbeURL, "alg-none"),
	}
}

// findingSymmetricAlg reports HS-family algorithms in the advertised
// set. Symmetric signing means the AS and every RP that verifies
// id_tokens share the same secret, which scales poorly across
// federations and makes one RP's compromise everyone's compromise.
func (c *OAuthDiscovery) findingSymmetricAlg(f *OAuthDiscoveryFacts, symAlgs []string) Finding {
	return Finding{
		Check:    "oauth-discovery",
		Target:   f.ProbeURL,
		URL:      f.ProbeURL,
		Severity: SeverityMedium,
		Title:    "OAuth/OIDC discovery advertises symmetric id_token signing",
		Detail: fmt.Sprintf(
			"The authorization server at %s advertises symmetric id_token signing algorithms (%v) in "+
				"id_token_signing_alg_values_supported. Symmetric algorithms require the AS and every relying party "+
				"to share the same secret to verify tokens, so one RP's secret compromise lets that RP forge tokens "+
				"any other RP will accept. The OIDC core spec deprecated HS* outside narrow same-trust-domain "+
				"deployments for this reason.",
			f.Issuer, symAlgs),
		CWE:   "CWE-327",
		OWASP: "A02:2021 Cryptographic Failures",
		Remediation: "Migrate to asymmetric id_token signing (RS256, ES256, EdDSA). Publish the public key via " +
			"jwks_uri so RPs verify against a key only the AS holds the private half of. If a symmetric algorithm " +
			"must remain for a legacy client, advertise it only for that client's audience rather than as a server-" +
			"wide capability.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: f.ProbeURL,
			Status:     f.Status,
			Snippet:    snippetJSON(f.Body),
		},
		DedupeKey: MakeKey("oauth-discovery", ScopeHost, f.ProbeURL, "symmetric-alg"),
	}
}

// findingTokenEndpointAuthNone reports a token endpoint whose only
// advertised client-auth method is "none". This means every public
// client (e.g. a SPA holding a stolen code) can mint tokens; per-
// client secrets and assertion methods are not offered at all.
func (c *OAuthDiscovery) findingTokenEndpointAuthNone(f *OAuthDiscoveryFacts) Finding {
	return Finding{
		Check:    "oauth-discovery",
		Target:   f.ProbeURL,
		URL:      f.ProbeURL,
		Severity: SeverityHigh,
		Title:    "OAuth/OIDC token endpoint accepts only unauthenticated clients",
		Detail: fmt.Sprintf(
			"The authorization server at %s advertises only \"none\" in token_endpoint_auth_methods_supported. "+
				"That means the token endpoint will mint tokens for any caller presenting a valid authorization code "+
				"without verifying client identity, so an attacker who intercepts a code can trade it for tokens "+
				"indistinguishably from the legitimate client. Confidential clients become impossible against this AS.",
			f.Issuer),
		CWE:   "CWE-287",
		OWASP: "A07:2021 Identification and Authentication Failures",
		Remediation: "Configure the AS to support a real client-auth method for confidential clients " +
			"(client_secret_basic, client_secret_post, private_key_jwt). Reserve token_endpoint_auth_method=none " +
			"for public clients (SPAs, native apps) that pair it with PKCE; even then, confidential clients should " +
			"have a stronger option available.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: f.ProbeURL,
			Status:     f.Status,
			Snippet:    snippetJSON(f.Body),
		},
		DedupeKey: MakeKey("oauth-discovery", ScopeHost, f.ProbeURL, "token-auth-none"),
	}
}

// findingPKCEWeak reports a missing or weak PKCE configuration:
// either code_challenge_methods_supported is absent entirely (PKCE
// not advertised) or only "plain" is offered (a no-op transformation
// that gives a code interceptor the verifier directly).
func (c *OAuthDiscovery) findingPKCEWeak(f *OAuthDiscoveryFacts, weakness string) Finding {
	return Finding{
		Check:    "oauth-discovery",
		Target:   f.ProbeURL,
		URL:      f.ProbeURL,
		Severity: SeverityMedium,
		Title:    "OAuth/OIDC discovery advertises weak or absent PKCE support",
		Detail: fmt.Sprintf(
			"The authorization server at %s %s. PKCE binds an authorization code to the client that requested it, "+
				"preventing an interceptor of the code from trading it for tokens. Without S256 enforcement, public "+
				"clients (SPAs, native apps) fall back to bearer-style code exchange and any party who reads the "+
				"redirect URL can complete the flow.",
			f.Issuer, weakness),
		CWE:   "CWE-287",
		OWASP: "A07:2021 Identification and Authentication Failures",
		Remediation: "Advertise S256 in code_challenge_methods_supported and reject authorization requests without " +
			"a code_challenge parameter for public clients. OAuth 2.1 and FAPI 2.0 mandate PKCE with S256; legacy " +
			"\"plain\" support should be removed since it provides no protection against a code interceptor.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: f.ProbeURL,
			Status:     f.Status,
			Snippet:    snippetJSON(f.Body),
		},
		DedupeKey: MakeKey("oauth-discovery", ScopeHost, f.ProbeURL, "pkce-weak"),
	}
}

// findingImplicitFlow reports advertised response_types that
// correspond to the implicit flow (token / id_token / id_token token).
// The implicit flow leaks tokens via URL fragments and is deprecated
// by OAuth 2.1 / OIDC's "implicit considered harmful" guidance.
func (c *OAuthDiscovery) findingImplicitFlow(f *OAuthDiscoveryFacts, types []string) Finding {
	return Finding{
		Check:    "oauth-discovery",
		Target:   f.ProbeURL,
		URL:      f.ProbeURL,
		Severity: SeverityLow,
		Title:    "OAuth/OIDC discovery advertises deprecated implicit flow",
		Detail: fmt.Sprintf(
			"The authorization server at %s advertises implicit-flow response types (%v) in "+
				"response_types_supported. The implicit flow lands access tokens (and sometimes id_tokens) in the "+
				"URL fragment, where they leak through browser history, server access logs, the Referer header, and "+
				"document.location. OAuth 2.1 and the OIDC \"implicit considered harmful\" guidance recommend the "+
				"authorization code flow with PKCE for every client shape that previously used implicit.",
			f.Issuer, types),
		CWE:   "CWE-598",
		OWASP: "A04:2021 Insecure Design",
		Remediation: "Stop advertising implicit response types. Migrate SPA / native clients to authorization code " +
			"flow with PKCE, which keeps tokens out of the URL and supports refresh tokens. If a client cannot be " +
			"migrated immediately, scope the deprecation to that client's metadata rather than as a server-wide " +
			"capability.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: f.ProbeURL,
			Status:     f.Status,
			Snippet:    snippetJSON(f.Body),
		},
		DedupeKey: MakeKey("oauth-discovery", ScopeHost, f.ProbeURL, "implicit-flow"),
	}
}

// findingPlainHTTPEndpoint reports advertised endpoint URLs over
// plain HTTP. The OAuth flow becomes interceptable end-to-end at
// these endpoints regardless of how strong the rest of the
// configuration is.
func (c *OAuthDiscovery) findingPlainHTTPEndpoint(f *OAuthDiscoveryFacts, endpoints []string) Finding {
	return Finding{
		Check:    "oauth-discovery",
		Target:   f.ProbeURL,
		URL:      f.ProbeURL,
		Severity: SeverityHigh,
		Title:    "OAuth/OIDC discovery advertises endpoints over plain HTTP",
		Detail: fmt.Sprintf(
			"The authorization server at %s advertises one or more endpoints over plain HTTP (%v). Any caller "+
				"on the network between the user agent and the AS can read or rewrite the authorization request, "+
				"the code exchange, or the userinfo response. OAuth 2.0 (RFC 6749) and OIDC core both require TLS "+
				"on every endpoint in the flow.",
			f.Issuer, endpoints),
		CWE:   "CWE-319",
		OWASP: "A02:2021 Cryptographic Failures",
		Remediation: "Serve every OAuth / OIDC endpoint over HTTPS and update the discovery document so the " +
			"published URLs match. If the AS is behind a TLS-terminating proxy, ensure the metadata advertises the " +
			"external HTTPS URL rather than the internal HTTP one.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: f.ProbeURL,
			Status:     f.Status,
			Snippet:    snippetJSON(f.Body),
		},
		DedupeKey: MakeKey("oauth-discovery", ScopeHost, f.ProbeURL, "plain-http"),
	}
}

// lowerSet returns a case-folded set of the input slice. Used to
// match advertised values without case sensitivity since OIDC
// discovery values are conventionally lowercase but the spec does
// not require it.
func lowerSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
	}
	return out
}

// onlyContains returns true when set is non-empty and every element
// equals want. Used for "only none" style checks where a value mixed
// with stronger alternatives is not a finding.
func onlyContains(set map[string]struct{}, want string) bool {
	if len(set) == 0 {
		return false
	}
	for k := range set {
		if k != want {
			return false
		}
	}
	return true
}

// symmetricAlgs returns the HMAC family algorithms present in algs.
// HS256/HS384/HS512 are the JWS-defined symmetric options; any
// non-empty return triggers the symmetric-alg finding.
func symmetricAlgs(algs map[string]struct{}) []string {
	var out []string
	for _, candidate := range []string{"hs256", "hs384", "hs512"} {
		if _, ok := algs[candidate]; ok {
			out = append(out, strings.ToUpper(candidate))
		}
	}
	return out
}

// pkceWeakness returns a human-readable description of the PKCE
// weakness present in the advertised methods, or empty when PKCE is
// configured correctly (S256 advertised).
func pkceWeakness(methods map[string]struct{}) string {
	if len(methods) == 0 {
		return "does not advertise code_challenge_methods_supported, so PKCE is not announced as a capability"
	}
	if _, hasS256 := methods["s256"]; hasS256 {
		return ""
	}
	if _, hasPlain := methods["plain"]; hasPlain {
		return "advertises only \"plain\" in code_challenge_methods_supported, which provides no protection against a code interceptor"
	}
	return "advertises code_challenge_methods_supported without S256"
}

// implicitFlowTypes returns the response_types entries that
// correspond to the implicit flow. response_types containing only
// "code" is the authorization code flow and is not flagged.
func implicitFlowTypes(types map[string]struct{}) []string {
	var out []string
	// Each implicit-flow shape: token, id_token, and the hybrid
	// id_token+token. "code id_token" is a hybrid that includes the
	// code path and isn't strictly implicit, but the fragment leak
	// applies whenever id_token rides in the URL response, so it
	// gets flagged too.
	for _, rt := range []string{"token", "id_token", "id_token token", "token id_token"} {
		if _, ok := types[rt]; ok {
			out = append(out, rt)
		}
	}
	return out
}

// plainHTTPEndpointsFromFacts returns the names of advertised
// endpoint fields whose URL is plain HTTP rather than HTTPS. Empty
// endpoints are skipped (a missing optional endpoint is not a finding
// here). Accepts the bridge-shared facts struct so both Go and Lua
// paths see the same endpoint roster without two policies drifting.
func plainHTTPEndpointsFromFacts(f *OAuthDiscoveryFacts) []string {
	var out []string
	check := func(label, raw string) {
		if raw == "" {
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		if strings.EqualFold(u.Scheme, "http") {
			out = append(out, label+"="+raw)
		}
	}
	check("authorization_endpoint", f.AuthorizationEndpoint)
	check("token_endpoint", f.TokenEndpoint)
	check("userinfo_endpoint", f.UserinfoEndpoint)
	check("jwks_uri", f.JwksURI)
	check("introspection_endpoint", f.IntrospectionEndpoint)
	check("revocation_endpoint", f.RevocationEndpoint)
	return out
}

// restampFindings returns a copy of in with Target and URL set to
// pageURL. The findings carry the discovery URL as their target; this
// re-emits them against the actual page the user saw so the report
// ties the finding to a meaningful URL while keeping the per-host
// dedupe key intact.
func restampFindings(in []Finding, pageURL string) []Finding {
	if len(in) == 0 {
		return nil
	}
	out := make([]Finding, len(in))
	copy(out, in)
	for i := range out {
		out[i].Target = pageURL
		out[i].URL = pageURL
	}
	return out
}
