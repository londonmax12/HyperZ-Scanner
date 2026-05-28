package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// buildOAuthTable returns the ctx.oauth helper namespace. The single
// entry point - discover(catalogue, page_url) - resolves the issuer
// host implied by page_url, fetches the discovery document at every
// well-known path in the named catalogue ("oidc" covers RFC 8414
// + OIDC discovery 1.0), and returns the raw scan facts (parsed doc
// fields plus probe URL / status / body) so the .lua port can run
// the audit policy itself. Per-host caching lives on the receiver
// via AuxOrCreate so a 50-page crawl probes the well-known endpoint
// once.
//
// All operator-visible catalog metadata (title / severity / detail /
// CWE / OWASP / remediation / dedupe key / evidence) is composed in
// oauth_discovery.lua; this helper deliberately returns only the raw
// document fields, mirroring the pattern set by ctx.takeover.evaluate.
func buildOAuthTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("discover", L.NewFunction(oauthDiscover))
	return t
}

// oauthEvaluatorKey identifies the per-LuaCheck slot the
// *OAuthDiscovery evaluator lives in. Unique zero-size type so
// two helpers cannot collide on AuxOrCreate key equality.
type oauthEvaluatorKey struct{}

// oauthDiscover implements ctx.oauth.discover(catalogue, page_url).
// Returns nil when the host has no parseable discovery document
// (the clean path - not an error). On transport failure returns
// (nil, err_string) so the .lua port can surface it via ctx:report.
func oauthDiscover(L *lua.LState) int {
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.oauth.discover called outside a check run")
	}
	catalogue := RequireString(L, 1)
	pageURL := RequireString(L, 2)
	eval := env.Check.AuxOrCreate(oauthEvaluatorKey{}, func() any {
		return &OAuthDiscovery{}
	}).(*OAuthDiscovery)
	facts, err := eval.DiscoverFacts(env.Ctx, env.Client, env.Scope, pageURL, catalogue)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	if facts == nil {
		L.Push(lua.LNil)
		return 1
	}

	out := L.NewTable()
	out.RawSetString("issuer", lua.LString(facts.Issuer))
	out.RawSetString("authorization_endpoint", lua.LString(facts.AuthorizationEndpoint))
	out.RawSetString("token_endpoint", lua.LString(facts.TokenEndpoint))
	out.RawSetString("userinfo_endpoint", lua.LString(facts.UserinfoEndpoint))
	out.RawSetString("jwks_uri", lua.LString(facts.JwksURI))
	out.RawSetString("introspection_endpoint", lua.LString(facts.IntrospectionEndpoint))
	out.RawSetString("revocation_endpoint", lua.LString(facts.RevocationEndpoint))
	out.RawSetString("response_types_supported", pushStringList(L, facts.ResponseTypesSupported))
	out.RawSetString("id_token_signing_alg_values_supported", pushStringList(L, facts.IDTokenSigningAlgValuesSupported))
	out.RawSetString("token_endpoint_auth_methods_supported", pushStringList(L, facts.TokenEndpointAuthMethodsSupported))
	out.RawSetString("code_challenge_methods_supported", pushStringList(L, facts.CodeChallengeMethodsSupported))
	out.RawSetString("probe_url", lua.LString(facts.ProbeURL))
	out.RawSetString("status", lua.LNumber(facts.Status))
	out.RawSetString("body", lua.LString(string(facts.Body)))

	L.Push(out)
	return 1
}

func init() {
	RegisterHelperTable("oauth", buildOAuthTable)
}
