package luabridge

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/checks"
)

// buildOpenAPITable returns the ctx.openapi helper namespace. Two
// entry points:
//
//	ctx.openapi.discover(page_url)
//	  Resolves the host implied by page_url, walks the curated list
//	  of well-known OpenAPI / Swagger paths, and returns the first
//	  probe whose body looks like a real spec. Per-host caching lives
//	  on the receiver via AuxOrCreate so a 50-page crawl probes the
//	  well-known endpoints at most once. Returns nil for the clean
//	  path; (nil, err_string) on transport failure.
//
//	ctx.openapi.scan_example_auth_matches(body)
//	  Walks body for Bearer / Basic values that sit next to an
//	  OpenAPI example / default / value key. Regex + nearby-context
//	  window stay in Go because gopher-lua's pattern library cannot
//	  express the lookbehind; the .lua port owns dedup, sort, severity,
//	  and finding-shape composition.
//
// All operator-visible catalog metadata (title / severity / detail /
// CWE / OWASP / remediation / dedupe key / evidence) is composed in
// openapi_audit.lua; this helper deliberately returns only the raw
// document bytes and the raw regex hit list, mirroring the pattern set
// by ctx.oauth.discover.
func buildOpenAPITable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("discover", L.NewFunction(openapiDiscover))
	t.RawSetString("scan_example_auth_matches", L.NewFunction(openapiScanExampleAuthMatches))
	return t
}

// openapiEvaluatorKey identifies the per-LuaCheck slot the
// *checks.OpenAPIAudit evaluator lives in. Unique zero-size type so
// two helpers cannot collide on AuxOrCreate key equality.
type openapiEvaluatorKey struct{}

func openapiDiscover(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("ctx.openapi.discover called outside a check run")
	}
	pageURL := requireString(L, 1)
	eval := env.check.AuxOrCreate(openapiEvaluatorKey{}, func() any {
		return &checks.OpenAPIAudit{}
	}).(*checks.OpenAPIAudit)
	facts, err := eval.DiscoverFacts(env.ctx, env.client, env.scope, pageURL)
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
	out.RawSetString("probe_url", lua.LString(facts.ProbeURL))
	out.RawSetString("status", lua.LNumber(facts.Status))
	out.RawSetString("body", lua.LString(string(facts.Body)))
	L.Push(out)
	return 1
}

// openapiScanExampleAuthMatches returns the Bearer / Basic example
// values present in body, in document order, after the
// example/default/value-context filter has been applied. Each entry is
// { scheme, raw, redacted } so the Lua port can dedupe / sort / render
// without touching the redaction helper itself.
func openapiScanExampleAuthMatches(L *lua.LState) int {
	body := requireString(L, 1)
	hits := checks.OpenAPIScanExampleAuthMatches([]byte(body))
	out := L.NewTable()
	for i, h := range hits {
		entry := L.NewTable()
		entry.RawSetString("scheme", lua.LString(h.Scheme))
		entry.RawSetString("raw", lua.LString(h.Raw))
		entry.RawSetString("redacted", lua.LString(h.Redacted))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}
