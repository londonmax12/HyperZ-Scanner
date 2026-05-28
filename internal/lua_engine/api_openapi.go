package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// buildOpenAPITable returns the ctx.openapi helper namespace. Three
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
//	ctx.openapi.scan_security_facts(body)
//	  Parses body as a JSON spec and returns only the security-
//	  relevant subset (declares_security, global_required, operations
//	  with their security flags). The narrow Go-side struct keeps
//	  encoding/json from allocating any field outside that subset,
//	  avoiding the O(spec size) Lua-table explosion ctx.json.decode
//	  would otherwise cause on a multi-MiB spec.
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
	t.RawSetString("scan_security_facts", L.NewFunction(openapiScanSecurityFacts))
	return t
}

// openapiEvaluatorKey identifies the per-LuaCheck slot the
// *OpenAPIAudit evaluator lives in. Unique zero-size type so
// two helpers cannot collide on AuxOrCreate key equality.
type openapiEvaluatorKey struct{}

func openapiDiscover(L *lua.LState) int {
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.openapi.discover called outside a check run")
	}
	pageURL := RequireString(L, 1)
	eval := env.Check.AuxOrCreate(openapiEvaluatorKey{}, func() any {
		return &OpenAPIAudit{}
	}).(*OpenAPIAudit)
	facts, err := eval.DiscoverFacts(env.Ctx, env.Client, env.Scope, pageURL)
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
	body := RequireString(L, 1)
	hits := OpenAPIScanExampleAuthMatches([]byte(body))
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

// openapiScanSecurityFacts returns the security-relevant subset of
// body as a Lua table. Shape:
//
//	{
//	  declares_security = bool,
//	  global_required   = bool,
//	  operations = {
//	    { method, path, has_security, required }, ...
//	  },
//	}
//
// Returns nil when body isn't a parseable JSON object - the Lua port
// treats that the same way the Go check does (skip the authless pass
// for non-JSON / malformed bodies, the other passes still run on the
// raw bytes). The whole point of this helper is to keep the .lua
// port from calling ctx.json.decode on a multi-MiB spec just to read
// four fields.
func openapiScanSecurityFacts(L *lua.LState) int {
	body := RequireString(L, 1)
	facts := OpenAPIScanSecurityFacts([]byte(body))
	if facts == nil {
		L.Push(lua.LNil)
		return 1
	}
	out := L.NewTable()
	out.RawSetString("declares_security", lua.LBool(facts.DeclaresSecurity))
	out.RawSetString("global_required", lua.LBool(facts.GlobalRequired))
	ops := L.NewTable()
	for i, op := range facts.Operations {
		entry := L.NewTable()
		entry.RawSetString("method", lua.LString(op.Method))
		entry.RawSetString("path", lua.LString(op.Path))
		entry.RawSetString("has_security", lua.LBool(op.HasSecurity))
		entry.RawSetString("required", lua.LBool(op.Required))
		ops.RawSetInt(i+1, entry)
	}
	out.RawSetString("operations", ops)
	L.Push(out)
	return 1
}

func init() {
	RegisterHelperTable("openapi", buildOpenAPITable)
}
