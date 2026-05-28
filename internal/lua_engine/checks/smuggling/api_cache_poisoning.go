package smuggling

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// buildCachePoisoningTable returns the ctx.cache_poisoning helper
// namespace - one bucket per check family, just like the rest of the
// per-family ctx layout. The cache-poisoning check is the only consumer
// of these helpers; putting them under their own namespace (rather than
// ctx.smuggling alongside the request-smuggling scanner) keeps the two
// surfaces independent and matches the .lua filename.
//
// Entry points:
//
//	ctx.cache_poisoning.has_cache_hint(headers)
//	ctx.cache_poisoning.find_reflection(needle, headers, body, baseline)
//	ctx.cache_poisoning.response_diverged(status, body, base_status, base_body)
//	ctx.cache_poisoning.bodies_match(a, b)
//	ctx.cache_poisoning.cc_forbids_storage(cache_control)
//	ctx.cache_poisoning.is_auth_likely_path(path)
//	ctx.cache_poisoning.deception_url(target)
//	ctx.cache_poisoning.parse_vary(vary_header)
//	ctx.cache_poisoning.probe_url(target)
//	ctx.cache_poisoning.header_probes() -> array
//	ctx.cache_poisoning.deception_suffix() -> string
//	ctx.cache_poisoning.canary_host() -> string
//	ctx.cache_poisoning.canary_path() -> string
func buildCachePoisoningTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("has_cache_hint", L.NewFunction(cachePoisonHasCacheHint))
	t.RawSetString("find_reflection", L.NewFunction(cachePoisonFindReflection))
	t.RawSetString("response_diverged", L.NewFunction(cachePoisonResponseDiverged))
	t.RawSetString("bodies_match", L.NewFunction(cachePoisonBodiesMatch))
	t.RawSetString("cc_forbids_storage", L.NewFunction(cachePoisonCCForbidsStorage))
	t.RawSetString("is_auth_likely_path", L.NewFunction(cachePoisonIsAuthLikelyPath))
	t.RawSetString("deception_url", L.NewFunction(cachePoisonDeceptionURLFn))
	t.RawSetString("parse_vary", L.NewFunction(cachePoisonParseVaryFn))
	t.RawSetString("probe_url", L.NewFunction(cachePoisonProbeURLFn))
	t.RawSetString("header_probes", L.NewFunction(cachePoisonHeaderProbesFn))
	t.RawSetString("deception_suffix", L.NewFunction(cachePoisonDeceptionSuffixFn))
	t.RawSetString("canary_host", L.NewFunction(cachePoisonCanaryHostFn))
	t.RawSetString("canary_path", L.NewFunction(cachePoisonCanaryPathFn))
	return t
}

func cachePoisonHasCacheHint(L *lua.LState) int {
	h, _ := lua_engine.UnwrapHeaders(L.Get(1))
	L.Push(lua.LBool(CachePoisonHasCacheHint(h)))
	return 1
}

func cachePoisonFindReflection(L *lua.LState) int {
	needle := lua_engine.RequireString(L, 1)
	headers, _ := lua_engine.UnwrapHeaders(L.Get(2))
	body := lua_engine.RequireString(L, 3)
	baseline := lua_engine.OptString(L, 4, "")
	where, ok := CachePoisonFindReflection(needle, headers, []byte(body), []byte(baseline))
	L.Push(lua.LString(where))
	L.Push(lua.LBool(ok))
	return 2
}

func cachePoisonResponseDiverged(L *lua.LState) int {
	status := L.CheckInt(1)
	body := lua_engine.RequireString(L, 2)
	baseStatus := L.CheckInt(3)
	baseBody := lua_engine.OptString(L, 4, "")
	L.Push(lua.LBool(CachePoisonResponseDiverged(status, []byte(body), baseStatus, []byte(baseBody))))
	return 1
}

func cachePoisonBodiesMatch(L *lua.LState) int {
	a := lua_engine.RequireString(L, 1)
	b := lua_engine.RequireString(L, 2)
	L.Push(lua.LBool(CachePoisonBodiesMatch([]byte(a), []byte(b))))
	return 1
}

func cachePoisonCCForbidsStorage(L *lua.LState) int {
	L.Push(lua.LBool(CachePoisonCacheControlForbidsStorage(lua_engine.RequireString(L, 1))))
	return 1
}

func cachePoisonIsAuthLikelyPath(L *lua.LState) int {
	L.Push(lua.LBool(CachePoisonIsAuthLikelyPath(lua_engine.RequireString(L, 1))))
	return 1
}

func cachePoisonDeceptionURLFn(L *lua.LState) int {
	out, err := CachePoisonDeceptionURL(lua_engine.RequireString(L, 1))
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(out))
	return 1
}

func cachePoisonParseVaryFn(L *lua.LState) int {
	L.Push(lua_engine.PushStringList(L, CachePoisonParseVary(lua_engine.RequireString(L, 1))))
	return 1
}

func cachePoisonProbeURLFn(L *lua.LState) int {
	out, err := CachePoisonProbeURL(lua_engine.RequireString(L, 1))
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(out))
	return 1
}

func cachePoisonHeaderProbesFn(L *lua.LState) int {
	src := CachePoisonHeaderProbesLua()
	out := L.NewTable()
	for i, h := range src {
		entry := L.NewTable()
		entry.RawSetString("header", lua.LString(h.Header))
		entry.RawSetString("value", lua.LString(h.Value))
		entry.RawSetString("canary", lua.LString(h.Canary))
		entry.RawSetString("kind", lua.LString(h.Kind))
		entry.RawSetString("deception_message", lua.LString(h.DeceptionMessage))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func cachePoisonDeceptionSuffixFn(L *lua.LState) int {
	L.Push(lua.LString(CachePoisonDeceptionSuffix()))
	return 1
}

func cachePoisonCanaryHostFn(L *lua.LState) int {
	L.Push(lua.LString(CachePoisonCanaryHost()))
	return 1
}

func cachePoisonCanaryPathFn(L *lua.LState) int {
	L.Push(lua.LString(CachePoisonCanaryPath()))
	return 1
}

func init() {
	lua_engine.RegisterHelperTable("cache_poisoning", buildCachePoisoningTable)
}
