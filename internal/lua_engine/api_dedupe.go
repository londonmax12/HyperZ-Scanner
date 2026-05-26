package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// buildDedupeTable returns the ctx.dedupe helper namespace. dedupe
// fingerprints are how the report collapses repeat observations of
// the same issue across crawled pages; the Lua surface intentionally
// mirrors the Go MakeKey shape so a check author can pick the same
// scope tag (host / page / param) they would in Go.
//
// Two entry points are exposed:
//
//	ctx.dedupe.key{ check=name, scope="host", target=url, parts={...} }
//	  -- Explicit construction. Useful when a check wants a key for
//	     something other than its own findings (cross-check stitching).
//
//	ctx.dedupe.host_scope(url)
//	  -- The bare "scheme://host" string. Useful for log lines and
//	     per-host caches the check builds itself.
//
// Findings can also declare `dedupe_parts = {...}` directly on a
// finding table; the marshal path then builds the key with the
// check's own metadata (name + default scope). Authors only need to
// call ctx.dedupe.key directly when they want to override the scope
// for a specific finding.
func buildDedupeTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("key", L.NewFunction(dedupeKey))
	t.RawSetString("host_scope", L.NewFunction(dedupeHostScope))
	return t
}

func dedupeKey(L *lua.LState) int {
	opts := L.CheckTable(1)
	name := lvalString(opts.RawGetString("check"))
	if name == "" {
		L.ArgError(1, "dedupe.key: missing required field `check`")
	}
	target := lvalString(opts.RawGetString("target"))
	if target == "" {
		L.ArgError(1, "dedupe.key: missing required field `target`")
	}
	scopeStr := lvalString(opts.RawGetString("scope"))
	if scopeStr == "" {
		scopeStr = "page"
	}
	sc, err := parseScope(scopeStr)
	if err != nil {
		L.ArgError(1, err.Error())
	}
	parts := stringList(opts, "parts")
	L.Push(lua.LString(MakeKey(name, sc, target, parts...)))
	return 1
}

func dedupeHostScope(L *lua.LState) int {
	raw := requireString(L, 1)
	L.Push(lua.LString(HostScope(raw)))
	return 1
}
