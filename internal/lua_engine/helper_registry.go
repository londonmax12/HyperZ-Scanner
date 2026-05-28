package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// helperTableBuilder constructs one ctx-side helper table on the given
// VM. Each api_*.go registers exactly one builder under the Lua-side
// namespace name (e.g. "evidence", "stored_xss") in its init(). The
// registry is the single source of truth for which namespaces are
// installed on ctx; bindHyperzAPI iterates it at VM creation, and
// buildCtxUserdata reads back the built tables when assembling the
// per-Run ctx.
//
// Using a registry rather than a central hardcoded list lets a future
// subpackage extract (each subpackage's init() registers its own
// helpers without an import-cycle back into engine).
type helperTableBuilder func(*lua.LState) *lua.LTable

// helperTableExtender adds entries to an already-built helper table.
// Per-check subpackages register extenders to contribute family-specific
// entries (e.g. ssrf_canary, cmd_injection_filler_value) to the root-
// owned shared namespaces (payloads, body, url, ...) without forcing
// the root package to import its own children, which would cycle. Run
// after every builder in bindHyperzAPI so the table the extender sees
// already has the root entries on it.
type helperTableExtender func(*lua.LState, *lua.LTable)

var (
	helperTableBuilders  = map[string]helperTableBuilder{}
	helperTableExtenders = map[string][]helperTableExtender{}
)

// RegisterHelperTable installs name -> build at init time. Panics on a
// duplicate registration so a typo (two api_*.go files reaching for the
// same Lua-side name) fails loudly at package load rather than after
// silent overwrite.
func RegisterHelperTable(name string, build helperTableBuilder) {
	if _, dup := helperTableBuilders[name]; dup {
		panic("lua_engine: duplicate helper table registration for " + name)
	}
	helperTableBuilders[name] = build
}

// RegisterHelperTableExtender appends extra entries to an existing
// helper table at VM build time. The extender runs after the base
// builder has produced the table, so its RawSetString calls land on
// the same table the rest of the api_*.go entries are already on.
// Multiple extenders per namespace are allowed and run in registration
// order; this is the seam check subpackages use to contribute their
// own entries to shared root namespaces without an import cycle.
func RegisterHelperTableExtender(name string, extend helperTableExtender) {
	helperTableExtenders[name] = append(helperTableExtenders[name], extend)
}

// applyHelperTableExtenders runs every extender registered against
// name against table. No-op when no extender is registered. Centralised
// so bindHyperzAPI iterates the same map every callsite would.
func applyHelperTableExtenders(L *lua.LState, name string, table *lua.LTable) {
	for _, extend := range helperTableExtenders[name] {
		extend(L, table)
	}
}
