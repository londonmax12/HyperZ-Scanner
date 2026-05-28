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

var helperTableBuilders = map[string]helperTableBuilder{}

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

