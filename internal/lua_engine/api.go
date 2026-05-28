package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// bindHyperzAPI installs the static helper tables on L and stashes
// them in the registry so each per-Run ctx can snap them in without
// rebuilding. Called by newVM exactly once per VM; the resulting
// tables are read-only from Lua's perspective (no setter API is
// exposed) and shared across every Run that VM serves.
//
// "Static" here means "does not depend on the per-Run env": these
// helpers are pure transformations (parse a URL, build a dedupe key,
// compose an evidence value). Per-Run state (page, client, scope)
// flows in through the dynamic fields buildCtxUserdata sets on the
// ctx table for each invocation.
//
// The helper set is open: each api_*.go registers its builder under a
// Lua-side namespace name in init(); this function only iterates the
// registry. To add a new namespace, drop a new api_*.go with a build
// function and an init() that calls RegisterHelperTable.
func bindHyperzAPI(L *lua.LState) {
	// Constant vocabularies (cms, framework, methods, severity, ...)
	// live in Lua globals so meta-table fields evaluated at module-load
	// time (applies_to, patched_in, tier, level, ...) can reference
	// them. Pure-helper namespaces with functions on them stay on ctx,
	// installed via the staticHelpers map below.
	installConstGlobals(L)

	h := make(staticHelpers, len(helperTableBuilders))
	for name, build := range helperTableBuilders {
		h[name] = build(L)
	}
	storeStaticHelpers(L, h)
}
