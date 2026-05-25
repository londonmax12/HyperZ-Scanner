package luabridge

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
func bindHyperzAPI(L *lua.LState) {
	h := &staticHelpers{
		severity: buildSeverityTable(L),
		scopes:   buildScopesTable(L),
		levels:   buildLevelsTable(L),
		locs:     buildLocsTable(L),
		evidence: buildEvidenceTable(L),
		dedupe:   buildDedupeTable(L),
		url:      buildURLTable(L),
		body:     buildBodyTable(L),
		sinks:    buildSinksTable(L),
		html:     buildHTMLTable(L),
		cookies:  buildCookiesTable(L),
	}
	storeStaticHelpers(L, h)
}
