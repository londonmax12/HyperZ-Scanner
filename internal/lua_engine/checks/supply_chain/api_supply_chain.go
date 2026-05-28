package supply_chain

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// buildSupplyChainTable returns the ctx.supply_chain helper namespace.
// The single entry point - scan_known_js_libs(body) - walks the body's
// script tags, identifies known JS libraries from their src URLs, and
// returns the per-library hits with their detected version and any
// matching vulnerability rows. Lives here (not on ctx.body) because
// the catalogue + matching logic are js-libs-specific; ctx.body keeps
// only the generic content-type / regex helpers every check shares.
func buildSupplyChainTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("scan_known_js_libs", L.NewFunction(supplyChainScanKnownJSLibs))
	return t
}

func supplyChainScanKnownJSLibs(L *lua.LState) int {
	body := lua_engine.RequireString(L, 1)
	hits := ScanScriptTagsForKnownJSLibraries([]byte(body))
	out := L.NewTable()
	for i, h := range hits {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(h.Name))
		entry.RawSetString("version", lua.LString(h.Version))
		entry.RawSetString("vulnerabilities", lua_engine.PushStringList(L, h.Vulnerabilities))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func init() {
	lua_engine.RegisterHelperTable("supply_chain", buildSupplyChainTable)
}
