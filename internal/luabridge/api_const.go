package luabridge

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/checks"
)

// buildSeverityTable returns the read-only severity constant table
// exposed as ctx.severity. Lua authors write `ctx.severity.high`
// rather than the bare string "high" so a typo (`ctx.severity.hgh`)
// fails fast at the use site with a nil access rather than silently
// producing a finding with severity = "" that ranks below info.
//
// Keys are lowercased to match the wire format the rest of the engine
// uses (Finding.Severity is already a lowercase string); values are
// strings rather than ints because checks.Severity is a string type
// and there's nothing to be gained by interposing a numeric layer.
func buildSeverityTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("info", lua.LString(checks.SeverityInfo))
	t.RawSetString("low", lua.LString(checks.SeverityLow))
	t.RawSetString("medium", lua.LString(checks.SeverityMedium))
	t.RawSetString("high", lua.LString(checks.SeverityHigh))
	t.RawSetString("critical", lua.LString(checks.SeverityCritical))
	return t
}

// buildScopesTable mirrors the checks.Scope enum for dedupe-key
// construction. Authors pass these into dedupe.key:
//
//	dedupe.key{ scope = ctx.scopes.param, parts = {"loc:query", "param:next"} }
//
// The strings ("host", "page", "param") match parseScope's accepted
// inputs so the same vocabulary works on both sides of the bridge.
func buildScopesTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("host", lua.LString("host"))
	t.RawSetString("page", lua.LString("page"))
	t.RawSetString("param", lua.LString("param"))
	return t
}

// buildLevelsTable exposes the checks.Level vocabulary. The active
// scan level surfaces as ctx.level (a string), and authors compare
// with ctx.levels.aggressive instead of writing "aggressive" inline
// for the same reason severity uses a table.
func buildLevelsTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("passive", lua.LString("passive"))
	t.RawSetString("default", lua.LString("default"))
	t.RawSetString("aggressive", lua.LString("aggressive"))
	return t
}

// buildLocsTable exposes the checks.Loc enum used by Sink. Lua
// authors that read sink.loc compare against ctx.locs.query,
// ctx.locs.form, etc. The string values are exactly the wire form
// checks.Loc carries so a sink loc surfaces as the same string in
// Lua and in Go.
func buildLocsTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("query", lua.LString(checks.LocQuery))
	t.RawSetString("form", lua.LString(checks.LocForm))
	t.RawSetString("header", lua.LString(checks.LocHeader))
	t.RawSetString("cookie", lua.LString(checks.LocCookie))
	t.RawSetString("json", lua.LString(checks.LocJSON))
	t.RawSetString("path", lua.LString(checks.LocPath))
	return t
}
