package lua_engine

import (
	"strconv"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

// buildPayloadsTable returns the ctx.payloads helper namespace. What
// remains here after the per-family subpackages took ownership of
// their own payload catalogues is the cross-family rendering surface
// every family shares: the {{TOKEN}} / {{SLEEP}} placeholder
// substitutor and the human-facing Loc descriptor renderer used in
// finding titles. Family-specific catalogues (SQLi pairs, SSRF param
// lists, SSTI probes, ...) moved to the matching ctx.<family>
// namespace when each family was lifted into its own subpackage.
//
// Helpers seeded here:
//
//	ctx.payloads.render(template, token, sleep_secs) -> string
//	  Substitutes the {{TOKEN}} / {{SLEEP}} placeholders the catalogue
//	  templates carry. Mirrors Payload.Render so a Lua-authored check
//	  produces the same wire bytes the Go check would.
func buildPayloadsTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("render", L.NewFunction(payloadsRender))
	return t
}

// PushPayloadList pushes a Lua array of {name, template} tables for
// the supplied projection. Centralised so the per-class helpers stay
// one-liners and the table shape can not drift between them. Exported
// so per-family subpackages can build the same {name, template} arrays
// without re-implementing the shape.
func PushPayloadList(L *lua.LState, src []SQLiErrorPayload) int {
	out := L.NewTable()
	for i, p := range src {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(p.Name))
		entry.RawSetString("template", lua.LString(p.Template))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

// payloadsRender substitutes {{TOKEN}} / {{SLEEP}} placeholders the
// catalogue templates carry. token replaces {{TOKEN}}; sleepSecs > 0
// replaces {{SLEEP}} with the literal integer. Lua-side callers do this
// in one place rather than every check re-implementing the gsub pair,
// so the placeholder vocabulary stays a single source of truth.
func payloadsRender(L *lua.LState) int {
	template := RequireString(L, 1)
	token := OptString(L, 2, "")
	sleepSecs := 0
	if L.GetTop() >= 3 {
		if n, ok := L.Get(3).(lua.LNumber); ok {
			sleepSecs = int(n)
		}
	}
	out := template
	if strings.Contains(out, "{{TOKEN}}") {
		out = strings.ReplaceAll(out, "{{TOKEN}}", token)
	}
	if sleepSecs > 0 && strings.Contains(out, "{{SLEEP}}") {
		out = strings.ReplaceAll(out, "{{SLEEP}}", strconv.Itoa(sleepSecs))
	}
	L.Push(lua.LString(out))
	return 1
}

func init() {
	RegisterHelperTable("payloads", buildPayloadsTable)
}
