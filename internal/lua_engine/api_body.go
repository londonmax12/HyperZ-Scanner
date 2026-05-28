package lua_engine

import (
	"net/http"

	lua "github.com/yuin/gopher-lua"
)

// buildBodyTable returns the ctx.body helper namespace. What remains
// here after the per-family subpackages took ownership of their own
// helpers is the small set that is genuinely cross-family: a
// content-type sniffer (HTML response gate) and net/http.StatusText
// (status-line rendering for evidence snippets). Family-specific body
// scanners (SQLi error patterns, traversal markers, XXE error patterns,
// proto-pollution JSON sniffing, ...) moved to the matching
// ctx.<family> namespace when each family was lifted into its own
// subpackage.
//
// Helpers seeded here:
//
//	ctx.body.is_html_ct(content_type) -> bool
//	  Mirrors the Go-side content-type filter every passive check gates
//	  on, so a Lua port and the Go original agree on "this response is
//	  HTML".
//
//	ctx.body.status_text(code) -> string
//	  Wraps net/http.StatusText so Lua-authored evidence snippets render
//	  "HTTP/1.1 200 OK"-style status lines without the .lua file
//	  carrying its own status-code table.
func buildBodyTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("is_html_ct", L.NewFunction(bodyIsHTMLCT))
	t.RawSetString("status_text", L.NewFunction(bodyStatusText))
	return t
}

// bodyStatusText wraps net/http.StatusText so Lua-authored evidence
// snippets can render "HTTP/1.1 200 OK"-style status lines without
// the .lua file carrying its own status-code table. Returns "" for
// unrecognized codes (matches the Go API verbatim).
func bodyStatusText(L *lua.LState) int {
	L.Push(lua.LString(http.StatusText(L.CheckInt(1))))
	return 1
}

func bodyIsHTMLCT(L *lua.LState) int {
	L.Push(lua.LBool(IsHTMLContentType(RequireString(L, 1))))
	return 1
}

func init() {
	RegisterHelperTable("body", buildBodyTable)
}
