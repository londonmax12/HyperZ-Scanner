package luabridge

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/checks"
)

// buildBodyTable returns the ctx.body helper namespace. These are
// the regex-heavy body-scanning routines that live in Go (we keep
// them in Go on purpose: gopher-lua's pattern library is weaker than
// re2/Go regex, and the scanners are perf-sensitive). The Lua side
// gets a stable surface that delegates to engine implementations.
//
// Helpers seeded here:
//
//	ctx.body.find_redirect_sink(body, canary_host)
//	  -> (match_string, kind_string) or ("", "") when nothing found.
//	     kind is the human-readable label for the report
//	     ("a JavaScript navigation sink", "a meta refresh tag").
//
// Additional body scanners (XSS reflection, SQLi error fingerprints,
// SSTI markers) are added here as their owning checks are ported to
// Lua. Each is a Go function with a stable arg shape that a Lua
// author calls without having to know the internal regex.
func buildBodyTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("find_redirect_sink", L.NewFunction(bodyFindRedirectSink))
	return t
}

// bodyFindRedirectSink delegates to checks.FindBodyRedirectSink so a
// Lua-authored check applies the exact same JS-navigation + meta-
// refresh scanning the Go check uses. Keeping the regex in Go means
// future tightening (new sink shapes, false-positive fixes) only
// needs to land once.
func bodyFindRedirectSink(L *lua.LState) int {
	body := requireString(L, 1)
	host := requireString(L, 2)
	target, kind := checks.FindBodyRedirectSink([]byte(body), host)
	L.Push(lua.LString(target))
	L.Push(lua.LString(kind))
	return 2
}
