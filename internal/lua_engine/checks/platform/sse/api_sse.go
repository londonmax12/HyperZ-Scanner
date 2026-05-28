package sse

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// buildSSETable returns the ctx.sse helper namespace. Two entry points:
//
//	ctx.sse.is_event_stream(content_type) -> bool
//	ctx.sse.find_event_source_literals(body) -> array of url strings
//
// Both wrap package-private helpers in sse_audit.go that the Lua port
// would otherwise re-implement against gopher-lua's weaker pattern
// library.
func buildSSETable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("is_event_stream", L.NewFunction(sseIsEventStream))
	t.RawSetString("find_event_source_literals", L.NewFunction(sseFindEventSourceLiterals))
	return t
}

func sseIsEventStream(L *lua.LState) int {
	L.Push(lua.LBool(IsEventStreamContentType(lua_engine.RequireString(L, 1))))
	return 1
}

func sseFindEventSourceLiterals(L *lua.LState) int {
	L.Push(lua_engine.PushStringList(L, FindEventSourceLiteralsLua([]byte(lua_engine.RequireString(L, 1)))))
	return 1
}

func init() {
	lua_engine.RegisterHelperTable("sse", buildSSETable)
}
