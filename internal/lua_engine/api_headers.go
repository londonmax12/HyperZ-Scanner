package lua_engine

import (
	"net/http"

	lua "github.com/yuin/gopher-lua"
)

// headersUserData wraps an http.Header for Lua. The wrapper exists so
// the bridge preserves http.Header.Get's case-insensitive lookup
// semantics - the same call shape Go checks already use - without
// forcing the Lua author to either lower-case keys themselves or
// scan the table linearly. Using a userdata also keeps the underlying
// header set live (a Lua-side rebinding can not desynchronize from
// the Go side because there is no Lua-visible mutation API).
type headersUserData struct {
	h http.Header
}

// pushHeaders wraps h as a userdata and pushes it onto L's stack with
// the headers metatable bound. The metatable's __index points at a
// methods table built by ensureHeadersMT so lookups like
// `headers:get("Server")` and the equivalent two-argument form
// (`headers.get(headers, "Server")`) both work.
func pushHeaders(L *lua.LState, h http.Header) lua.LValue {
	ud := L.NewUserData()
	ud.Value = &headersUserData{h: h}
	ud.Metatable = ensureHeadersMT(L)
	return ud
}

// ensureHeadersMT returns the shared headers metatable for L,
// creating it on first use. Shared across all header userdata
// instances so one metatable allocation per VM serves every page's
// request/response headers.
func ensureHeadersMT(L *lua.LState) *lua.LTable {
	if mt, ok := L.G.Registry.RawGetString(mtHeaders).(*lua.LTable); ok {
		return mt
	}
	mt := L.NewTable()
	methods := L.NewTable()
	methods.RawSetString("get", L.NewFunction(headersGet))
	methods.RawSetString("values", L.NewFunction(headersValues))
	methods.RawSetString("names", L.NewFunction(headersNames))
	methods.RawSetString("has", L.NewFunction(headersHas))
	mt.RawSetString("__index", methods)
	L.G.Registry.RawSetString(mtHeaders, mt)
	return mt
}

// headersFromArg unwraps the headers userdata at position 1. Callers
// that fail this check raise a Lua error - a check author asking
// `something:get("X")` against a non-headers value is a programming
// mistake, not a runtime condition we want to silently swallow.
func headersFromArg(L *lua.LState) *headersUserData {
	ud, ok := L.CheckUserData(1).Value.(*headersUserData)
	if !ok {
		L.ArgError(1, "expected headers userdata")
	}
	return ud
}

// headersGet implements headers:get(name). Returns the first value
// for name using net/http canonicalization (case-insensitive), or
// "" when absent. Matches http.Header.Get exactly so a Lua check that
// reads a header sees the same value the equivalent Go check would.
func headersGet(L *lua.LState) int {
	h := headersFromArg(L).h
	name := requireString(L, 2)
	L.Push(lua.LString(h.Get(name)))
	return 1
}

// headersValues implements headers:values(name) returning every
// value for name as an array table. Distinct from get for headers
// that legitimately repeat (Set-Cookie, Link) where the first value
// is not enough.
func headersValues(L *lua.LState) int {
	h := headersFromArg(L).h
	name := requireString(L, 2)
	L.Push(pushStringList(L, h.Values(name)))
	return 1
}

// headersNames implements headers:names() returning the set of
// canonicalized header names as an array table. Useful for checks
// that scan for header families (everything beginning with "X-") or
// emit evidence enumerating which headers were observed.
func headersNames(L *lua.LState) int {
	h := headersFromArg(L).h
	tbl := L.NewTable()
	i := 1
	for k := range h {
		tbl.RawSetInt(i, lua.LString(k))
		i++
	}
	L.Push(tbl)
	return 1
}

// headersHas implements headers:has(name). Returns true if name is
// present (even with an empty value); false otherwise. Distinct from
// `get(name) ~= ""` because a header may legitimately be set with an
// empty value and an author may want to detect the presence not the
// content.
func headersHas(L *lua.LState) int {
	h := headersFromArg(L).h
	name := requireString(L, 2)
	_, ok := h[http.CanonicalHeaderKey(name)]
	L.Push(lua.LBool(ok))
	return 1
}
