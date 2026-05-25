package luabridge

import (
	"net/url"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/scope"
)

// scopeUserData wraps a *scope.Scope for Lua. Same rationale as the
// headers wrapper: scope is a Go value with non-trivial methods we
// would rather not reimplement in Lua, and userdata keeps the Lua
// surface narrow (one method, allows) without leaking the rest of
// scope.Scope.
type scopeUserData struct {
	sc *scope.Scope
}

// pushScope wraps sc as a userdata. A nil sc is still wrapped: the
// scanner's contract is "nil scope means no restrictions", and
// scope.Allows handles a nil receiver permissively. Always returning
// a userdata means the Lua side does not have to special-case the
// nil scope before calling :allows - the call goes through and
// returns true, matching the Go behavior exactly.
func pushScope(L *lua.LState, sc *scope.Scope) lua.LValue {
	ud := L.NewUserData()
	ud.Value = &scopeUserData{sc: sc}
	ud.Metatable = ensureScopeMT(L)
	return ud
}

func ensureScopeMT(L *lua.LState) *lua.LTable {
	if mt, ok := L.G.Registry.RawGetString(mtScope).(*lua.LTable); ok {
		return mt
	}
	mt := L.NewTable()
	methods := L.NewTable()
	methods.RawSetString("allows", L.NewFunction(scopeAllows))
	mt.RawSetString("__index", methods)
	L.G.Registry.RawSetString(mtScope, mt)
	return mt
}

// scopeAllows implements scope:allows(rawurl) returning a bool. The
// URL is parsed inside the binding so the Lua author does not have
// to import the url helpers; an unparseable URL returns false (deny)
// which is the safer default for active probes.
func scopeAllows(L *lua.LState) int {
	ud, ok := L.CheckUserData(1).Value.(*scopeUserData)
	if !ok {
		L.ArgError(1, "expected scope userdata")
	}
	raw := requireString(L, 2)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		L.Push(lua.LBool(false))
		return 1
	}
	L.Push(lua.LBool(ud.sc.Allows(u)))
	return 1
}
