package lua_engine

import (
	"net/http"

	lua "github.com/yuin/gopher-lua"
)

// buildCookiesTable returns the ctx.cookies helper namespace. Only
// one method ships today (from_headers) because the cookie-attributes
// port is the only Lua check that needs structured Set-Cookie data;
// future cookie-aware ports add helpers here rather than fanning out
// into ad-hoc top-level tables.
//
//	ctx.cookies.from_headers(headers)
//	  -> array of { name, value, domain, path, expires, max_age,
//	                secure (bool), http_only (bool), same_site (string),
//	                raw }
//	     headers is the headers userdata exposed on snap.headers /
//	     response:headers(). Returns an empty array when no Set-Cookie
//	     header is present.
func buildCookiesTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("from_headers", L.NewFunction(cookiesFromHeaders))
	return t
}

// cookiesFromHeaders unwraps the headers userdata at position 1 and
// returns the parsed Set-Cookie entries as a Lua array. Delegating to
// ParseSetCookies keeps the Go-side http.Response.Cookies()
// behavior as the single source of truth.
func cookiesFromHeaders(L *lua.LState) int {
	hud, ok := L.CheckUserData(1).Value.(*headersUserData)
	if !ok {
		L.ArgError(1, "expected headers userdata")
	}
	cookies := ParseSetCookies(hud.h)
	out := L.NewTable()
	for i, ck := range cookies {
		out.RawSetInt(i+1, cookieTable(L, ck))
	}
	L.Push(out)
	return 1
}

// cookieTable mirrors http.Cookie into a Lua table. SameSite is
// emitted as a lower-cased string ("lax", "strict", "none", "") to
// keep the Lua-side comparison simple - authors write
// `if ck.same_site ~= "lax" and ck.same_site ~= "strict" and ck.same_site ~= "none" then`
// without having to import an enum.
func cookieTable(L *lua.LState, ck *http.Cookie) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("name", lua.LString(ck.Name))
	t.RawSetString("value", lua.LString(ck.Value))
	t.RawSetString("domain", lua.LString(ck.Domain))
	t.RawSetString("path", lua.LString(ck.Path))
	t.RawSetString("max_age", lua.LNumber(ck.MaxAge))
	t.RawSetString("secure", lua.LBool(ck.Secure))
	t.RawSetString("http_only", lua.LBool(ck.HttpOnly))
	t.RawSetString("raw", lua.LString(ck.Raw))
	switch ck.SameSite {
	case http.SameSiteLaxMode:
		t.RawSetString("same_site", lua.LString("lax"))
	case http.SameSiteStrictMode:
		t.RawSetString("same_site", lua.LString("strict"))
	case http.SameSiteNoneMode:
		t.RawSetString("same_site", lua.LString("none"))
	default:
		t.RawSetString("same_site", lua.LString(""))
	}
	return t
}

func init() {
	registerHelperTable("cookies", buildCookiesTable)
}
