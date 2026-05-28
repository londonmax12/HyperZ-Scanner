package access

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// buildAccessTable returns the ctx.access helper namespace. These are
// the open-redirect family's body-sink scanner and URL-shape gates
// that used to live on the root ctx.body / ctx.url. They are
// check-specific to access-control redirect handling, so they moved
// with the Go files when the family was lifted into its own
// subpackage.
//
// Entry points:
//
//	ctx.access.find_redirect_sink(body, canary_host)
//	  -> (match_string, kind_string) or ("", "") when nothing found.
//
//	ctx.access.is_redirect_status(status)
//	  -> bool. true for 301 / 302 / 303 / 307 / 308.
//
//	ctx.access.location_targets_host(location_value, host)
//	  -> bool. Resolves location the way a browser would (including
//	     backslash + multi-slash normalization) and checks against host.
//
//	ctx.access.looks_redirectish(url_path)
//	  -> bool. true when the path contains a redirect-handling keyword
//	     (login / logout / auth / sso / redirect).
func buildAccessTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("find_redirect_sink", L.NewFunction(accessFindRedirectSink))
	t.RawSetString("is_redirect_status", L.NewFunction(accessIsRedirectStatus))
	t.RawSetString("location_targets_host", L.NewFunction(accessLocationTargetsHost))
	t.RawSetString("looks_redirectish", L.NewFunction(accessLooksRedirectish))
	return t
}

// accessFindRedirectSink delegates to FindBodyRedirectSink so a
// Lua-authored check applies the exact same JS-navigation + meta-
// refresh scanning the Go check uses. Keeping the regex in Go means
// future tightening (new sink shapes, false-positive fixes) only
// needs to land once.
func accessFindRedirectSink(L *lua.LState) int {
	body := lua_engine.RequireString(L, 1)
	host := lua_engine.RequireString(L, 2)
	target, kind := FindBodyRedirectSink([]byte(body), host)
	L.Push(lua.LString(target))
	L.Push(lua.LString(kind))
	return 2
}

// accessIsRedirectStatus reports whether the given HTTP status code is
// a 3xx redirect that carries a Location header. 304 (Not Modified)
// is excluded; see IsRedirectStatus for the accepted code list.
func accessIsRedirectStatus(L *lua.LState) int {
	code := L.CheckInt(1)
	L.Push(lua.LBool(IsRedirectStatus(code)))
	return 1
}

// accessLocationTargetsHost reports whether a Location-header-style
// string s resolves (after browser-quirk normalization) to the
// given host. Delegates to LocationTargetsHost so the Lua-
// authored open-redirect check uses the same comparator as the Go
// original, including the backslash-collapse / multi-slash-collapse
// passes that catch real-world bypass variants.
func accessLocationTargetsHost(L *lua.LState) int {
	s := lua_engine.RequireString(L, 1)
	host := lua_engine.RequireString(L, 2)
	L.Push(lua.LBool(LocationTargetsHost(s, host)))
	return 1
}

// accessLooksRedirectish reports whether path contains one of the
// canonical redirect-handling keywords. Used by the open-redirect
// port to decide whether to fold the canonical parameter sweep into
// a page's probe surface.
func accessLooksRedirectish(L *lua.LState) int {
	path := lua_engine.RequireString(L, 1)
	L.Push(lua.LBool(LooksRedirectish(path)))
	return 1
}

func init() {
	lua_engine.RegisterHelperTable("access", buildAccessTable)
}
