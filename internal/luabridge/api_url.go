package luabridge

import (
	"net/url"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/checks"
)

// buildURLTable returns the ctx.url helper table. The helpers are
// thin wrappers over net/url so Lua authors do not have to import
// their own URL parser; everything that used to be inline in a Go
// check (parse, host extraction, path-keyword sniffing) is exposed
// here under a stable surface.
//
// Lookups are pure functions: they hold no env-specific state and
// therefore live on the static side of the bridge (built once per
// VM and reused across every Run on that VM).
func buildURLTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("parse", L.NewFunction(urlParse))
	t.RawSetString("host", L.NewFunction(urlHost))
	t.RawSetString("path", L.NewFunction(urlPath))
	t.RawSetString("scheme", L.NewFunction(urlScheme))
	t.RawSetString("query", L.NewFunction(urlQuery))
	t.RawSetString("location_targets_host", L.NewFunction(urlLocationTargetsHost))
	t.RawSetString("looks_redirectish", L.NewFunction(urlLooksRedirectish))
	t.RawSetString("is_redirect_status", L.NewFunction(urlIsRedirectStatus))
	return t
}

// urlParse implements url.parse(raw). Returns a table mirroring the
// net/url.URL fields, or (nil, err) when the string is unparseable.
// Authors guard on the nil return rather than reading individual
// fields and discovering they are all empty - this matches the
// idiomatic shape of every Go check that calls url.Parse.
func urlParse(L *lua.LState) int {
	raw := requireString(L, 1)
	u, err := url.Parse(raw)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	t := L.NewTable()
	t.RawSetString("scheme", lua.LString(u.Scheme))
	t.RawSetString("host", lua.LString(u.Host))
	t.RawSetString("hostname", lua.LString(u.Hostname()))
	t.RawSetString("port", lua.LString(u.Port()))
	t.RawSetString("path", lua.LString(u.EscapedPath()))
	t.RawSetString("raw_query", lua.LString(u.RawQuery))
	t.RawSetString("fragment", lua.LString(u.Fragment))
	t.RawSetString("user", lua.LString(u.User.Username()))
	t.RawSetString("string", lua.LString(u.String()))
	L.Push(t)
	return 1
}

// urlHost returns u.Host for an arbitrary URL. A convenience over
// parse() when the author only wants the host - skipping the full
// table build keeps hot loops (per-page host checks) lean.
func urlHost(L *lua.LState) int {
	raw := requireString(L, 1)
	u, err := url.Parse(raw)
	if err != nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(u.Host))
	return 1
}

func urlPath(L *lua.LState) int {
	raw := requireString(L, 1)
	u, err := url.Parse(raw)
	if err != nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(u.EscapedPath()))
	return 1
}

func urlScheme(L *lua.LState) int {
	raw := requireString(L, 1)
	u, err := url.Parse(raw)
	if err != nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(u.Scheme))
	return 1
}

// urlLocationTargetsHost reports whether a Location-header-style
// string s resolves (after browser-quirk normalization) to the
// given host. Delegates to checks.LocationTargetsHost so the Lua-
// authored open-redirect check uses the same comparator as the Go
// original, including the backslash-collapse / multi-slash-collapse
// passes that catch real-world bypass variants.
func urlLocationTargetsHost(L *lua.LState) int {
	s := requireString(L, 1)
	host := requireString(L, 2)
	L.Push(lua.LBool(checks.LocationTargetsHost(s, host)))
	return 1
}

// urlLooksRedirectish reports whether path contains one of the
// canonical redirect-handling keywords. Used by the open-redirect
// port to decide whether to fold the canonical parameter sweep into
// a page's probe surface. See checks.LooksRedirectish for the
// keyword list - kept in one place so the gating heuristic doesn't
// drift between the Go and Lua authoring paths.
func urlLooksRedirectish(L *lua.LState) int {
	path := requireString(L, 1)
	L.Push(lua.LBool(checks.LooksRedirectish(path)))
	return 1
}

// urlIsRedirectStatus reports whether the given HTTP status code is
// a 3xx redirect that carries a Location header. 304 (Not Modified)
// is excluded; see checks.IsRedirectStatus for the accepted code
// list. Belongs under ctx.url because the open-redirect logic pairs
// it with Location-header inspection - moving it to its own
// `ctx.http` namespace would split the redirect detection surface
// across two tables for no real gain.
func urlIsRedirectStatus(L *lua.LState) int {
	code := L.CheckInt(1)
	L.Push(lua.LBool(checks.IsRedirectStatus(code)))
	return 1
}

// urlQuery returns the parsed query as a flat table: every name
// maps to its first value. Repeated query params surface as an
// array under the name; the dual shape (scalar | array) matches
// http.Header.Get / Values and keeps the common case (single-value
// query) ergonomic.
func urlQuery(L *lua.LState) int {
	raw := requireString(L, 1)
	u, err := url.Parse(raw)
	if err != nil {
		L.Push(L.NewTable())
		return 1
	}
	q := u.Query()
	t := L.NewTable()
	for k, vs := range q {
		if len(vs) == 1 {
			t.RawSetString(k, lua.LString(vs[0]))
			continue
		}
		arr := L.NewTable()
		for i, v := range vs {
			arr.RawSetInt(i+1, lua.LString(v))
		}
		t.RawSetString(k, arr)
	}
	L.Push(t)
	return 1
}
