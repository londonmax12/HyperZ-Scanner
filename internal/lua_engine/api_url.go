package lua_engine

import (
	"net/url"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/scope"
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
	t.RawSetString("resolve", L.NewFunction(urlResolve))
	t.RawSetString("encode_values", L.NewFunction(urlEncodeValues))
	t.RawSetString("same_site", L.NewFunction(urlSameSite))
	return t
}

// urlSameSite reports whether two hostnames share a registrable
// domain (eTLD+1). Delegates to scope.SameSite so the Lua decision
// logic and Go originals use the same comparator, including the
// IP / bare-host fallback to exact equality. Lua-authored active
// checks call this to gate same-organization probing when the
// operator has not pinned a scope host allowlist.
func urlSameSite(L *lua.LState) int {
	a := RequireString(L, 1)
	b := RequireString(L, 2)
	L.Push(lua.LBool(scope.SameSite(a, b)))
	return 1
}

// urlEncodeValues encodes a flat name -> string|array table into the
// url.Values.Encode() form (RFC 3986 percent-encoding, alphabetically
// sorted keys). Used by the proto-pollution port to build bracket-
// notation parameter strings without re-implementing the escape rules
// in Lua. An empty / nil table returns "".
func urlEncodeValues(L *lua.LState) int {
	v := L.Get(1)
	if v == nil || v == lua.LNil {
		L.Push(lua.LString(""))
		return 1
	}
	tbl, ok := v.(*lua.LTable)
	if !ok {
		L.Push(lua.LString(""))
		return 1
	}
	values := url.Values{}
	tbl.ForEach(func(k, val lua.LValue) {
		name := LValString(k)
		if name == "" {
			return
		}
		switch t := val.(type) {
		case lua.LString:
			values.Add(name, string(t))
		case lua.LNumber:
			values.Add(name, LValString(t))
		case *lua.LTable:
			n := t.Len()
			for i := 1; i <= n; i++ {
				values.Add(name, LValString(t.RawGetInt(i)))
			}
		default:
			values.Add(name, LValString(val))
		}
	})
	L.Push(lua.LString(values.Encode()))
	return 1
}

// urlResolve resolves ref against base via net/url.URL.ResolveReference
// and returns the absolute URL string. Returns "" when either arg is
// unparseable. Lua-authored body scanners need this to lift relative
// URLs (e.g. EventSource('/stream')) up to absolute form before they
// route through ctx.client.
func urlResolve(L *lua.LState) int {
	baseRaw := RequireString(L, 1)
	refRaw := RequireString(L, 2)
	base, err := url.Parse(baseRaw)
	if err != nil {
		L.Push(lua.LString(""))
		return 1
	}
	ref, err := url.Parse(refRaw)
	if err != nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(base.ResolveReference(ref).String()))
	return 1
}

// urlParse implements url.parse(raw). Returns a table mirroring the
// net/url.URL fields, or (nil, err) when the string is unparseable.
// Authors guard on the nil return rather than reading individual
// fields and discovering they are all empty - this matches the
// idiomatic shape of every Go check that calls url.Parse.
func urlParse(L *lua.LState) int {
	raw := RequireString(L, 1)
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
	raw := RequireString(L, 1)
	u, err := url.Parse(raw)
	if err != nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(u.Host))
	return 1
}

func urlPath(L *lua.LState) int {
	raw := RequireString(L, 1)
	u, err := url.Parse(raw)
	if err != nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(u.EscapedPath()))
	return 1
}

func urlScheme(L *lua.LState) int {
	raw := RequireString(L, 1)
	u, err := url.Parse(raw)
	if err != nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(u.Scheme))
	return 1
}

// urlQuery returns the parsed query as a flat table: every name
// maps to its first value. Repeated query params surface as an
// array under the name; the dual shape (scalar | array) matches
// http.Header.Get / Values and keeps the common case (single-value
// query) ergonomic.
func urlQuery(L *lua.LState) int {
	raw := RequireString(L, 1)
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
		t.RawSetString(k, PushStringList(L, vs))
	}
	L.Push(t)
	return 1
}

func init() {
	RegisterHelperTable("url", buildURLTable)
}
