package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// oobUserData wraps the per-Run OOB server (which may be nil when no
// listener is attached to the scan) plus the running check's name. The
// check name is what the OOB server indexes registrations under, so
// every register() call from a Lua check needs to thread it through
// without the author having to repeat it.
//
// Storing the wrapper as a userdata (rather than a Lua table that
// directly exposes register / hits / registrations functions) lets the
// metatable carry the methods - mirroring how the existing client /
// scope / sink wrappers expose their behavior - so the Lua call site
// is consistent: ctx.oob:register{...} rather than ctx.oob.register{...}.
type oobUserData struct {
	env *RunEnv
}

// pushOOBServer wraps env into the OOB userdata. We always push a
// userdata (rather than lua.LNil when OOBFrom is nil) so a Lua-side
// `if ctx.oob then` guard distinguishes "no listener attached" from
// "I forgot to call OOBFrom" - we expose an attached() method below
// for the boolean query.
func pushOOBServer(L *lua.LState, env *RunEnv) lua.LValue {
	ud := L.NewUserData()
	ud.Value = &oobUserData{env: env}
	ud.Metatable = ensureOOBMT(L)
	return ud
}

func ensureOOBMT(L *lua.LState) *lua.LTable {
	if mt, ok := L.G.Registry.RawGetString(mtOOB).(*lua.LTable); ok {
		return mt
	}
	mt := L.NewTable()
	methods := L.NewTable()
	methods.RawSetString("attached", L.NewFunction(oobAttached))
	methods.RawSetString("register", L.NewFunction(oobRegister))
	methods.RawSetString("register_asset", L.NewFunction(oobRegisterAsset))
	methods.RawSetString("hits", L.NewFunction(oobHits))
	methods.RawSetString("registrations", L.NewFunction(oobRegistrations))
	methods.RawSetString("callback_host", L.NewFunction(oobCallbackHost))
	mt.RawSetString("__index", methods)
	L.G.Registry.RawSetString(mtOOB, mt)
	return mt
}

func oobFromArg(L *lua.LState) *oobUserData {
	ud, ok := L.CheckUserData(1).Value.(*oobUserData)
	if !ok {
		L.ArgError(1, "expected oob userdata")
	}
	return ud
}

// oobCallbackHost returns the host:port targets see in canary URLs.
// Used by the .lua xxe drain path to render the exfil-receiver URL
// in finding evidence (the parameter-entity callback the parser
// issued lands at http://callback-host/<receiver-token>). Returns ""
// when no listener is attached.
func oobCallbackHost(L *lua.LState) int {
	o := oobFromArg(L)
	if o.env == nil {
		L.Push(lua.LString(""))
		return 1
	}
	srv := OOBFrom(o.env.Ctx)
	if srv == nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(srv.CallbackHost()))
	return 1
}

// oobAttached reports whether the running scan has an OOB listener
// attached. Checks that mint canaries gate the entire probe sequence
// on this so a passive scan (no --oob) silently skips the OOB arm
// rather than minting unused canaries.
func oobAttached(L *lua.LState) int {
	o := oobFromArg(L)
	L.Push(lua.LBool(o.env != nil && OOBFrom(o.env.Ctx) != nil))
	return 1
}

// oobRegister mints a fresh canary indexed under the running check's
// name and returns {token, http_url, dns_host}. extra is an optional
// table whose string fields ride into the OOB registration's Extra
// map, so the matching Drain pass can recover per-finding context
// (target, sink, payload name, engine) without the check having to
// maintain its own correlation table.
func oobRegister(L *lua.LState) int {
	o := oobFromArg(L)
	if o.env == nil {
		L.Push(lua.LNil)
		return 1
	}
	srv := OOBFrom(o.env.Ctx)
	if srv == nil {
		L.Push(lua.LNil)
		return 1
	}
	extra := map[string]string{}
	if t, ok := L.Get(2).(*lua.LTable); ok {
		t.ForEach(func(k, v lua.LValue) {
			if name, ok := k.(lua.LString); ok {
				extra[string(name)] = lvalString(v)
			}
		})
	}
	canary := srv.Register(o.env.Check.name, extra)
	out := L.NewTable()
	out.RawSetString("token", lua.LString(canary.Token))
	out.RawSetString("http_url", lua.LString(canary.HTTPURL))
	L.Push(out)
	return 1
}

// oobRegisterAsset mirrors oobRegister but additionally configures the
// listener to respond with body / content_type when the canary URL is
// hit. Returns the same {token, http_url} shape. Used by xxe-style
// follow-up callback chains where the parser needs a real artifact in
// the response to proceed; the current 10-check round does not exercise
// this path but the helper is exposed for symmetry with the Go API.
func oobRegisterAsset(L *lua.LState) int {
	o := oobFromArg(L)
	if o.env == nil {
		L.Push(lua.LNil)
		return 1
	}
	srv := OOBFrom(o.env.Ctx)
	if srv == nil {
		L.Push(lua.LNil)
		return 1
	}
	body := ""
	contentType := ""
	extra := map[string]string{}
	if t, ok := L.Get(2).(*lua.LTable); ok {
		body = lvalString(t.RawGetString("body"))
		contentType = lvalString(t.RawGetString("content_type"))
		if et, ok := t.RawGetString("extra").(*lua.LTable); ok {
			et.ForEach(func(k, v lua.LValue) {
				if name, ok := k.(lua.LString); ok {
					extra[string(name)] = lvalString(v)
				}
			})
		}
	}
	canary := srv.RegisterAsset(o.env.Check.name, body, contentType, extra)
	out := L.NewTable()
	out.RawSetString("token", lua.LString(canary.Token))
	out.RawSetString("http_url", lua.LString(canary.HTTPURL))
	L.Push(out)
	return 1
}

// oobHits returns the observed callbacks for a token as an array of
// {method, path, source_addr, timestamp_unix, user_agent} tables. The
// drain pass iterates these to build per-registration findings.
func oobHits(L *lua.LState) int {
	o := oobFromArg(L)
	out := L.NewTable()
	if o.env == nil {
		L.Push(out)
		return 1
	}
	srv := OOBFrom(o.env.Ctx)
	if srv == nil {
		L.Push(out)
		return 1
	}
	token := requireString(L, 2)
	for i, h := range srv.Hits(token) {
		entry := L.NewTable()
		entry.RawSetString("method", lua.LString(h.Method))
		entry.RawSetString("path", lua.LString(h.Path))
		entry.RawSetString("source_addr", lua.LString(h.SourceAddr))
		entry.RawSetString("timestamp_unix", lua.LNumber(h.Timestamp.Unix()))
		if h.Headers != nil {
			entry.RawSetString("user_agent", lua.LString(h.Headers.Get("User-Agent")))
		}
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

// oobRegistrations returns every canary the running check minted, as
// an array of {token, http_url, extra={...}} tables. Drain iterates
// these to fold per-canary hits into findings.
func oobRegistrations(L *lua.LState) int {
	o := oobFromArg(L)
	out := L.NewTable()
	if o.env == nil {
		L.Push(out)
		return 1
	}
	srv := OOBFrom(o.env.Ctx)
	if srv == nil {
		L.Push(out)
		return 1
	}
	for i, r := range srv.Registrations(o.env.Check.name) {
		entry := L.NewTable()
		entry.RawSetString("token", lua.LString(r.Canary.Token))
		entry.RawSetString("http_url", lua.LString(r.Canary.HTTPURL))
		extra := L.NewTable()
		for k, v := range r.Extra {
			extra.RawSetString(k, lua.LString(v))
		}
		entry.RawSetString("extra", extra)
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}
