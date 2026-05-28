package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// buildWSTable returns the ctx.ws helper namespace. ws-audit is the
// only consumer today; the surface is two pieces - endpoint discovery
// (a regex scan over a body that produces the sorted, deduped set of
// ws:// / wss:// URL literals) and the raw RFC 6455 handshake (which
// has to live in Go because the http.Client transport will not let us
// inspect a 101 Switching Protocols response cleanly).
//
//	ctx.ws.discover_endpoints(body)   -> array of url string
//	  Sorted + deduped. The regex + body cap live in Go so a future
//	  tightening lands once. Empty body yields an empty array.
//
//	ctx.ws.handshake{url, origin}     -> (state_table, err_string)
//	  state_table = { accepted = bool, snippet = string, status = int }
//	  Sends one RFC 6455 client handshake with the supplied Origin and
//	  returns the verdict. Connection is closed before returning; no
//	  data frames are sent.
//
//	ctx.ws.foreign_origin()           -> string
//	  The well-known foreign-Origin string (https://hyperz-attacker.example).
//	  Lua-side authors stamp this onto handshake calls and finding text
//	  so the value never drifts between Go and Lua probes.
//
//	ctx.ws.max_endpoints_per_page()   -> int
//	  Per-page probe-fan-out cap so the .lua port short-circuits the
//	  same way the Go check does on SPAs that inline dozens of endpoint
//	  references in a config blob.
func buildWSTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("discover_endpoints", L.NewFunction(wsDiscoverEndpoints))
	t.RawSetString("handshake", L.NewFunction(wsHandshakeBinding))
	t.RawSetString("foreign_origin", L.NewFunction(wsForeignOrigin))
	t.RawSetString("max_endpoints_per_page", L.NewFunction(wsMaxEndpointsPerPageFn))
	return t
}

func wsDiscoverEndpoints(L *lua.LState) int {
	L.Push(pushStringList(L, WSAuditDiscoverEndpointsLua([]byte(requireString(L, 1)))))
	return 1
}

// wsHandshakeBinding implements ctx.ws.handshake{url, origin}. Accepts
// opts at position 1 OR 2 so both colon (ctx.ws:handshake{...}) and
// dot (ctx.ws.handshake{...}) styles work - same pattern the browser
// bridge uses for visit().
//
// Returns (state_table, nil) on dial / handshake success (including
// the not-accepted path where the verdict is just false) and
// (nil, err_string) when the dial itself failed. Differentiating the
// two lets the .lua port emit a single finding per accepted handshake
// AND report any wire-level failures through ctx.report().
func wsHandshakeBinding(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("ctx.ws.handshake called outside a check run"))
		return 2
	}
	opts, ok := L.Get(2).(*lua.LTable)
	if !ok {
		opts, ok = L.Get(1).(*lua.LTable)
		if !ok {
			L.ArgError(1, "expected opts table")
		}
	}
	url := lvalString(opts.RawGetString("url"))
	if url == "" {
		L.ArgError(1, "opts.url is required")
	}
	origin := lvalString(opts.RawGetString("origin"))
	res, err := WSAuditHandshakeLua(env.ctx, url, origin)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	state := L.NewTable()
	state.RawSetString("accepted", lua.LBool(res.Accepted))
	state.RawSetString("snippet", lua.LString(res.Snippet))
	state.RawSetString("status", lua.LNumber(res.Status))
	L.Push(state)
	return 1
}

func wsForeignOrigin(L *lua.LState) int {
	L.Push(lua.LString(WSAuditForeignOriginLua()))
	return 1
}

func wsMaxEndpointsPerPageFn(L *lua.LState) int {
	L.Push(lua.LNumber(WSAuditMaxEndpointsPerPageLua()))
	return 1
}

func init() {
	registerHelperTable("ws", buildWSTable)
}
