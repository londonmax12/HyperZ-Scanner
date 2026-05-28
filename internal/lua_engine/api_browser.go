package lua_engine

import (
	"fmt"
	"time"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/browser"
)

// buildBrowserTable returns the ctx.browser helper namespace. The
// surface mirrors what dom-xss and any future runtime-execution check
// needs from the engine's headless-browser pool:
//
//	ctx.browser.attached()        -> bool, true when the operator opted
//	                                  into --js and the scanner attached
//	                                  a Pool to the active context.
//	ctx.browser.binding_name()    -> string, the JS function name
//	                                  payloads call to prove execution
//	                                  (browser.BindingName). Exposed so
//	                                  Lua-side payload builders don't
//	                                  hard-code the constant and drift if
//	                                  the Go-side name ever changes.
//	ctx.browser.new_canary()      -> string, a fresh per-probe token to
//	                                  embed in a payload and match
//	                                  against the binding call. Wraps
//	                                  NewCanary so Lua authors
//	                                  don't need to reimplement the
//	                                  hex-suffix shape the rest of the
//	                                  engine produces.
//	ctx.browser:visit(opts)       -> fired (bool), err
//	                                  opts.url       (string, required)
//	                                  opts.token     (string, required)
//	                                  opts.settle_ms (number, optional;
//	                                                   defaults to 1500ms,
//	                                                   matching the Go
//	                                                   check's domXSSSettle)
//
// Visit is exposed via the wrapper userdata's metatable so the call
// site reads ctx.browser:visit{...} (colon syntax) for consistency with
// other engine helpers (ctx.oob, ctx.client). The helper functions
// (attached, binding_name, new_canary) hang off the same table as plain
// fields because they don't need an implicit self argument.
//
// When no Pool is attached, visit() returns (false, nil) silently so a
// Lua check can be written without an explicit attached() guard around
// every probe - the visit just no-ops the same way the Go check no-ops
// when BrowserFrom returns nil. attached() is exposed for the cases
// where a check wants to skip the entire payload-mint loop rather than
// pay the per-probe binding setup cost.
func buildBrowserTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("binding_name", L.NewFunction(browserBindingName))
	t.RawSetString("new_canary", L.NewFunction(browserNewCanary))
	t.RawSetString("attached", L.NewFunction(browserAttached))
	t.RawSetString("visit", L.NewFunction(browserVisit))
	return t
}

// browserBindingName returns browser.BindingName. Exposed as a function
// rather than a constant string on the table so the bridge wires it
// through one helper - if BindingName ever becomes per-VM (unlikely but
// cheap to allow) the Lua side doesn't need to change.
func browserBindingName(L *lua.LState) int {
	L.Push(lua.LString(browser.BindingName))
	return 1
}

// browserNewCanary wraps NewCanary. Returns the same per-call
// canary shape the Go side uses so a Lua-authored check produces tokens
// indistinguishable from a Go-authored one - matters because the
// binding-call payload check is byte-exact.
func browserNewCanary(L *lua.LState) int {
	L.Push(lua.LString(NewCanary()))
	return 1
}

// browserAttached reports whether the scanner attached a browser.Pool
// to the active context. False here means --js was not passed (or the
// browser process failed to launch), in which case visit() will return
// (false, nil) on every call.
func browserAttached(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.Push(lua.LBool(false))
		return 1
	}
	L.Push(lua.LBool(BrowserFrom(env.ctx) != nil))
	return 1
}

// browserVisit implements ctx.browser:visit{url, token, settle_ms}.
//
// Returns (fired_bool, err_string) - err is nil on the binding-not-fired
// path (which is a clean miss, not a failure) and on every path where
// no pool is attached. Errors are reserved for navigation / browser-
// process failures the Pool.Visit implementation surfaces - the Lua
// check is expected to thread them through ctx.report() the same way
// the Go check threads them through Report.
func browserVisit(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LNil)
		return 2
	}
	pool := BrowserFrom(env.ctx)
	if pool == nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LNil)
		return 2
	}

	// The first arg is the ctx.browser table itself (colon syntax); the
	// opts table arrives at position 2. Accept either shape so a
	// dot-call (ctx.browser.visit{...}) still works.
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
	token := lvalString(opts.RawGetString("token"))
	if token == "" {
		L.ArgError(1, "opts.token is required")
	}
	settle := 1500 * time.Millisecond
	if n, ok := opts.RawGetString("settle_ms").(lua.LNumber); ok && float64(n) > 0 {
		settle = time.Duration(float64(n) * float64(time.Millisecond))
	}

	fired, err := pool.Visit(env.ctx, url, token, settle)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(fmt.Sprintf("browser visit %s: %s", url, err.Error())))
		return 2
	}
	L.Push(lua.LBool(fired))
	L.Push(lua.LNil)
	return 2
}

func init() {
	registerHelperTable("browser", buildBrowserTable)
}
