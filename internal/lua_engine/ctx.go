package lua_engine

import (
	"errors"

	lua "github.com/yuin/gopher-lua"
)

// buildCtxUserdata produces the per-Run ctx table the check sees as
// its first argument. The table mixes:
//
//   - dynamic fields populated from envCtx (page, scope, client,
//     check_name, level)
//   - static helper tables snapped in from the VM's staticHelpers
//     (severity, scopes, levels, evidence, dedupe, url, body, sinks)
//   - method bindings (ensure_response, report) that close over the
//     current registry slot rather than envCtx itself, so the same
//     ctx table never carries a stale env pointer between Runs (the
//     env lives in the Lua registry; bindings look it up via
//     currentEnv on every call).
//
// Rebuilding the ctx table each Run is cheap: gopher-lua's LTable is
// a small allocation and the static references are re-attached, not
// re-built. The alternative (mutating a cached ctx table per Run) is
// fragile - a previous Run's residue on the table would leak into
// the next one.
//
// setEnv must be called before this so the per-call methods can
// resolve `env` via currentEnv. Run does this in the right order
// already; buildCtxUserdata is otherwise an inner detail.
func buildCtxUserdata(L *lua.LState, env *runEnv) *lua.LTable {
	setEnv(L, env)

	t := L.NewTable()
	t.RawSetString("check_name", lua.LString(env.check.name))
	t.RawSetString("page", buildPageTable(L, env.page))
	t.RawSetString("scope", pushScope(L, env.scope))
	t.RawSetString("client", pushClient(L, env.client))

	// Active scan level surfaces as a string. Authors compare with
	// ctx.levels.aggressive (table constant) rather than the bare
	// string so a typo at the use site fails as nil-not-equal-string.
	t.RawSetString("level", lua.LString(LevelFrom(env.ctx).String()))

	if helpers := staticFor(L); helpers != nil {
		t.RawSetString("severity", helpers.severity)
		t.RawSetString("scopes", helpers.scopes)
		t.RawSetString("levels", helpers.levels)
		t.RawSetString("locs", helpers.locs)
		t.RawSetString("evidence", helpers.evidence)
		t.RawSetString("dedupe", helpers.dedupe)
		t.RawSetString("url", helpers.url)
		t.RawSetString("body", helpers.body)
		t.RawSetString("sinks", helpers.sinks)
		t.RawSetString("html", helpers.html)
		t.RawSetString("cookies", helpers.cookies)
		t.RawSetString("takeover", helpers.takeover)
		t.RawSetString("payloads", helpers.payloads)
		t.RawSetString("oracle", helpers.oracle)
		t.RawSetString("json", helpers.json)
		t.RawSetString("oauth", helpers.oauth)
		t.RawSetString("openapi", helpers.openapi)
		t.RawSetString("deserial", helpers.deserial)
		t.RawSetString("discovery", helpers.discovery)
		t.RawSetString("host", helpers.host)
		t.RawSetString("xxe", helpers.xxe)
		t.RawSetString("browser", helpers.browser)
		t.RawSetString("tls", helpers.tls)
		t.RawSetString("ws", helpers.ws)
		t.RawSetString("idor", helpers.idor)
		t.RawSetString("stored_xss", helpers.storedXSS)
		t.RawSetString("jwt", helpers.jwt)
		t.RawSetString("race", helpers.race)
		t.RawSetString("smuggling", helpers.smuggling)
	}
	t.RawSetString("oob", pushOOBServer(L, env))
	// config carries the operator-supplied per-check settings bag
	// from the YAML config file (or an empty table when no bag was
	// supplied). Always populated so Lua authors can read
	// `ctx.config.foo` without first nil-checking ctx.config.
	t.RawSetString("config", pushConfig(L, env.check.settings))

	t.RawSetString("ensure_response", L.NewFunction(ctxEnsureResponse))
	t.RawSetString("report", L.NewFunction(ctxReport))
	t.RawSetString("level_at_least", L.NewFunction(ctxLevelAtLeast))
	return t
}

// ctxEnsureResponse mirrors the Go ensureResponse helper: if the
// page already carries headers, return that snapshot; if the
// producer tried and failed, return the ErrFetchAlreadyFailed
// sentinel; otherwise GET p.URL up to the optional max_body bytes.
//
// Args (Lua-side): ctx:ensure_response(opts?)
// opts.max_body (number) - capped read; omit/0 for headers-only.
//
// Returns (snapshot_table, nil) on success or (nil, err) on failure.
// The snapshot table mirrors what the Go check sees: status, headers
// (userdata), body (string).
func ctxEnsureResponse(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("ctx:ensure_response called outside a check run")
	}
	maxBody := int64(0)
	if t, ok := L.Get(2).(*lua.LTable); ok {
		maxBody = int64(lvalInt(t.RawGetString("max_body")))
	}
	snap, err := ensureResponse(env.ctx, env.client, env.page, maxBody)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	out := L.NewTable()
	out.RawSetString("status", lua.LNumber(snap.Status))
	if snap.Headers != nil {
		out.RawSetString("headers", pushHeaders(L, snap.Headers))
	}
	out.RawSetString("body", lua.LString(string(snap.Body)))
	L.Push(out)
	return 1
}

// ctxReport forwards a non-fatal message through the scanner's
// per-call reporter. Lua authors call this for sub-probe failures
// they swallowed so a flaky host still leaves breadcrumbs.
func ctxReport(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("ctx:report called outside a check run")
	}
	msg := requireString(L, 2)
	Report(env.ctx, errors.New(msg))
	return 0
}

// ctxLevelAtLeast returns true if the active scan level is >= the
// argument. The Lua-side `if ctx.level == ctx.levels.aggressive`
// shape only matches one level exactly; level_at_least keeps the
// "includes everything below" semantics that scan filters use
// without forcing the author to enumerate every higher level.
func ctxLevelAtLeast(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("ctx:level_at_least called outside a check run")
	}
	want, err := ParseLevel(requireString(L, 2))
	if err != nil {
		L.ArgError(2, err.Error())
	}
	L.Push(lua.LBool(LevelFrom(env.ctx) >= want))
	return 1
}
