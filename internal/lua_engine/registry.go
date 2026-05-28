package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// envRegistryKey is the slot in the Lua registry where each Run
// stashes its *RunEnv. Bindings (ensure_response, report, client
// methods, ...) read it back via CurrentEnv. Using the registry
// instead of a Go closure means one VM can serve many sequential
// Runs with different envs without rebuilding any closures.
const envRegistryKey = "__hyperz_env"

// metatableSlot names the slot under which each userdata kind stashes
// its shared metatable in the Lua registry. Centralized so the
// per-kind binders (client, scope, headers) don't drift on key naming.
const (
	mtClient  = "__hyperz_mt_client"
	mtScope   = "__hyperz_mt_scope"
	mtHeaders = "__hyperz_mt_headers"
	mtRequest = "__hyperz_mt_request"
	mtResp    = "__hyperz_mt_response"
	mtSink    = "__hyperz_mt_sink"
	mtOOB     = "__hyperz_mt_oob"
)

// setEnv installs env in the Lua registry so per-call bindings can
// read it. Called by Run before each PCall. Pairs with clearEnv,
// which the release path uses to drop the reference so the pooled
// VM does not retain a stale pointer between calls.
func setEnv(L *lua.LState, env *RunEnv) {
	ud := L.NewUserData()
	ud.Value = env
	L.G.Registry.RawSetString(envRegistryKey, ud)
}

// CurrentEnv returns the *RunEnv attached to L by the active Run.
// Returns nil when called outside a Run (e.g. during VM warmup or
// after a release that cleared the env). Bindings should treat nil
// as an internal error - a Lua-callable function reaching this path
// means the engine ran user code without setting the env up first,
// which is a programmer error in the bridge, not in the check.
func CurrentEnv(L *lua.LState) *RunEnv {
	v := L.G.Registry.RawGetString(envRegistryKey)
	ud, ok := v.(*lua.LUserData)
	if !ok || ud == nil {
		return nil
	}
	env, _ := ud.Value.(*RunEnv)
	return env
}

// staticHelpersKey names the registry slot where the static helper
// tables (evidence, dedupe, url, body, ...) live. Those tables are
// built once at VM creation and re-attached to each per-Run ctx by
// buildCtxUserdata - storing them centrally lets the per-Run path
// snap the references in without rebuilding every helper for every
// check invocation.
const staticHelpersKey = "__hyperz_static"

// staticHelpers maps each registered Lua-side namespace name (e.g.
// "evidence", "stored_xss") to the *lua.LTable produced by that
// namespace's builder. The per-Run path reads tables by name and
// assigns them as-is to ctx; the tables are immutable from Lua (no
// setter API is exposed) but we still re-share the same instance
// across every Run since gopher-lua tables are not subject to GC
// pressure during a single VM's lifetime.
//
// Pure-constant vocabularies (severity, scopes, levels, locs, cms,
// methods, ...) are NOT here - they live in Lua globals installed by
// installConstGlobals so meta-table fields (applies_to, patched_in,
// tier, level, scope, consumes) can reference them at module-load
// time, before any ctx exists.
type staticHelpers map[string]*lua.LTable

func storeStaticHelpers(L *lua.LState, h staticHelpers) {
	ud := L.NewUserData()
	ud.Value = h
	L.G.Registry.RawSetString(staticHelpersKey, ud)
}

func staticFor(L *lua.LState) staticHelpers {
	v := L.G.Registry.RawGetString(staticHelpersKey)
	ud, ok := v.(*lua.LUserData)
	if !ok || ud == nil {
		return nil
	}
	h, _ := ud.Value.(staticHelpers)
	return h
}
