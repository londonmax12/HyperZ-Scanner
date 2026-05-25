package luabridge

import (
	lua "github.com/yuin/gopher-lua"
)

// envRegistryKey is the slot in the Lua registry where each Run
// stashes its *runEnv. Bindings (ensure_response, report, client
// methods, ...) read it back via currentEnv. Using the registry
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
func setEnv(L *lua.LState, env *runEnv) {
	ud := L.NewUserData()
	ud.Value = env
	L.G.Registry.RawSetString(envRegistryKey, ud)
}

func clearEnv(L *lua.LState) {
	L.G.Registry.RawSetString(envRegistryKey, lua.LNil)
}

// currentEnv returns the *runEnv attached to L by the active Run.
// Returns nil when called outside a Run (e.g. during VM warmup or
// after a release that cleared the env). Bindings should treat nil
// as an internal error - a Lua-callable function reaching this path
// means the engine ran user code without setting the env up first,
// which is a programmer error in the bridge, not in the check.
func currentEnv(L *lua.LState) *runEnv {
	v := L.G.Registry.RawGetString(envRegistryKey)
	ud, ok := v.(*lua.LUserData)
	if !ok || ud == nil {
		return nil
	}
	env, _ := ud.Value.(*runEnv)
	return env
}

// staticHelpersKey names the registry slot where the static helper
// tables (severity, scopes, evidence, dedupe, url, body) live. Those
// tables are built once at VM creation and re-attached to each
// per-Run ctx by buildCtxUserdata - storing them centrally lets the
// per-Run path snap the references in without rebuilding every helper
// for every check invocation.
const staticHelpersKey = "__hyperz_static"

// staticHelpers is the bag of pre-built helper tables snapped onto
// the per-Run ctx. Each field is a *lua.LTable that the per-Run path
// assigns to ctx as-is; the tables are immutable from Lua (no setter
// API is exposed) but we still re-share the same instance across
// every Run since gopher-lua tables are not subject to GC pressure
// during a single VM's lifetime.
type staticHelpers struct {
	severity *lua.LTable
	scopes   *lua.LTable
	levels   *lua.LTable
	locs     *lua.LTable
	evidence *lua.LTable
	dedupe   *lua.LTable
	url      *lua.LTable
	body     *lua.LTable
	sinks    *lua.LTable
	html     *lua.LTable
	cookies  *lua.LTable
	takeover *lua.LTable
	payloads *lua.LTable
	oracle   *lua.LTable
	json     *lua.LTable
	oauth    *lua.LTable
	openapi  *lua.LTable
	deserial *lua.LTable
}

func storeStaticHelpers(L *lua.LState, h *staticHelpers) {
	ud := L.NewUserData()
	ud.Value = h
	L.G.Registry.RawSetString(staticHelpersKey, ud)
}

func staticFor(L *lua.LState) *staticHelpers {
	v := L.G.Registry.RawGetString(staticHelpersKey)
	ud, ok := v.(*lua.LUserData)
	if !ok || ud == nil {
		return nil
	}
	h, _ := ud.Value.(*staticHelpers)
	return h
}
