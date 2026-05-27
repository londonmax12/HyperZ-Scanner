package lua_engine

import (
	"net/url"
	"sync"

	lua "github.com/yuin/gopher-lua"
)

// buildHostTable returns the ctx.host helper namespace. Host-scoped
// checks (content-discovery, vendor checks that probe a host root,
// future per-host fingerprint extensions) share this namespace so a
// crawl that yields many pages on one host fires the host-level work
// exactly once.
//
// Surface:
//
//	ctx.host.claim_once(host_root) -> bool
//	  Atomically marks host_root as claimed by this LuaCheck instance
//	  and reports whether this caller won the race. State lives on
//	  the LuaCheck (AuxOrCreate) so the lifetime mirrors a single
//	  scan session; a separate scan starts with an empty claim set.
//	  Use at the entry of a host-scoped Run to skip duplicate work
//	  on subsequent pages from the same host without each check
//	  open-coding its own sync.Map.
func buildHostTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("claim_once", L.NewFunction(hostClaimOnce))
	t.RawSetString("claim_from_page", L.NewFunction(hostClaimFromPage))
	return t
}

// hostClaimFromPage collapses the 5-line "parse page URL -> derive
// host_root -> scope-gate -> claim_once" prelude that ~30 host-scoped
// checks repeat verbatim into a single call.
//
// Returns (host_root, ok). ok=false collapses every reject path
// (malformed URL, scope denies, claim already taken) into one - the
// caller's only sensible reaction is `if not ok then return nil end`,
// so funneling all three rejections through one boolean removes the
// per-check error-path noise without losing any decision the original
// 5 lines could express.
//
// host_root is the scheme://host prefix (no path / query). The URL
// comes from the runtime env's page (ctx.page.url in Lua), not from
// an argument, because every existing caller derives it from the page
// anyway. Hosts that need a different root use the per-helper
// primitives (ctx.url.parse + ctx.scope:allows + ctx.host.claim_once).
func hostClaimFromPage(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("ctx.host:claim_from_page called outside a check run")
	}
	u, err := url.Parse(env.page.URL)
	if err != nil || u == nil || u.Scheme == "" || u.Host == "" {
		L.Push(lua.LString(""))
		L.Push(lua.LBool(false))
		return 2
	}
	hostRoot := u.Scheme + "://" + u.Host
	if env.scope != nil && !env.scope.Allows(u) {
		L.Push(lua.LString(""))
		L.Push(lua.LBool(false))
		return 2
	}
	claims := env.check.AuxOrCreate(hostClaimsKey{}, func() any {
		return &hostClaims{set: map[string]struct{}{}}
	}).(*hostClaims)
	claims.mu.Lock()
	defer claims.mu.Unlock()
	if _, taken := claims.set[hostRoot]; taken {
		L.Push(lua.LString(""))
		L.Push(lua.LBool(false))
		return 2
	}
	claims.set[hostRoot] = struct{}{}
	L.Push(lua.LString(hostRoot))
	L.Push(lua.LBool(true))
	return 2
}

// hostClaimsKey identifies the per-LuaCheck slot for the host-claim
// set on the LuaCheck's aux map. Unique zero-size type so
// AuxOrCreate's key equality cannot collide with another helper's
// slot.
type hostClaimsKey struct{}

// hostClaims holds the deduplicated set of host roots this LuaCheck
// instance has already processed. The mutex covers concurrent Run
// invocations from the scanner's per-target fanout.
type hostClaims struct {
	mu  sync.Mutex
	set map[string]struct{}
}

// hostClaimOnce claims host_root for this LuaCheck instance and
// returns true exactly once per (host_root, check) tuple. Subsequent
// calls return false so the caller can short-circuit duplicate
// host-level work. Calling outside a check run raises a Lua error.
func hostClaimOnce(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("ctx.host.claim_once called outside a check run")
	}
	hostRoot := requireString(L, 1)
	claims := env.check.AuxOrCreate(hostClaimsKey{}, func() any {
		return &hostClaims{set: map[string]struct{}{}}
	}).(*hostClaims)
	claims.mu.Lock()
	defer claims.mu.Unlock()
	if _, ok := claims.set[hostRoot]; ok {
		L.Push(lua.LBool(false))
		return 1
	}
	claims.set[hostRoot] = struct{}{}
	L.Push(lua.LBool(true))
	return 1
}
