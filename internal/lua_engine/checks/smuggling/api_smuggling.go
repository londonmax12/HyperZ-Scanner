package smuggling

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// buildSmugglingTable returns the ctx.smuggling helper namespace.
// The single scan(catalogue) entry point bundles baseline measurement
// + per-variant probing + the per-host cache into one Go-side pass.
// catalogue selects the registered family bundle ("framing" covers
// today's HTTP/1.1 framing pairs + H2.CL downgrade; future sibling
// catalogues like "h2c" register additional protocol families).
// The Lua composer reads the raw timings and variant labels, decides
// which (if any) confirmed variant to surface, and stamps its own
// severity / title / detail / remediation / dedupe-key shape onto
// the resulting finding.
//
// The per-LuaCheck *RequestSmuggling instance is held via
// AuxOrCreate so the cross-page host-cache survives across every Run
// on this LuaCheck. Same lifecycle as IDOR / JWT / race-condition:
// one scan, one shared state, and the second Page on the same host
// gets FromCache=true so the Lua port can decide whether to re-emit
// the per-host finding for the active page.
//
// Raw-socket HTTP/1.1 framing and HPACK encoding stay in Go because
// re-implementing them in Lua would be expensive without making the
// rule more editable. The .lua file owns every operator-visible
// string instead.
func buildSmugglingTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("scan", L.NewFunction(smugglingScan))
	t.RawSetString("hang_threshold_ms", L.NewFunction(smugglingHangThresholdFn))
	return t
}

// smugglingCheckKey identifies the per-LuaCheck slot the shared
// *RequestSmuggling lives in. Unique zero-size type per the
// AuxOrCreate convention.
type smugglingCheckKey struct{}

func smugglingScan(L *lua.LState) int {
	env := lua_engine.CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.smuggling.scan called outside a check run")
	}
	catalogue := lua_engine.RequireString(L, 1)
	rs := env.Check.AuxOrCreate(smugglingCheckKey{}, func() any {
		return &RequestSmuggling{}
	}).(*RequestSmuggling)
	hostFact, err := rs.ScanFacts(env.Ctx, env.Scope, env.Page, catalogue)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	if hostFact == nil {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(smugglingFactToLua(L, hostFact))
	return 1
}

func smugglingHangThresholdFn(L *lua.LState) int {
	L.Push(lua.LNumber(SmugglingHangThresholdMS()))
	return 1
}

// smugglingFactToLua converts the SmugglingHostFact the Go check
// produced into the table shape the Lua composer consumes. The
// variant slice is preserved in scan order; the Lua side decides
// which entries fire a finding by reading Confirmed (single-variant
// emit policy) or by aggregating across variants (per-host emit).
// FromCache surfaces verbatim so the Lua port can skip the re-probe
// branch when the host already produced its verdict.
func smugglingFactToLua(L *lua.LState, hostFact *SmugglingHostFact) *lua.LTable {
	out := L.NewTable()
	out.RawSetString("host_key", lua.LString(hostFact.HostKey))
	out.RawSetString("from_cache", lua.LBool(hostFact.FromCache))
	variants := L.NewTable()
	for i, v := range hostFact.Variants {
		vt := L.NewTable()
		vt.RawSetString("label", lua.LString(v.Label))
		vt.RawSetString("front_end", lua.LString(v.FrontEnd))
		vt.RawSetString("back_end", lua.LString(v.BackEnd))
		vt.RawSetString("description", lua.LString(v.Description))
		vt.RawSetString("proto", lua.LString(v.Proto))
		vt.RawSetString("baseline_ms", lua.LNumber(v.BaselineMS))
		vt.RawSetString("probe1_ms", lua.LNumber(v.Probe1MS))
		vt.RawSetString("probe2_ms", lua.LNumber(v.Probe2MS))
		vt.RawSetString("threshold_ms", lua.LNumber(v.ThresholdMS))
		vt.RawSetString("confirmed", lua.LBool(v.Confirmed))
		vt.RawSetString("probed", lua.LBool(v.Probed))
		vt.RawSetString("skip_reason", lua.LString(v.SkipReason))
		variants.RawSetInt(i+1, vt)
	}
	out.RawSetString("variants", variants)
	return out
}

func init() {
	lua_engine.RegisterHelperTable("smuggling", buildSmugglingTable)
}
