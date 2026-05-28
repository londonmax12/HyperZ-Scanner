package lua_engine

import (
	"time"

	lua "github.com/yuin/gopher-lua"
)

// buildOracleTable returns the ctx.oracle helper namespace. The oracle
// functions live here (rather than under ctx.body) because they do not
// scan bytes for patterns; they verdict a tuple of snapshots that the
// per-check probe orchestration has already produced. Keeping the
// boolean / timing verdicts grouped means a Lua-authored check pulls
// in one helper table for "decide whether the differential evidence is
// vulnerability-shaped" without dragging in the body scanners next to it.
//
// Helpers seeded here:
//
//	ctx.oracle.boolean_compare(baseline, truthy, falsy)
//	  -> { decision, truthy_sim, falsy_sim, detail }
//	  Each input is a table {status = int, body = string}. Maps to
//	  BooleanCompare verbatim so the Lua-port verdict matches
//	  the Go-side check on the same wire.
//
//	ctx.oracle.timing_compare(baseline_seconds, probe_seconds,
//	                          sleep_seconds, margin)
//	  -> { vulnerable, threshold_seconds, margin_seconds, detail }
//	  Wraps TimingCompare. Lua uses seconds-as-float-doubles
//	  rather than time.Duration because gopher-lua has no native
//	  duration type; the bridge does the float -> Duration conversion
//	  symmetrically on both sides so per-check probes round-trip
//	  losslessly within the resolution that matters (millisecond floor).
//
//	ctx.oracle.similarity(a, b) -> number
//	  Wraps Similarity. Lets a check show the two contributing
//	  scores in its evidence text without re-running the BooleanCompare
//	  path twice.
func buildOracleTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("boolean_compare", L.NewFunction(oracleBooleanCompare))
	t.RawSetString("timing_compare", L.NewFunction(oracleTimingCompare))
	t.RawSetString("similarity", L.NewFunction(oracleSimilarity))
	return t
}

func readSnapshotArg(v lua.LValue) Snapshot {
	t, ok := v.(*lua.LTable)
	if !ok {
		return Snapshot{}
	}
	return Snapshot{
		Status: lvalInt(t.RawGetString("status")),
		Body:   []byte(lvalString(t.RawGetString("body"))),
	}
}

func oracleBooleanCompare(L *lua.LState) int {
	baseline := readSnapshotArg(L.Get(1))
	truthy := readSnapshotArg(L.Get(2))
	falsy := readSnapshotArg(L.Get(3))
	res := BooleanCompare(baseline, truthy, falsy)
	out := L.NewTable()
	out.RawSetString("decision", lua.LString(string(res.Decision)))
	out.RawSetString("truthy_sim", lua.LNumber(res.TruthySim))
	out.RawSetString("falsy_sim", lua.LNumber(res.FalsySim))
	out.RawSetString("detail", lua.LString(res.Detail))
	L.Push(out)
	return 1
}

func oracleTimingCompare(L *lua.LState) int {
	baselineSec := lvalNumber(L.Get(1))
	probeSec := lvalNumber(L.Get(2))
	sleepSec := lvalNumber(L.Get(3))
	margin := lvalNumber(L.Get(4))
	res := TimingCompare(
		time.Duration(baselineSec*float64(time.Second)),
		time.Duration(probeSec*float64(time.Second)),
		time.Duration(sleepSec*float64(time.Second)),
		margin,
	)
	out := L.NewTable()
	out.RawSetString("vulnerable", lua.LBool(res.Vulnerable))
	out.RawSetString("threshold_seconds", lua.LNumber(res.Threshold.Seconds()))
	out.RawSetString("margin_seconds", lua.LNumber(res.Margin.Seconds()))
	out.RawSetString("detail", lua.LString(res.Detail))
	L.Push(out)
	return 1
}

func oracleSimilarity(L *lua.LState) int {
	a := RequireString(L, 1)
	b := RequireString(L, 2)
	L.Push(lua.LNumber(Similarity([]byte(a), []byte(b))))
	return 1
}

// lvalNumber coerces v to a Go float64. Non-numbers (nil, strings,
// userdata) collapse to 0. Mirrors lvalString / lvalInt but for the
// floating-point path the oracle helpers need to read latency / margin
// values from Lua without forcing the author to differentiate int vs
// float at the call site.
func lvalNumber(v lua.LValue) float64 {
	if v == nil || v == lua.LNil {
		return 0
	}
	if n, ok := v.(lua.LNumber); ok {
		return float64(n)
	}
	return 0
}

func init() {
	RegisterHelperTable("oracle", buildOracleTable)
}
