package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// buildRaceTable returns the ctx.race helper namespace. The single
// scan() entry point bundles target collection and per-target single-
// packet probing into one Go-side pass so the per-LuaCheck cross-page
// dedupe set and the per-page target cap stay in Go where they were
// already implemented and tested. The Lua side consumes raw scan
// facts (target descriptor + baseline status + per-connection probe
// outcomes) and decides on its own which represent a race signal,
// how the histogram reads in the finding text, what severity to
// stamp, and how the dedupe key is shaped.
//
// The per-LuaCheck *RaceCondition instance is held via
// AuxOrCreate so the cross-page target-seen set survives across
// every Run on this LuaCheck the same way the Go check's
// `&RaceCondition{}` registration does. Same pattern as the
// IDOR corpus, the stored-xss state container, and the jwt-vulns
// probed-token set: one scan, one shared state.
func buildRaceTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("scan", L.NewFunction(raceScan))
	return t
}

// raceCheckKey identifies the per-LuaCheck slot the shared
// *RaceCondition lives in. Unique zero-size type per the
// AuxOrCreate convention used by the IDOR / JWT / stored-xss bridges.
type raceCheckKey struct{}

func raceScan(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("ctx.race.scan called outside a check run")
	}
	rc := env.check.AuxOrCreate(raceCheckKey{}, func() any {
		return &RaceCondition{}
	}).(*RaceCondition)
	facts, err := rc.ScanFacts(env.ctx, env.scope, env.page)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(raceFactsToLua(L, facts))
	return 1
}

// raceFactsToLua converts the []RaceTargetFact the Go check produced
// into the array-of-tables shape the Lua composer consumes. Each
// entry is one probed target: descriptor fields (method, url,
// source, ...) and the structural probe results (baseline status,
// per-connection outcomes). Keeping the conversion in one function
// keeps the wire shape between Go and Lua centralised so adding a
// field on RaceTargetFact lands once.
func raceFactsToLua(L *lua.LState, facts []RaceTargetFact) *lua.LTable {
	out := L.NewTable()
	for i, f := range facts {
		entry := L.NewTable()
		entry.RawSetString("method", lua.LString(f.Method))
		entry.RawSetString("url", lua.LString(f.URL))
		entry.RawSetString("body_len", lua.LNumber(f.BodyLen))
		entry.RawSetString("content_type", lua.LString(f.ContentType))
		entry.RawSetString("source", lua.LString(f.Source))
		entry.RawSetString("target_key", lua.LString(f.TargetKey))
		entry.RawSetString("baseline_status", lua.LNumber(f.BaselineStatus))

		probes := L.NewTable()
		for j, p := range f.Probes {
			pt := L.NewTable()
			pt.RawSetString("status", lua.LNumber(p.Status))
			pt.RawSetString("body_hash", lua.LString(p.BodyHash))
			pt.RawSetString("err", lua.LString(p.Err))
			probes.RawSetInt(j+1, pt)
		}
		entry.RawSetString("probes", probes)
		out.RawSetInt(i+1, entry)
	}
	return out
}

func init() {
	registerHelperTable("race", buildRaceTable)
}
