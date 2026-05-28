package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// buildJWTTable returns the ctx.jwt helper namespace. Two entry
// points - scan(page_url) and drain() - mirror the Go check's Run
// and Drain methods respectively, but emit raw scan facts (kind +
// params bag per fact) rather than already-composed findings. The
// Lua port iterates the facts, dispatches on kind, and composes its
// own findings - so severity / title / detail / remediation prose
// lives in the .lua catalog file and is editable without
// recompiling the scanner.
//
// The per-LuaCheck *JWTVulns instance is held via AuxOrCreate
// so the cross-page token-fingerprint dedupe set (the c.probed map)
// survives across every Run on this LuaCheck the same way the Go
// check's `&JWTVulns{}` registration does. Same pattern as
// the IDOR corpus and the stored-xss state container; one scan,
// one shared probe-history map.
//
// JWT crypto is left in Go on purpose. The probes drive RFC 7515
// alg pinning, HMAC sign with attacker-controlled keys, RSA public-
// key extraction for asymmetric->HMAC confusion, base64url codec,
// and an OOB-canary fan-out for jku/x5u. Re-implementing any of
// those in Lua would be expensive without making the rule more
// editable - the per-finding severity / text / remediation prose
// is what an operator might actually want to rewrite, and that
// stays Lua-side.
func buildJWTTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("scan", L.NewFunction(jwtScan))
	t.RawSetString("drain", L.NewFunction(jwtDrain))
	return t
}

// jwtCheckKey identifies the per-LuaCheck slot the shared
// *JWTVulns lives in. Unique zero-size type per AuxOrCreate
// convention.
type jwtCheckKey struct{}

func jwtScan(L *lua.LState) int {
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.jwt.scan called outside a check run")
	}
	jwt := env.Check.AuxOrCreate(jwtCheckKey{}, func() any {
		return &JWTVulns{}
	}).(*JWTVulns)
	facts, err := jwt.ScanFacts(env.Ctx, env.Client, env.Scope, env.Page)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(jwtFactsToLua(L, facts))
	return 1
}

// jwtDrain runs the OOB drain pass and surfaces the resulting facts.
// The Lua check.drain entry point calls into this so the OOB
// confirmation findings still flow when the Lua port has shadowed
// the Go check via mergeLuaOverrides. Without this bridge, the OOB
// callbacks would land on the listener and never produce findings
// because the Go *JWTVulns lives under the LuaCheck aux map, not in
// the scanner's check list.
func jwtDrain(L *lua.LState) int {
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.jwt.drain called outside a check run")
	}
	jwt, _ := env.Check.AuxOrCreate(jwtCheckKey{}, func() any {
		return &JWTVulns{}
	}).(*JWTVulns)
	if jwt == nil {
		L.Push(L.NewTable())
		return 1
	}
	// Drain inspects OOBFrom(ctx); pass through the env ctx the
	// scanner already wired with the active OOB server.
	facts := jwt.DrainFacts(env.Ctx)
	L.Push(jwtFactsToLua(L, facts))
	return 1
}

func jwtFactsToLua(L *lua.LState, facts []JWTFact) *lua.LTable {
	out := L.NewTable()
	for i, f := range facts {
		entry := L.NewTable()
		entry.RawSetString("kind", lua.LString(f.Kind))
		entry.RawSetString("target", lua.LString(f.Target))
		params := L.NewTable()
		for k, v := range f.Params {
			switch tv := v.(type) {
			case string:
				params.RawSetString(k, lua.LString(tv))
			case int:
				params.RawSetString(k, lua.LNumber(tv))
			case float64:
				params.RawSetString(k, lua.LNumber(tv))
			case bool:
				params.RawSetString(k, lua.LBool(tv))
			case []string:
				params.RawSetString(k, pushStringList(L, tv))
			default:
				// Coerce anything else to its Go fmt; the Lua side
				// reads it as a string and a typo at the consumer
				// fails as nil-not-equal-string rather than via a
				// type panic at the binding boundary.
				params.RawSetString(k, lua.LString(toString(v)))
			}
		}
		entry.RawSetString("params", params)
		out.RawSetInt(i+1, entry)
	}
	return out
}

func toString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	type stringer interface{ String() string }
	if s, ok := v.(stringer); ok {
		return s.String()
	}
	return ""
}

func init() {
	RegisterHelperTable("jwt", buildJWTTable)
}
