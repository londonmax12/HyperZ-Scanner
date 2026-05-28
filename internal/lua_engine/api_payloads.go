package lua_engine

import (
	"strconv"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

// buildPayloadsTable returns the ctx.payloads helper namespace. The
// helpers here expose the Go-side payload catalogues (PayloadsFor,
// SQLiBooleanPairs, SSTIExprProbes, ...) plus the per-check pair /
// operator lists that lived as private vars in the Go check files
// until the Lua ports needed them.
//
// Catalogues are static (their entries are fixed at compile time),
// so they live on the per-VM staticHelpers bag instead of being
// rebuilt for every Run. The functions on the table are pure (no
// per-Run env access) and re-allocate the result slice per call so
// Lua-side mutation of the returned table can not race with another
// concurrent Run on the same VM.
//
// Helpers seeded here:
//
//	ctx.payloads.traversal()          -> [{name, template}]
//	ctx.payloads.sqli_error()         -> [{name, template}]
//	ctx.payloads.sqli_time()          -> [{name, template}]
//	ctx.payloads.cmd_inject()         -> [{name, template}]
//	ctx.payloads.cmd_inject_blind()   -> [{name, template}]
//	ctx.payloads.xss()                -> [{name, template}]
//
//	ctx.payloads.sqli_boolean_pairs() -> [{name, truthy, falsy}]
//	ctx.payloads.ldapi_boolean_pairs() -> [{name, truthy, falsy_tpl}]
//	ctx.payloads.ldapi_canary_placeholder() -> string
//	ctx.payloads.ldapi_error_payloads() -> [string]
//	ctx.payloads.nosqli_boolean_ops() -> [{name, key_suffix}]
//	ctx.payloads.nosqli_error_payloads() -> [string]
//
//	ctx.payloads.ssti_expr_probes()   -> [{name, template, expected}]
//	ctx.payloads.ssti_confirm_probe(template) -> {template, expected}
//	ctx.payloads.ssti_error_payloads() -> [string]
//
//	ctx.payloads.cache_poison_header_probes() -> [{header, value, canary, kind, poisoning_path}]
//	ctx.payloads.cache_poison_deception_suffix() -> string
//
//	ctx.payloads.render(template, token, sleep_secs) -> string
//	  Substitutes the {{TOKEN}} / {{SLEEP}} placeholders the catalogue
//	  templates carry. Mirrors Payload.Render so a Lua-authored check
//	  produces the same wire bytes the Go check would.
func buildPayloadsTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("traversal", L.NewFunction(payloadsTraversal))
	t.RawSetString("sqli_error", L.NewFunction(payloadsSQLiError))
	t.RawSetString("sqli_time", L.NewFunction(payloadsSQLiTime))
	t.RawSetString("cmd_inject", L.NewFunction(payloadsCmdInject))
	t.RawSetString("cmd_inject_blind", L.NewFunction(payloadsCmdInjectBlind))
	t.RawSetString("xss", L.NewFunction(payloadsXSS))

	t.RawSetString("sqli_boolean_pairs", L.NewFunction(payloadsSQLiBooleanPairs))
	t.RawSetString("ldapi_boolean_pairs", L.NewFunction(payloadsLDAPiBooleanPairs))
	t.RawSetString("ldapi_canary_placeholder", L.NewFunction(payloadsLDAPiCanaryPlaceholder))
	t.RawSetString("ldapi_error_payloads", L.NewFunction(payloadsLDAPiErrorPayloads))
	t.RawSetString("nosqli_boolean_ops", L.NewFunction(payloadsNoSQLiBooleanOps))
	t.RawSetString("nosqli_error_payloads", L.NewFunction(payloadsNoSQLiErrorPayloads))

	t.RawSetString("ssti_expr_probes", L.NewFunction(payloadsSSTIExprProbes))
	t.RawSetString("ssti_confirm_probe", L.NewFunction(payloadsSSTIConfirmProbe))
	t.RawSetString("ssti_error_payloads", L.NewFunction(payloadsSSTIErrorPayloads))

	t.RawSetString("cache_poison_header_probes", L.NewFunction(payloadsCachePoisonHeaders))
	t.RawSetString("cache_poison_deception_suffix", L.NewFunction(payloadsCachePoisonDeceptionSuffix))
	t.RawSetString("cache_poison_canary_host", L.NewFunction(payloadsCachePoisonCanaryHost))
	t.RawSetString("cache_poison_canary_path", L.NewFunction(payloadsCachePoisonCanaryPath))

	t.RawSetString("cmd_injection_filler_value", L.NewFunction(payloadsCmdInjectionFiller))
	t.RawSetString("cmd_injection_blind_oob", L.NewFunction(payloadsCmdInjectionBlindOOB))
	t.RawSetString("ssti_oob_payloads", L.NewFunction(payloadsSSTIOOB))
	t.RawSetString("loc_descriptor", L.NewFunction(payloadsLocDescriptor))

	t.RawSetString("ssrf_canary", L.NewFunction(payloadsSSRFCanary))
	t.RawSetString("ssrf_body_cap", L.NewFunction(payloadsSSRFBodyCap))
	t.RawSetString("ssrf_specific_params", L.NewFunction(payloadsSSRFSpecificParams))
	t.RawSetString("ssrf_generic_params", L.NewFunction(payloadsSSRFGenericParams))
	t.RawSetString("ssrf_looks_proxyish", L.NewFunction(payloadsSSRFLooksProxyish))

	t.RawSetString("render", L.NewFunction(payloadsRender))
	return t
}

func payloadsSSRFCanary(L *lua.LState) int {
	L.Push(lua.LString(SSRFCanaryLua()))
	return 1
}

func payloadsSSRFBodyCap(L *lua.LState) int {
	L.Push(lua.LNumber(SSRFBodyCapLua()))
	return 1
}

func payloadsSSRFSpecificParams(L *lua.LState) int {
	L.Push(pushStringList(L, SSRFSpecificParamNamesLua()))
	return 1
}

func payloadsSSRFGenericParams(L *lua.LState) int {
	L.Push(pushStringList(L, SSRFGenericParamNamesLua()))
	return 1
}

func payloadsSSRFLooksProxyish(L *lua.LState) int {
	L.Push(lua.LBool(SSRFLooksProxyish(requireString(L, 1))))
	return 1
}

func payloadsCmdInjectionFiller(L *lua.LState) int {
	L.Push(lua.LString(CmdInjectionFillerValue()))
	return 1
}

func payloadsCmdInjectionBlindOOB(L *lua.LState) int {
	src := CmdInjectionBlindOOBPayloadsLua()
	out := L.NewTable()
	for i, p := range src {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(p.Name))
		entry.RawSetString("template", lua.LString(p.Template))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func payloadsSSTIOOB(L *lua.LState) int {
	src := SSTIOOBPayloadsLua()
	out := L.NewTable()
	for i, p := range src {
		entry := L.NewTable()
		entry.RawSetString("engine", lua.LString(p.Engine))
		entry.RawSetString("template", lua.LString(p.Template))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func payloadsLocDescriptor(L *lua.LState) int {
	L.Push(lua.LString(LocDescriptorLua(requireString(L, 1))))
	return 1
}

// pushPayloadList pushes a Lua array of {name, template} tables for
// the supplied projection. Centralised so the per-class helpers stay
// one-liners and the table shape can not drift between them.
func pushPayloadList(L *lua.LState, src []SQLiErrorPayload) int {
	out := L.NewTable()
	for i, p := range src {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(p.Name))
		entry.RawSetString("template", lua.LString(p.Template))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func payloadsTraversal(L *lua.LState) int { return pushPayloadList(L, TraversalPayloadsLua()) }
func payloadsSQLiError(L *lua.LState) int { return pushPayloadList(L, SQLiErrorPayloads()) }
func payloadsSQLiTime(L *lua.LState) int  { return pushPayloadList(L, SQLiTimePayloadsLua()) }
func payloadsCmdInject(L *lua.LState) int { return pushPayloadList(L, CmdInjectPayloadsLua()) }
func payloadsCmdInjectBlind(L *lua.LState) int {
	return pushPayloadList(L, CmdInjectBlindPayloadsLua())
}
func payloadsXSS(L *lua.LState) int { return pushPayloadList(L, XSSPayloadsLua()) }

func payloadsSQLiBooleanPairs(L *lua.LState) int {
	src := SQLiBooleanPairsLua()
	out := L.NewTable()
	for i, p := range src {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(p.Name))
		entry.RawSetString("truthy", lua.LString(p.True))
		entry.RawSetString("falsy", lua.LString(p.False))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func payloadsLDAPiBooleanPairs(L *lua.LState) int {
	src := LDAPiBooleanPairsLua()
	out := L.NewTable()
	for i, p := range src {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(p.Name))
		entry.RawSetString("truthy", lua.LString(p.Truthy))
		entry.RawSetString("falsy_template", lua.LString(p.FalsyTemplate))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func payloadsLDAPiCanaryPlaceholder(L *lua.LState) int {
	L.Push(lua.LString(LDAPiCanaryPlaceholder()))
	return 1
}

func payloadsLDAPiErrorPayloads(L *lua.LState) int {
	L.Push(pushStringList(L, LDAPiErrorPayloadsLua()))
	return 1
}

func payloadsNoSQLiBooleanOps(L *lua.LState) int {
	src := NoSQLiBooleanOpsLua()
	out := L.NewTable()
	for i, op := range src {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(op.Name))
		entry.RawSetString("key_suffix", lua.LString(op.KeySuffix))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func payloadsNoSQLiErrorPayloads(L *lua.LState) int {
	L.Push(pushStringList(L, NoSQLiErrorPayloadsLua()))
	return 1
}

func payloadsSSTIExprProbes(L *lua.LState) int {
	out := L.NewTable()
	for i, p := range SSTIExprProbes() {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(p.Name))
		entry.RawSetString("template", lua.LString(p.Template))
		entry.RawSetString("expected", lua.LString(p.Expected))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func payloadsSSTIConfirmProbe(L *lua.LState) int {
	template := requireString(L, 1)
	confirmTemplate, confirmExpected := SSTIConfirmProbeLua(template)
	entry := L.NewTable()
	entry.RawSetString("template", lua.LString(confirmTemplate))
	entry.RawSetString("expected", lua.LString(confirmExpected))
	L.Push(entry)
	return 1
}

func payloadsSSTIErrorPayloads(L *lua.LState) int {
	L.Push(pushStringList(L, SSTIErrorPayloadsLua()))
	return 1
}

func payloadsCachePoisonHeaders(L *lua.LState) int {
	src := CachePoisonHeaderProbesLua()
	out := L.NewTable()
	for i, h := range src {
		entry := L.NewTable()
		entry.RawSetString("header", lua.LString(h.Header))
		entry.RawSetString("value", lua.LString(h.Value))
		entry.RawSetString("canary", lua.LString(h.Canary))
		entry.RawSetString("kind", lua.LString(h.Kind))
		entry.RawSetString("deception_message", lua.LString(h.DeceptionMessage))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func payloadsCachePoisonDeceptionSuffix(L *lua.LState) int {
	L.Push(lua.LString(CachePoisonDeceptionSuffix()))
	return 1
}

func payloadsCachePoisonCanaryHost(L *lua.LState) int {
	L.Push(lua.LString(CachePoisonCanaryHost()))
	return 1
}

func payloadsCachePoisonCanaryPath(L *lua.LState) int {
	L.Push(lua.LString(CachePoisonCanaryPath()))
	return 1
}

// payloadsRender substitutes {{TOKEN}} / {{SLEEP}} placeholders the
// catalogue templates carry. token replaces {{TOKEN}}; sleepSecs > 0
// replaces {{SLEEP}} with the literal integer. Lua-side callers do this
// in one place rather than every check re-implementing the gsub pair,
// so the placeholder vocabulary stays a single source of truth.
func payloadsRender(L *lua.LState) int {
	template := requireString(L, 1)
	token := optString(L, 2, "")
	sleepSecs := 0
	if L.GetTop() >= 3 {
		if n, ok := L.Get(3).(lua.LNumber); ok {
			sleepSecs = int(n)
		}
	}
	out := template
	if strings.Contains(out, "{{TOKEN}}") {
		out = strings.ReplaceAll(out, "{{TOKEN}}", token)
	}
	if sleepSecs > 0 && strings.Contains(out, "{{SLEEP}}") {
		out = strings.ReplaceAll(out, "{{SLEEP}}", strconv.Itoa(sleepSecs))
	}
	L.Push(lua.LString(out))
	return 1
}

func init() {
	registerHelperTable("payloads", buildPayloadsTable)
}
