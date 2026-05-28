package injection

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// buildInjectionTable returns the ctx.injection helper namespace. The
// surface bundles every body-scanning / payload-catalogue helper the
// injection family's per-check .lua ports consume - SQLi error / time
// helpers, path-traversal markers, LDAP / NoSQL / SSTI / cmd-injection
// catalogues, SSRF param lists, and the proto-pollution JSON sniffer.
// They used to live on the root ctx.body / ctx.payloads but are
// check-specific to the injection family, so they moved with the Go
// files when the family was lifted into its own subpackage.
//
// The .lua port reads each helper exactly as it did under
// ctx.body.X / ctx.payloads.X - only the table prefix changed.
//
// Entry points (catalogues):
//
//	ctx.injection.traversal()                 -> [{name, template}]
//	ctx.injection.sqli_error()                -> [{name, template}]
//	ctx.injection.sqli_time()                 -> [{name, template}]
//	ctx.injection.cmd_inject()                -> [{name, template}]
//	ctx.injection.cmd_inject_blind()          -> [{name, template}]
//	ctx.injection.sqli_boolean_pairs()        -> [{name, truthy, falsy}]
//	ctx.injection.ldapi_boolean_pairs()       -> [{name, truthy, falsy_template}]
//	ctx.injection.ldapi_canary_placeholder()  -> string
//	ctx.injection.ldapi_error_payloads()      -> [string]
//	ctx.injection.nosqli_boolean_ops()        -> [{name, key_suffix}]
//	ctx.injection.nosqli_error_payloads()     -> [string]
//	ctx.injection.ssti_expr_probes()          -> [{name, template, expected}]
//	ctx.injection.ssti_confirm_probe(tmpl)    -> {template, expected}
//	ctx.injection.ssti_error_payloads()       -> [string]
//	ctx.injection.ssti_oob_payloads()         -> [{engine, template}]
//	ctx.injection.cmd_injection_blind_oob()   -> [{name, template}]
//	ctx.injection.cmd_injection_filler_value()-> string
//	ctx.injection.ssrf_canary()               -> string
//	ctx.injection.ssrf_body_cap()             -> int
//	ctx.injection.ssrf_specific_params()      -> [string]
//	ctx.injection.ssrf_generic_params()       -> [string]
//	ctx.injection.ssrf_looks_proxyish(path)   -> bool
//
// Entry points (body scanners + timing knobs):
//
//	ctx.injection.sqli_error_new_matches(body, baseline) -> [string]
//	ctx.injection.sqli_error_payloads()                  -> [{name, template}]
//	ctx.injection.sqli_time_sleep_seconds()              -> int
//	ctx.injection.sqli_time_margin()                     -> float
//	ctx.injection.traversal_new_markers(body, baseline)  -> [string]
//	ctx.injection.traversal_markers(body)                -> [string]
//	ctx.injection.ldap_error_new_matches(body, baseline) -> [string]
//	ctx.injection.ldapi_sink_probable(loc)               -> bool
//	ctx.injection.mongo_error_new_matches(body, base)    -> [string]
//	ctx.injection.nosqli_sink_probable(loc)              -> bool
//	ctx.injection.nosqli_build_operator_request(sink, op_name, op_value)
//	  -> (request_userdata, err_string)
//	ctx.injection.ssti_error_new_matches(body, baseline) -> [string]
//	ctx.injection.cmd_error_first_match(body)            -> string
//	ctx.injection.cmd_injection_sleep_seconds()          -> int
//	ctx.injection.cmd_injection_margin()                 -> float
//	ctx.injection.ssrf_matches_error(body)               -> string
//	ctx.injection.is_json_response(content_type, body)   -> bool
//	ctx.injection.json_indent_width(body)                -> int
//	ctx.injection.xxe_error_patterns(body)               -> [string]
//	ctx.injection.xxe_base64_markers(body)               -> [string]
//	ctx.injection.path_sink_candidate(sink)              -> bool
//	ctx.injection.loc_descriptor(loc)                    -> string
func buildInjectionTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	// Payload catalogues.
	t.RawSetString("traversal", L.NewFunction(injectionTraversal))
	t.RawSetString("sqli_error", L.NewFunction(injectionSQLiError))
	t.RawSetString("sqli_time", L.NewFunction(injectionSQLiTime))
	t.RawSetString("cmd_inject", L.NewFunction(injectionCmdInject))
	t.RawSetString("cmd_inject_blind", L.NewFunction(injectionCmdInjectBlind))
	t.RawSetString("sqli_boolean_pairs", L.NewFunction(injectionSQLiBooleanPairs))
	t.RawSetString("ldapi_boolean_pairs", L.NewFunction(injectionLDAPiBooleanPairs))
	t.RawSetString("ldapi_canary_placeholder", L.NewFunction(injectionLDAPiCanaryPlaceholder))
	t.RawSetString("ldapi_error_payloads", L.NewFunction(injectionLDAPiErrorPayloads))
	t.RawSetString("nosqli_boolean_ops", L.NewFunction(injectionNoSQLiBooleanOps))
	t.RawSetString("nosqli_error_payloads", L.NewFunction(injectionNoSQLiErrorPayloads))
	t.RawSetString("ssti_expr_probes", L.NewFunction(injectionSSTIExprProbes))
	t.RawSetString("ssti_confirm_probe", L.NewFunction(injectionSSTIConfirmProbe))
	t.RawSetString("ssti_error_payloads", L.NewFunction(injectionSSTIErrorPayloads))
	t.RawSetString("ssti_oob_payloads", L.NewFunction(injectionSSTIOOB))
	t.RawSetString("cmd_injection_blind_oob", L.NewFunction(injectionCmdInjectionBlindOOB))
	t.RawSetString("cmd_injection_filler_value", L.NewFunction(injectionCmdInjectionFiller))
	t.RawSetString("ssrf_canary", L.NewFunction(injectionSSRFCanary))
	t.RawSetString("ssrf_body_cap", L.NewFunction(injectionSSRFBodyCap))
	t.RawSetString("ssrf_specific_params", L.NewFunction(injectionSSRFSpecificParams))
	t.RawSetString("ssrf_generic_params", L.NewFunction(injectionSSRFGenericParams))
	t.RawSetString("ssrf_looks_proxyish", L.NewFunction(injectionSSRFLooksProxyish))
	// Body scanners + sink heuristics + timing knobs.
	t.RawSetString("sqli_error_new_matches", L.NewFunction(injectionSQLiErrorNewMatches))
	t.RawSetString("sqli_error_payloads", L.NewFunction(injectionSQLiErrorPayloads))
	t.RawSetString("sqli_time_sleep_seconds", L.NewFunction(injectionSQLiTimeSleepSeconds))
	t.RawSetString("sqli_time_margin", L.NewFunction(injectionSQLiTimeMargin))
	t.RawSetString("traversal_new_markers", L.NewFunction(injectionTraversalNewMarkers))
	t.RawSetString("traversal_markers", L.NewFunction(injectionTraversalMarkers))
	t.RawSetString("ldap_error_new_matches", L.NewFunction(injectionLDAPErrorNewMatches))
	t.RawSetString("ldapi_sink_probable", L.NewFunction(injectionLDAPiSinkProbable))
	t.RawSetString("mongo_error_new_matches", L.NewFunction(injectionMongoErrorNewMatches))
	t.RawSetString("nosqli_sink_probable", L.NewFunction(injectionNoSQLiSinkProbable))
	t.RawSetString("nosqli_build_operator_request", L.NewFunction(injectionNoSQLiBuildOperatorRequest))
	t.RawSetString("ssti_error_new_matches", L.NewFunction(injectionSSTIErrorNewMatches))
	t.RawSetString("cmd_error_first_match", L.NewFunction(injectionCmdErrorFirstMatch))
	t.RawSetString("cmd_injection_sleep_seconds", L.NewFunction(injectionCmdInjectionSleepSeconds))
	t.RawSetString("cmd_injection_margin", L.NewFunction(injectionCmdInjectionMargin))
	t.RawSetString("ssrf_matches_error", L.NewFunction(injectionSSRFMatchesError))
	t.RawSetString("is_json_response", L.NewFunction(injectionIsJSONResponse))
	t.RawSetString("json_indent_width", L.NewFunction(injectionJSONIndentWidth))
	t.RawSetString("xxe_error_patterns", L.NewFunction(injectionXXEErrorPatterns))
	t.RawSetString("xxe_base64_markers", L.NewFunction(injectionXXEBase64Markers))
	t.RawSetString("path_sink_candidate", L.NewFunction(injectionPathSinkCandidate))
	t.RawSetString("loc_descriptor", L.NewFunction(injectionLocDescriptor))
	return t
}

// -- Payload catalogues ----------------------------------------------

func injectionTraversal(L *lua.LState) int {
	return lua_engine.PushPayloadList(L, lua_engine.TraversalPayloadsLua())
}

func injectionSQLiError(L *lua.LState) int {
	return lua_engine.PushPayloadList(L, lua_engine.SQLiErrorPayloads())
}

func injectionSQLiTime(L *lua.LState) int {
	return lua_engine.PushPayloadList(L, lua_engine.SQLiTimePayloadsLua())
}

func injectionCmdInject(L *lua.LState) int {
	return lua_engine.PushPayloadList(L, lua_engine.CmdInjectPayloadsLua())
}

func injectionCmdInjectBlind(L *lua.LState) int {
	return lua_engine.PushPayloadList(L, lua_engine.CmdInjectBlindPayloadsLua())
}

func injectionSQLiBooleanPairs(L *lua.LState) int {
	src := lua_engine.SQLiBooleanPairsLua()
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

func injectionLDAPiBooleanPairs(L *lua.LState) int {
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

func injectionLDAPiCanaryPlaceholder(L *lua.LState) int {
	L.Push(lua.LString(LDAPiCanaryPlaceholder()))
	return 1
}

func injectionLDAPiErrorPayloads(L *lua.LState) int {
	L.Push(lua_engine.PushStringList(L, LDAPiErrorPayloadsLua()))
	return 1
}

func injectionNoSQLiBooleanOps(L *lua.LState) int {
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

func injectionNoSQLiErrorPayloads(L *lua.LState) int {
	L.Push(lua_engine.PushStringList(L, NoSQLiErrorPayloadsLua()))
	return 1
}

func injectionSSTIExprProbes(L *lua.LState) int {
	out := L.NewTable()
	for i, p := range lua_engine.SSTIExprProbes() {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(p.Name))
		entry.RawSetString("template", lua.LString(p.Template))
		entry.RawSetString("expected", lua.LString(p.Expected))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func injectionSSTIConfirmProbe(L *lua.LState) int {
	template := lua_engine.RequireString(L, 1)
	confirmTemplate, confirmExpected := SSTIConfirmProbeLua(template)
	entry := L.NewTable()
	entry.RawSetString("template", lua.LString(confirmTemplate))
	entry.RawSetString("expected", lua.LString(confirmExpected))
	L.Push(entry)
	return 1
}

func injectionSSTIErrorPayloads(L *lua.LState) int {
	L.Push(lua_engine.PushStringList(L, SSTIErrorPayloadsLua()))
	return 1
}

func injectionSSTIOOB(L *lua.LState) int {
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

func injectionCmdInjectionBlindOOB(L *lua.LState) int {
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

func injectionCmdInjectionFiller(L *lua.LState) int {
	L.Push(lua.LString(CmdInjectionFillerValue()))
	return 1
}

func injectionSSRFCanary(L *lua.LState) int {
	L.Push(lua.LString(SSRFCanaryLua()))
	return 1
}

func injectionSSRFBodyCap(L *lua.LState) int {
	L.Push(lua.LNumber(SSRFBodyCapLua()))
	return 1
}

func injectionSSRFSpecificParams(L *lua.LState) int {
	L.Push(lua_engine.PushStringList(L, SSRFSpecificParamNamesLua()))
	return 1
}

func injectionSSRFGenericParams(L *lua.LState) int {
	L.Push(lua_engine.PushStringList(L, SSRFGenericParamNamesLua()))
	return 1
}

func injectionSSRFLooksProxyish(L *lua.LState) int {
	L.Push(lua.LBool(SSRFLooksProxyish(lua_engine.RequireString(L, 1))))
	return 1
}

// -- Body scanners + sink heuristics + timing knobs ------------------

func injectionSQLiErrorNewMatches(L *lua.LState) int {
	body := lua_engine.RequireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = lua_engine.LValString(L.Get(2))
	}
	L.Push(lua_engine.PushStringList(L, SQLiErrorNewMatches([]byte(body), []byte(baseline))))
	return 1
}

func injectionSQLiErrorPayloads(L *lua.LState) int {
	out := L.NewTable()
	for i, p := range lua_engine.SQLiErrorPayloads() {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(p.Name))
		entry.RawSetString("template", lua.LString(p.Template))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func injectionSQLiTimeSleepSeconds(L *lua.LState) int {
	L.Push(lua.LNumber(SQLiTimeSleepSeconds()))
	return 1
}

func injectionSQLiTimeMargin(L *lua.LState) int {
	L.Push(lua.LNumber(SQLiTimeMargin()))
	return 1
}

func injectionTraversalNewMarkers(L *lua.LState) int {
	body := lua_engine.RequireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = lua_engine.LValString(L.Get(2))
	}
	L.Push(lua_engine.PushStringList(L, TraversalNewMarkers([]byte(body), []byte(baseline))))
	return 1
}

func injectionTraversalMarkers(L *lua.LState) int {
	L.Push(lua_engine.PushStringList(L, TraversalMarkerHits([]byte(lua_engine.RequireString(L, 1)))))
	return 1
}

func injectionLDAPErrorNewMatches(L *lua.LState) int {
	body := lua_engine.RequireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = lua_engine.LValString(L.Get(2))
	}
	L.Push(lua_engine.PushStringList(L, LDAPErrorNewMatches([]byte(body), []byte(baseline))))
	return 1
}

func injectionLDAPiSinkProbable(L *lua.LState) int {
	loc := lua_engine.RequireString(L, 1)
	L.Push(lua.LBool(LDAPiSinkProbable(loc)))
	return 1
}

func injectionMongoErrorNewMatches(L *lua.LState) int {
	body := lua_engine.RequireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = lua_engine.LValString(L.Get(2))
	}
	L.Push(lua_engine.PushStringList(L, MongoErrorNewMatches([]byte(body), []byte(baseline))))
	return 1
}

func injectionNoSQLiSinkProbable(L *lua.LState) int {
	loc := lua_engine.RequireString(L, 1)
	L.Push(lua.LBool(NoSQLiSinkProbable(loc)))
	return 1
}

func injectionNoSQLiBuildOperatorRequest(L *lua.LState) int {
	s, ok := lua_engine.UnwrapSink(L.CheckUserData(1))
	if !ok {
		L.ArgError(1, "expected sink userdata")
	}
	opName := lua_engine.RequireString(L, 2)
	opValue := lua_engine.RequireString(L, 3)
	env := lua_engine.CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.injection.nosqli_build_operator_request called outside a check run")
	}
	req, err := NoSQLiBuildOperatorRequest(env.Ctx, *s, opName, opValue)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua_engine.PushRequest(L, req, nil, false))
	return 1
}

func injectionSSTIErrorNewMatches(L *lua.LState) int {
	body := lua_engine.RequireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = lua_engine.LValString(L.Get(2))
	}
	L.Push(lua_engine.PushStringList(L, SSTIErrorNewMatches([]byte(body), []byte(baseline))))
	return 1
}

func injectionCmdErrorFirstMatch(L *lua.LState) int {
	body := lua_engine.RequireString(L, 1)
	L.Push(lua.LString(CmdErrorFirstMatch([]byte(body))))
	return 1
}

func injectionCmdInjectionSleepSeconds(L *lua.LState) int {
	L.Push(lua.LNumber(CmdInjectionSleepSeconds()))
	return 1
}

func injectionCmdInjectionMargin(L *lua.LState) int {
	L.Push(lua.LNumber(CmdInjectionMargin()))
	return 1
}

func injectionSSRFMatchesError(L *lua.LState) int {
	L.Push(lua.LString(SSRFMatchesError([]byte(lua_engine.RequireString(L, 1)))))
	return 1
}

func injectionIsJSONResponse(L *lua.LState) int {
	ct := lua_engine.OptString(L, 1, "")
	body := lua_engine.OptString(L, 2, "")
	L.Push(lua.LBool(ProtoPollutionIsJSONResponse(ct, []byte(body))))
	return 1
}

func injectionJSONIndentWidth(L *lua.LState) int {
	L.Push(lua.LNumber(ProtoPollutionJSONIndentWidth([]byte(lua_engine.RequireString(L, 1)))))
	return 1
}

func injectionXXEErrorPatterns(L *lua.LState) int {
	L.Push(lua_engine.PushStringList(L, XXEErrorPatternsLua([]byte(lua_engine.RequireString(L, 1)))))
	return 1
}

func injectionXXEBase64Markers(L *lua.LState) int {
	L.Push(lua_engine.PushStringList(L, XXEBase64MarkersLua([]byte(lua_engine.RequireString(L, 1)))))
	return 1
}

func injectionPathSinkCandidate(L *lua.LState) int {
	s, ok := lua_engine.UnwrapSink(L.CheckUserData(1))
	if !ok {
		L.Push(lua.LBool(false))
		return 1
	}
	L.Push(lua.LBool(PathSinkCandidate(*s)))
	return 1
}

func injectionLocDescriptor(L *lua.LState) int {
	L.Push(lua.LString(LocDescriptorLua(lua_engine.RequireString(L, 1))))
	return 1
}

func init() {
	lua_engine.RegisterHelperTable("injection", buildInjectionTable)
}
