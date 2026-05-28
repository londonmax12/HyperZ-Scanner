package lua_engine

import (
	"net/http"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/lua_engine/checks/supply_chain"
)

// buildBodyTable returns the ctx.body helper namespace. These are
// the regex-heavy body-scanning routines that live in Go (we keep
// them in Go on purpose: gopher-lua's pattern library is weaker than
// re2/Go regex, and the scanners are perf-sensitive). The Lua side
// gets a stable surface that delegates to engine implementations.
//
// Helpers seeded here:
//
//	ctx.body.is_html_ct(content_type) / ctx.body.is_scannable_ct(ct)
//	  -> bool. Mirror the Go-side content-type filters every passive
//	     check gates on, so a Lua port and the Go original agree on
//	     "this response is HTML" / "this response is worth scanning".
//
//	ctx.body.find_secrets(body)
//	  -> array of { id, label, severity, raw, redacted, count }.
//	     Runs the full secret-pattern catalogue on the bytes and
//	     returns the already-sorted (severity desc, id, redacted)
//	     hit list. Lua callers consume it directly and only own the
//	     surrounding finding-shape orchestration.
//
//	ctx.body.redact_secret(raw)
//	  -> string. Identical output to the Go check's redactSecret;
//	     exposed separately for ports that need to redact a value
//	     that did not come from find_secrets (rare).
//
//	ctx.body.source_map_kind(content_type)
//	  -> (kind_string, ok_bool) -> ("js"|"css"|"", false|true).
//
//	ctx.body.find_source_map_ref(headers, body, kind)
//	  -> string (the sourceMappingURL value the response advertises).
//
//	ctx.body.looks_like_source_map(body)
//	  -> bool. Anchors on the "version" + "sources"/"mappings" triple.
//
// Additional body scanners (XSS reflection, SQLi error fingerprints,
// SSTI markers) are added here as their owning checks are ported to
// Lua. Each is a Go function with a stable arg shape that a Lua
// author calls without having to know the internal regex.
func buildBodyTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("is_html_ct", L.NewFunction(bodyIsHTMLCT))
	t.RawSetString("scan_known_js_libs", L.NewFunction(bodyScanKnownJSLibs))
	t.RawSetString("sqli_error_new_matches", L.NewFunction(bodySQLiErrorNewMatches))
	t.RawSetString("sqli_error_payloads", L.NewFunction(bodySQLiErrorPayloads))
	t.RawSetString("traversal_new_markers", L.NewFunction(bodyTraversalNewMarkers))
	t.RawSetString("traversal_markers", L.NewFunction(bodyTraversalMarkers))
	t.RawSetString("ldap_error_new_matches", L.NewFunction(bodyLDAPErrorNewMatches))
	t.RawSetString("mongo_error_new_matches", L.NewFunction(bodyMongoErrorNewMatches))
	t.RawSetString("ssti_error_new_matches", L.NewFunction(bodySSTIErrorNewMatches))
	t.RawSetString("cmd_error_first_match", L.NewFunction(bodyCmdErrorFirstMatch))
	t.RawSetString("path_sink_candidate", L.NewFunction(bodyPathSinkCandidate))
	t.RawSetString("ldapi_sink_probable", L.NewFunction(bodyLDAPiSinkProbable))
	t.RawSetString("nosqli_sink_probable", L.NewFunction(bodyNoSQLiSinkProbable))
	t.RawSetString("nosqli_build_operator_request", L.NewFunction(bodyNoSQLiBuildOperatorRequest))
	t.RawSetString("cache_poison_has_cache_hint", L.NewFunction(bodyCachePoisonHasCacheHint))
	t.RawSetString("cache_poison_find_reflection", L.NewFunction(bodyCachePoisonFindReflection))
	t.RawSetString("cache_poison_response_diverged", L.NewFunction(bodyCachePoisonResponseDiverged))
	t.RawSetString("cache_poison_bodies_match", L.NewFunction(bodyCachePoisonBodiesMatch))
	t.RawSetString("cache_poison_cc_forbids_storage", L.NewFunction(bodyCachePoisonCCForbidsStorage))
	t.RawSetString("cache_poison_is_auth_likely_path", L.NewFunction(bodyCachePoisonIsAuthLikelyPath))
	t.RawSetString("cache_poison_deception_url", L.NewFunction(bodyCachePoisonDeceptionURL))
	t.RawSetString("cache_poison_parse_vary", L.NewFunction(bodyCachePoisonParseVary))
	t.RawSetString("cache_poison_probe_url", L.NewFunction(bodyCachePoisonProbeURL))
	t.RawSetString("sqli_time_sleep_seconds", L.NewFunction(bodySQLiTimeSleepSeconds))
	t.RawSetString("sqli_time_margin", L.NewFunction(bodySQLiTimeMargin))
	t.RawSetString("cmd_injection_sleep_seconds", L.NewFunction(bodyCmdInjectionSleepSeconds))
	t.RawSetString("cmd_injection_margin", L.NewFunction(bodyCmdInjectionMargin))
	t.RawSetString("ssrf_matches_error", L.NewFunction(bodySSRFMatchesError))
	t.RawSetString("status_text", L.NewFunction(bodyStatusText))
	t.RawSetString("is_json_response", L.NewFunction(bodyIsJSONResponse))
	t.RawSetString("json_indent_width", L.NewFunction(bodyJSONIndentWidth))
	t.RawSetString("xxe_error_patterns", L.NewFunction(bodyXXEErrorPatterns))
	t.RawSetString("xxe_base64_markers", L.NewFunction(bodyXXEBase64Markers))
	return t
}

// bodyIsJSONResponse mirrors isJSONResponse: Content-Type wins,
// otherwise a body that starts with `{` or `[` after whitespace
// stripping is treated as JSON. Used by the proto-pollution port to
// gate the json-spaces gadget.
func bodyIsJSONResponse(L *lua.LState) int {
	ct := OptString(L, 1, "")
	body := OptString(L, 2, "")
	L.Push(lua.LBool(ProtoPollutionIsJSONResponse(ct, []byte(body))))
	return 1
}

// bodyJSONIndentWidth wraps ProtoPollutionJSONIndentWidth so
// the .lua port reads the same GCD-of-indent-widths the Go check uses
// to detect the json-spaces gadget firing.
func bodyJSONIndentWidth(L *lua.LState) int {
	L.Push(lua.LNumber(ProtoPollutionJSONIndentWidth([]byte(RequireString(L, 1)))))
	return 1
}

// bodyXXEErrorPatterns returns every XML parser-error signature that
// appears in body (case-insensitive). The .lua port subtracts the
// baseline set itself.
func bodyXXEErrorPatterns(L *lua.LState) int {
	L.Push(PushStringList(L, XXEErrorPatternsLua([]byte(RequireString(L, 1)))))
	return 1
}

// bodyXXEBase64Markers returns every php-filter base64 marker visible
// in body (case-sensitive). Used by the .lua xxe port's file-
// disclosure phase as a fallback when the plaintext path doesn't hit.
func bodyXXEBase64Markers(L *lua.LState) int {
	L.Push(PushStringList(L, XXEBase64MarkersLua([]byte(RequireString(L, 1)))))
	return 1
}

// bodyStatusText wraps net/http.StatusText so Lua-authored evidence
// snippets can render "HTTP/1.1 200 OK"-style status lines without
// the .lua file carrying its own status-code table. Returns "" for
// unrecognized codes (matches the Go API verbatim).
func bodyStatusText(L *lua.LState) int {
	L.Push(lua.LString(http.StatusText(L.CheckInt(1))))
	return 1
}

// bodySSRFMatchesError returns the first SSRF error-signature pattern
// that appears in body, or "" when none match. Case-insensitive. Used
// by the ssrf Lua port to discriminate "the server fetched the canary
// and the library leaked the error" from a clean response.
func bodySSRFMatchesError(L *lua.LState) int {
	L.Push(lua.LString(SSRFMatchesError([]byte(RequireString(L, 1)))))
	return 1
}

// bodySQLiTimeSleepSeconds / bodySQLiTimeMargin /
// bodyCmdInjectionSleepSeconds / bodyCmdInjectionMargin expose the
// Go side's test-tunable timing knobs. The Lua port reads them every
// Run so a parity test that flips the Go vars sees both implementations
// dial down to the same value in lockstep.
func bodySQLiTimeSleepSeconds(L *lua.LState) int {
	L.Push(lua.LNumber(SQLiTimeSleepSeconds()))
	return 1
}
func bodySQLiTimeMargin(L *lua.LState) int {
	L.Push(lua.LNumber(SQLiTimeMargin()))
	return 1
}
func bodyCmdInjectionSleepSeconds(L *lua.LState) int {
	L.Push(lua.LNumber(CmdInjectionSleepSeconds()))
	return 1
}
func bodyCmdInjectionMargin(L *lua.LState) int {
	L.Push(lua.LNumber(CmdInjectionMargin()))
	return 1
}

func bodyIsHTMLCT(L *lua.LState) int {
	L.Push(lua.LBool(IsHTMLContentType(RequireString(L, 1))))
	return 1
}

// bodyScanKnownJSLibs returns the JS-library hits detected in an HTML
// body as an array of { name, version, vulnerabilities = [...] }.
// vulnerabilities is an empty array when the library was identified
// but no vulnerable version row matched; the Lua port discriminates
// info vs medium severity on `#vulnerabilities == 0`.
func bodyScanKnownJSLibs(L *lua.LState) int {
	body := RequireString(L, 1)
	hits := supply_chain.ScanScriptTagsForKnownJSLibraries([]byte(body))
	out := L.NewTable()
	for i, h := range hits {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(h.Name))
		entry.RawSetString("version", lua.LString(h.Version))
		entry.RawSetString("vulnerabilities", PushStringList(L, h.Vulnerabilities))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

// bodySQLiErrorNewMatches returns the SQL-driver error pattern names
// that appear in body but did not appear in baseline. Both args are
// strings; nil/missing slots collapse to empty.
func bodySQLiErrorNewMatches(L *lua.LState) int {
	body := RequireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = LValString(L.Get(2))
	}
	L.Push(PushStringList(L, SQLiErrorNewMatches([]byte(body), []byte(baseline))))
	return 1
}

// bodySQLiErrorPayloads exposes the curated SQLi-error payload list so
// the Lua port iterates them in the same order PayloadsFor produces.
func bodySQLiErrorPayloads(L *lua.LState) int {
	out := L.NewTable()
	for i, p := range SQLiErrorPayloads() {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(p.Name))
		entry.RawSetString("template", lua.LString(p.Template))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

// bodyTraversalNewMarkers / bodyTraversalMarkers wrap the path-traversal
// marker scanner + baseline subtraction. Mirrors the SQLiError pair so
// the Lua port can baseline-then-probe in the same shape it uses for
// the sister check.
func bodyTraversalNewMarkers(L *lua.LState) int {
	body := RequireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = LValString(L.Get(2))
	}
	L.Push(PushStringList(L, TraversalNewMarkers([]byte(body), []byte(baseline))))
	return 1
}

func bodyTraversalMarkers(L *lua.LState) int {
	L.Push(PushStringList(L, TraversalMarkerHits([]byte(RequireString(L, 1)))))
	return 1
}

// bodyLDAPErrorNewMatches / bodyMongoErrorNewMatches / bodySSTIErrorNewMatches
// share a shape: scan body for the check's pattern catalogue and
// subtract any patterns already present in baseline. Each one is one
// line because the per-check helpers in checks/lua_helpers.go own the
// catalogue + matcher; the bridge surface stays a pure forwarder.
func bodyLDAPErrorNewMatches(L *lua.LState) int {
	body := RequireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = LValString(L.Get(2))
	}
	L.Push(PushStringList(L, LDAPErrorNewMatches([]byte(body), []byte(baseline))))
	return 1
}

func bodyMongoErrorNewMatches(L *lua.LState) int {
	body := RequireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = LValString(L.Get(2))
	}
	L.Push(PushStringList(L, MongoErrorNewMatches([]byte(body), []byte(baseline))))
	return 1
}

func bodySSTIErrorNewMatches(L *lua.LState) int {
	body := RequireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = LValString(L.Get(2))
	}
	L.Push(PushStringList(L, SSTIErrorNewMatches([]byte(body), []byte(baseline))))
	return 1
}

// bodyCmdErrorFirstMatch returns "" when no shell-error signature
// appears in body. Returning just the first hit (rather than the full
// list) matches the cmd-injection-blind check's verdict shape, which
// only records one error string per finding.
func bodyCmdErrorFirstMatch(L *lua.LState) int {
	body := RequireString(L, 1)
	L.Push(lua.LString(CmdErrorFirstMatch([]byte(body))))
	return 1
}

// bodyPathSinkCandidate forwards the path-traversal sink-candidate
// heuristic so the Lua port short-circuits the sweep on non-path-ish
// sinks at LevelDefault. Argument is a sink userdata; the wrapper
// pulls the needed fields off it.
func bodyPathSinkCandidate(L *lua.LState) int {
	wrapper, ok := L.CheckUserData(1).Value.(*sinkUserData)
	if !ok {
		L.Push(lua.LBool(false))
		return 1
	}
	L.Push(lua.LBool(PathSinkCandidate(*wrapper.s)))
	return 1
}

func bodyLDAPiSinkProbable(L *lua.LState) int {
	loc := RequireString(L, 1)
	L.Push(lua.LBool(LDAPiSinkProbable(loc)))
	return 1
}

func bodyNoSQLiSinkProbable(L *lua.LState) int {
	loc := RequireString(L, 1)
	L.Push(lua.LBool(NoSQLiSinkProbable(loc)))
	return 1
}

// bodyNoSQLiBuildOperatorRequest builds the request that overlays the
// named MongoDB operator onto sink with opValue. Wrap-the-Go-builder
// keeps the per-loc shape rules (bracket key vs nested JSON) in one
// place; the Lua port hands back the resulting request userdata and
// dispatches it through client:do like any other request.
func bodyNoSQLiBuildOperatorRequest(L *lua.LState) int {
	wrapper, ok := L.CheckUserData(1).Value.(*sinkUserData)
	if !ok {
		L.ArgError(1, "expected sink userdata")
	}
	opName := RequireString(L, 2)
	opValue := RequireString(L, 3)
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.body.nosqli_build_operator_request called outside a check run")
	}
	req, err := NoSQLiBuildOperatorRequest(env.Ctx, *wrapper.s, opName, opValue)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(pushRequest(L, req, nil, false))
	return 1
}

// bodyCachePoisonHasCacheHint forwards the cache-poisoning gate so
// the Lua port skips the unkeyed-header arm on pages whose baseline
// response carries no cache hint. Argument is a headers userdata.
func bodyCachePoisonHasCacheHint(L *lua.LState) int {
	var h http.Header
	if ud, ok := L.Get(1).(*lua.LUserData); ok && ud != nil {
		if hu, ok := ud.Value.(*headersUserData); ok {
			h = hu.h
		}
	}
	L.Push(lua.LBool(CachePoisonHasCacheHint(h)))
	return 1
}

// bodyCachePoisonFindReflection runs the canary lookup against the
// probe response (headers + body) with baseline-body subtraction. Args
// are needle, headers userdata, body string, baseline body string;
// returns (location_string, ok_bool).
func bodyCachePoisonFindReflection(L *lua.LState) int {
	needle := RequireString(L, 1)
	var headers http.Header
	if ud, ok := L.Get(2).(*lua.LUserData); ok && ud != nil {
		if hu, ok := ud.Value.(*headersUserData); ok {
			headers = hu.h
		}
	}
	body := RequireString(L, 3)
	baseline := OptString(L, 4, "")
	where, ok := CachePoisonFindReflection(needle, headers, []byte(body), []byte(baseline))
	L.Push(lua.LString(where))
	L.Push(lua.LBool(ok))
	return 2
}

// bodyCachePoisonResponseDiverged returns true when the probe shape
// differs meaningfully from baseline (different status, or > 25%
// length divergence).
func bodyCachePoisonResponseDiverged(L *lua.LState) int {
	status := L.CheckInt(1)
	body := RequireString(L, 2)
	baseStatus := L.CheckInt(3)
	baseBody := OptString(L, 4, "")
	L.Push(lua.LBool(CachePoisonResponseDiverged(status, []byte(body), baseStatus, []byte(baseBody))))
	return 1
}

func bodyCachePoisonBodiesMatch(L *lua.LState) int {
	deceived := RequireString(L, 1)
	baseline := RequireString(L, 2)
	L.Push(lua.LBool(CachePoisonBodiesMatch([]byte(deceived), []byte(baseline))))
	return 1
}

func bodyCachePoisonCCForbidsStorage(L *lua.LState) int {
	L.Push(lua.LBool(CachePoisonCacheControlForbidsStorage(RequireString(L, 1))))
	return 1
}

func bodyCachePoisonIsAuthLikelyPath(L *lua.LState) int {
	L.Push(lua.LBool(CachePoisonIsAuthLikelyPath(RequireString(L, 1))))
	return 1
}

func bodyCachePoisonDeceptionURL(L *lua.LState) int {
	deceived, err := CachePoisonDeceptionURL(RequireString(L, 1))
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(deceived))
	return 1
}

func bodyCachePoisonParseVary(L *lua.LState) int {
	L.Push(PushStringList(L, CachePoisonParseVary(RequireString(L, 1))))
	return 1
}

// bodyCachePoisonProbeURL forwards CachePoisonProbeURL so the
// Lua port routes every unkeyed-header probe through the same random
// cachebuster the Go check uses. Returns (probe_url, err_string) - the
// helper can only fail when target is unparseable, which the caller
// will already have rejected via url.parse, so the err return is a
// belt-and-braces signal rather than an expected branch.
func bodyCachePoisonProbeURL(L *lua.LState) int {
	out, err := CachePoisonProbeURL(RequireString(L, 1))
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(out))
	return 1
}

func init() {
	RegisterHelperTable("body", buildBodyTable)
}
