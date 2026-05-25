package luabridge

import (
	"net/http"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/checks"
)

// buildBodyTable returns the ctx.body helper namespace. These are
// the regex-heavy body-scanning routines that live in Go (we keep
// them in Go on purpose: gopher-lua's pattern library is weaker than
// re2/Go regex, and the scanners are perf-sensitive). The Lua side
// gets a stable surface that delegates to engine implementations.
//
// Helpers seeded here:
//
//	ctx.body.find_redirect_sink(body, canary_host)
//	  -> (match_string, kind_string) or ("", "") when nothing found.
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
//	ctx.body.parse_hsts(value)
//	  -> { directives = { name = value, ... },
//	       errors    = [{ id = ..., detail = ... }, ...] }
//	     Wraps the HSTS-weak directive parser so the port iterates
//	     over the same parser output the Go check does.
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
	t.RawSetString("find_redirect_sink", L.NewFunction(bodyFindRedirectSink))
	t.RawSetString("is_html_ct", L.NewFunction(bodyIsHTMLCT))
	t.RawSetString("is_scannable_ct", L.NewFunction(bodyIsScannableCT))
	t.RawSetString("find_secrets", L.NewFunction(bodyFindSecrets))
	t.RawSetString("redact_secret", L.NewFunction(bodyRedactSecret))
	t.RawSetString("parse_hsts", L.NewFunction(bodyParseHSTS))
	t.RawSetString("source_map_kind", L.NewFunction(bodySourceMapKind))
	t.RawSetString("find_source_map_ref", L.NewFunction(bodyFindSourceMapRef))
	t.RawSetString("looks_like_source_map", L.NewFunction(bodyLooksLikeSourceMap))
	t.RawSetString("scan_known_js_libs", L.NewFunction(bodyScanKnownJSLibs))
	t.RawSetString("analyze_csp", L.NewFunction(bodyAnalyzeCSP))
	t.RawSetString("sqli_error_new_matches", L.NewFunction(bodySQLiErrorNewMatches))
	t.RawSetString("sqli_error_payloads", L.NewFunction(bodySQLiErrorPayloads))
	t.RawSetString("traversal_new_markers", L.NewFunction(bodyTraversalNewMarkers))
	t.RawSetString("traversal_markers", L.NewFunction(bodyTraversalMarkers))
	t.RawSetString("ldap_error_new_matches", L.NewFunction(bodyLDAPErrorNewMatches))
	t.RawSetString("mongo_error_new_matches", L.NewFunction(bodyMongoErrorNewMatches))
	t.RawSetString("ssti_error_new_matches", L.NewFunction(bodySSTIErrorNewMatches))
	t.RawSetString("cmd_error_first_match", L.NewFunction(bodyCmdErrorFirstMatch))
	t.RawSetString("find_reflections", L.NewFunction(bodyFindReflections))
	t.RawSetString("xss_payloads_for_contexts", L.NewFunction(bodyXSSPayloadsForContexts))
	t.RawSetString("xss_context_summary", L.NewFunction(bodyXSSContextSummary))
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
	t.RawSetString("sqli_time_sleep_seconds", L.NewFunction(bodySQLiTimeSleepSeconds))
	t.RawSetString("sqli_time_margin", L.NewFunction(bodySQLiTimeMargin))
	t.RawSetString("cmd_injection_sleep_seconds", L.NewFunction(bodyCmdInjectionSleepSeconds))
	t.RawSetString("cmd_injection_margin", L.NewFunction(bodyCmdInjectionMargin))
	t.RawSetString("ssrf_matches_error", L.NewFunction(bodySSRFMatchesError))
	t.RawSetString("is_event_stream", L.NewFunction(bodyIsEventStream))
	t.RawSetString("find_event_source_literals", L.NewFunction(bodyFindEventSourceLiterals))
	t.RawSetString("status_text", L.NewFunction(bodyStatusText))
	t.RawSetString("is_json_response", L.NewFunction(bodyIsJSONResponse))
	t.RawSetString("json_indent_width", L.NewFunction(bodyJSONIndentWidth))
	t.RawSetString("xxe_error_patterns", L.NewFunction(bodyXXEErrorPatterns))
	t.RawSetString("xxe_base64_markers", L.NewFunction(bodyXXEBase64Markers))
	return t
}

// bodyIsJSONResponse mirrors checks.isJSONResponse: Content-Type wins,
// otherwise a body that starts with `{` or `[` after whitespace
// stripping is treated as JSON. Used by the proto-pollution port to
// gate the json-spaces gadget.
func bodyIsJSONResponse(L *lua.LState) int {
	ct := optString(L, 1, "")
	body := optString(L, 2, "")
	L.Push(lua.LBool(checks.ProtoPollutionIsJSONResponse(ct, []byte(body))))
	return 1
}

// bodyJSONIndentWidth wraps checks.ProtoPollutionJSONIndentWidth so
// the .lua port reads the same GCD-of-indent-widths the Go check uses
// to detect the json-spaces gadget firing.
func bodyJSONIndentWidth(L *lua.LState) int {
	L.Push(lua.LNumber(checks.ProtoPollutionJSONIndentWidth([]byte(requireString(L, 1)))))
	return 1
}

// bodyXXEErrorPatterns returns every XML parser-error signature that
// appears in body (case-insensitive). The .lua port subtracts the
// baseline set itself.
func bodyXXEErrorPatterns(L *lua.LState) int {
	out := L.NewTable()
	for i, h := range checks.XXEErrorPatternsLua([]byte(requireString(L, 1))) {
		out.RawSetInt(i+1, lua.LString(h))
	}
	L.Push(out)
	return 1
}

// bodyXXEBase64Markers returns every php-filter base64 marker visible
// in body (case-sensitive). Used by the .lua xxe port's file-
// disclosure phase as a fallback when the plaintext path doesn't hit.
func bodyXXEBase64Markers(L *lua.LState) int {
	out := L.NewTable()
	for i, h := range checks.XXEBase64MarkersLua([]byte(requireString(L, 1))) {
		out.RawSetInt(i+1, lua.LString(h))
	}
	L.Push(out)
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

// bodyIsEventStream reports whether ct names a Server-Sent Events
// stream. Wraps checks.IsEventStreamContentType so the Lua port and
// the Go check gate on the exact same content-type rule (parameter-
// stripping + case-insensitive compare against text/event-stream).
func bodyIsEventStream(L *lua.LState) int {
	L.Push(lua.LBool(checks.IsEventStreamContentType(requireString(L, 1))))
	return 1
}

// bodyFindEventSourceLiterals returns the URL captures from any
// `new EventSource(...)` constructions in body, in document order. The
// regex (three quote styles, optional whitespace) stays in Go because
// gopher-lua's pattern library cannot express it; the Lua port resolves
// each capture against a base URL and dedupes/sorts itself.
func bodyFindEventSourceLiterals(L *lua.LState) int {
	body := requireString(L, 1)
	out := L.NewTable()
	for i, s := range checks.FindEventSourceLiteralsLua([]byte(body)) {
		out.RawSetInt(i+1, lua.LString(s))
	}
	L.Push(out)
	return 1
}

// bodySSRFMatchesError returns the first SSRF error-signature pattern
// that appears in body, or "" when none match. Case-insensitive. Used
// by the ssrf Lua port to discriminate "the server fetched the canary
// and the library leaked the error" from a clean response.
func bodySSRFMatchesError(L *lua.LState) int {
	L.Push(lua.LString(checks.SSRFMatchesError([]byte(requireString(L, 1)))))
	return 1
}

// bodySQLiTimeSleepSeconds / bodySQLiTimeMargin /
// bodyCmdInjectionSleepSeconds / bodyCmdInjectionMargin expose the
// Go side's test-tunable timing knobs. The Lua port reads them every
// Run so a parity test that flips the Go vars sees both implementations
// dial down to the same value in lockstep.
func bodySQLiTimeSleepSeconds(L *lua.LState) int {
	L.Push(lua.LNumber(checks.SQLiTimeSleepSeconds()))
	return 1
}
func bodySQLiTimeMargin(L *lua.LState) int {
	L.Push(lua.LNumber(checks.SQLiTimeMargin()))
	return 1
}
func bodyCmdInjectionSleepSeconds(L *lua.LState) int {
	L.Push(lua.LNumber(checks.CmdInjectionSleepSeconds()))
	return 1
}
func bodyCmdInjectionMargin(L *lua.LState) int {
	L.Push(lua.LNumber(checks.CmdInjectionMargin()))
	return 1
}

// bodyFindRedirectSink delegates to checks.FindBodyRedirectSink so a
// Lua-authored check applies the exact same JS-navigation + meta-
// refresh scanning the Go check uses. Keeping the regex in Go means
// future tightening (new sink shapes, false-positive fixes) only
// needs to land once.
func bodyFindRedirectSink(L *lua.LState) int {
	body := requireString(L, 1)
	host := requireString(L, 2)
	target, kind := checks.FindBodyRedirectSink([]byte(body), host)
	L.Push(lua.LString(target))
	L.Push(lua.LString(kind))
	return 2
}

func bodyIsHTMLCT(L *lua.LState) int {
	L.Push(lua.LBool(checks.IsHTMLContentType(requireString(L, 1))))
	return 1
}

func bodyIsScannableCT(L *lua.LState) int {
	L.Push(lua.LBool(checks.IsScannableContentType(requireString(L, 1))))
	return 1
}

// bodyFindSecrets runs the secrets-in-body scanner and returns the
// already-sorted hit list. The pre-redacted value is stamped on each
// entry so the Lua port does not have to call redact_secret again.
func bodyFindSecrets(L *lua.LState) int {
	body := requireString(L, 1)
	hits := checks.ScanSecretsInBody([]byte(body))
	out := L.NewTable()
	for i, h := range hits {
		entry := L.NewTable()
		entry.RawSetString("id", lua.LString(h.ID))
		entry.RawSetString("label", lua.LString(h.Label))
		entry.RawSetString("severity", lua.LString(string(h.Severity)))
		entry.RawSetString("raw", lua.LString(h.Raw))
		entry.RawSetString("redacted", lua.LString(checks.RedactSecret(h.Raw)))
		entry.RawSetString("count", lua.LNumber(h.Count))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func bodyRedactSecret(L *lua.LState) int {
	L.Push(lua.LString(checks.RedactSecret(requireString(L, 1))))
	return 1
}

// bodyParseHSTS returns { directives = { name = value }, errors = [...] }.
// directives uses raw values (empty string for flag-only directives);
// the structural-error array carries the spec-fatal duplicates the Go
// parser surfaces separately.
func bodyParseHSTS(L *lua.LState) int {
	parsed := checks.ParseHSTSHeader(requireString(L, 1))
	out := L.NewTable()
	dirs := L.NewTable()
	for k, v := range parsed.Directives {
		dirs.RawSetString(k, lua.LString(v))
	}
	out.RawSetString("directives", dirs)
	errs := L.NewTable()
	for i, e := range parsed.Errors {
		entry := L.NewTable()
		entry.RawSetString("id", lua.LString(e.ID))
		entry.RawSetString("detail", lua.LString(e.Detail))
		errs.RawSetInt(i+1, entry)
	}
	out.RawSetString("errors", errs)
	L.Push(out)
	return 1
}

func bodySourceMapKind(L *lua.LState) int {
	kind, ok := checks.SourceMapKind(requireString(L, 1))
	L.Push(lua.LString(kind))
	L.Push(lua.LBool(ok))
	return 2
}

// bodyFindSourceMapRef accepts a headers userdata + body + kind and
// returns the source-map reference the response advertises. The
// header / body precedence rule lives in Go - this is a thin
// forwarder, not a re-implementation.
func bodyFindSourceMapRef(L *lua.LState) int {
	hud, ok := L.CheckUserData(1).Value.(*headersUserData)
	var h http.Header
	if ok {
		h = hud.h
	}
	body := requireString(L, 2)
	kind := requireString(L, 3)
	L.Push(lua.LString(checks.FindSourceMapReference(h, []byte(body), kind)))
	return 1
}

func bodyLooksLikeSourceMap(L *lua.LState) int {
	L.Push(lua.LBool(checks.LooksLikeSourceMap([]byte(requireString(L, 1)))))
	return 1
}

// bodyScanKnownJSLibs returns the JS-library hits detected in an HTML
// body as an array of { name, version, vulnerabilities = [...] }.
// vulnerabilities is an empty array when the library was identified
// but no vulnerable version row matched; the Lua port discriminates
// info vs medium severity on `#vulnerabilities == 0`.
func bodyScanKnownJSLibs(L *lua.LState) int {
	body := requireString(L, 1)
	hits := checks.ScanScriptTagsForKnownJSLibraries([]byte(body))
	out := L.NewTable()
	for i, h := range hits {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(h.Name))
		entry.RawSetString("version", lua.LString(h.Version))
		vulns := L.NewTable()
		for j, v := range h.Vulnerabilities {
			vulns.RawSetInt(j+1, lua.LString(v))
		}
		entry.RawSetString("vulnerabilities", vulns)
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

// bodyAnalyzeCSP runs the CSP-weak analyzer against the enforcing +
// report-only header values and returns the deduplicated weakness
// list. Both arg slots accept either a string (a single header value),
// a Lua array of strings (multiple headers as http.Header.Values does),
// or nil (header absent). The result is { is_report_only, multi_count,
// weaknesses = [{directive, severity, id, detail}, ...] }.
func bodyAnalyzeCSP(L *lua.LState) int {
	enforcing := readStringList(L.Get(1))
	reportOnly := readStringList(L.Get(2))
	out := L.NewTable()
	out.RawSetString("is_report_only", lua.LBool(checks.CSPIsReportOnly(enforcing, reportOnly)))
	out.RawSetString("enforcing_count", lua.LNumber(len(enforcing)))
	out.RawSetString("report_only_count", lua.LNumber(len(reportOnly)))
	weaknesses := L.NewTable()
	for i, w := range checks.AnalyzeCSP(enforcing, reportOnly) {
		entry := L.NewTable()
		entry.RawSetString("directive", lua.LString(w.Directive))
		entry.RawSetString("severity", lua.LString(string(w.Severity)))
		entry.RawSetString("id", lua.LString(w.ID))
		entry.RawSetString("detail", lua.LString(w.Detail))
		weaknesses.RawSetInt(i+1, entry)
	}
	out.RawSetString("weaknesses", weaknesses)
	L.Push(out)
	return 1
}

// bodySQLiErrorNewMatches returns the SQL-driver error pattern names
// that appear in body but did not appear in baseline. Both args are
// strings; nil/missing slots collapse to empty.
func bodySQLiErrorNewMatches(L *lua.LState) int {
	body := requireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = lvalString(L.Get(2))
	}
	hits := checks.SQLiErrorNewMatches([]byte(body), []byte(baseline))
	out := L.NewTable()
	for i, h := range hits {
		out.RawSetInt(i+1, lua.LString(h))
	}
	L.Push(out)
	return 1
}

// bodySQLiErrorPayloads exposes the curated SQLi-error payload list so
// the Lua port iterates them in the same order PayloadsFor produces.
func bodySQLiErrorPayloads(L *lua.LState) int {
	out := L.NewTable()
	for i, p := range checks.SQLiErrorPayloads() {
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
	body := requireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = lvalString(L.Get(2))
	}
	out := L.NewTable()
	for i, h := range checks.TraversalNewMarkers([]byte(body), []byte(baseline)) {
		out.RawSetInt(i+1, lua.LString(h))
	}
	L.Push(out)
	return 1
}

func bodyTraversalMarkers(L *lua.LState) int {
	body := requireString(L, 1)
	out := L.NewTable()
	for i, h := range checks.TraversalMarkerHits([]byte(body)) {
		out.RawSetInt(i+1, lua.LString(h))
	}
	L.Push(out)
	return 1
}

// bodyLDAPErrorNewMatches / bodyMongoErrorNewMatches / bodySSTIErrorNewMatches
// share a shape: scan body for the check's pattern catalogue and
// subtract any patterns already present in baseline. Each one is one
// line because the per-check helpers in checks/lua_helpers.go own the
// catalogue + matcher; the bridge surface stays a pure forwarder.
func bodyLDAPErrorNewMatches(L *lua.LState) int {
	body := requireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = lvalString(L.Get(2))
	}
	out := L.NewTable()
	for i, h := range checks.LDAPErrorNewMatches([]byte(body), []byte(baseline)) {
		out.RawSetInt(i+1, lua.LString(h))
	}
	L.Push(out)
	return 1
}

func bodyMongoErrorNewMatches(L *lua.LState) int {
	body := requireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = lvalString(L.Get(2))
	}
	out := L.NewTable()
	for i, h := range checks.MongoErrorNewMatches([]byte(body), []byte(baseline)) {
		out.RawSetInt(i+1, lua.LString(h))
	}
	L.Push(out)
	return 1
}

func bodySSTIErrorNewMatches(L *lua.LState) int {
	body := requireString(L, 1)
	baseline := ""
	if L.GetTop() >= 2 {
		baseline = lvalString(L.Get(2))
	}
	out := L.NewTable()
	for i, h := range checks.SSTIErrorNewMatches([]byte(body), []byte(baseline)) {
		out.RawSetInt(i+1, lua.LString(h))
	}
	L.Push(out)
	return 1
}

// bodyCmdErrorFirstMatch returns "" when no shell-error signature
// appears in body. Returning just the first hit (rather than the full
// list) matches the cmd-injection-blind check's verdict shape, which
// only records one error string per finding.
func bodyCmdErrorFirstMatch(L *lua.LState) int {
	body := requireString(L, 1)
	L.Push(lua.LString(checks.CmdErrorFirstMatch([]byte(body))))
	return 1
}

// bodyFindReflections runs the HTML / JS state machine reflection
// scanner against body / headers and returns an array of
// {context, offset, header} tables. context is the string name of the
// matched Context (so a Lua-side comparator does not need to know the
// numeric enum). Header is "" for body matches.
func bodyFindReflections(L *lua.LState) int {
	body := requireString(L, 1)
	var headers http.Header
	if ud, ok := L.Get(2).(*lua.LUserData); ok && ud != nil {
		if h, ok := ud.Value.(*headersUserData); ok {
			headers = h.h
		}
	}
	token := requireString(L, 3)
	hits := checks.FindReflectionsLua([]byte(body), headers, token)
	out := L.NewTable()
	for i, r := range hits {
		entry := L.NewTable()
		entry.RawSetString("context", lua.LString(r.Context))
		entry.RawSetString("offset", lua.LNumber(r.Offset))
		entry.RawSetString("header", lua.LString(r.Header))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

// bodyXSSPayloadsForContexts picks the context-matched XSS payload
// subset for the supplied reflection contexts (an array of context
// strings) at the active scan level. Returns an ordered array of
// {name, template} tables; mirrors the Go check's payloadsForContexts
// shape so the Lua port iterates payloads in the same order.
func bodyXSSPayloadsForContexts(L *lua.LState) int {
	contexts := readStringList(L.Get(1))
	level := optString(L, 2, "default")
	src := checks.XSSPayloadsForContextsLua(contexts, level)
	return pushPayloadList(L, src)
}

func bodyXSSContextSummary(L *lua.LState) int {
	contexts := readStringList(L.Get(1))
	L.Push(lua.LString(checks.XSSContextSummaryLua(contexts)))
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
	L.Push(lua.LBool(checks.PathSinkCandidate(*wrapper.s)))
	return 1
}

func bodyLDAPiSinkProbable(L *lua.LState) int {
	loc := requireString(L, 1)
	L.Push(lua.LBool(checks.LDAPiSinkProbable(loc)))
	return 1
}

func bodyNoSQLiSinkProbable(L *lua.LState) int {
	loc := requireString(L, 1)
	L.Push(lua.LBool(checks.NoSQLiSinkProbable(loc)))
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
	opName := requireString(L, 2)
	opValue := requireString(L, 3)
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("ctx.body.nosqli_build_operator_request called outside a check run")
	}
	req, err := checks.NoSQLiBuildOperatorRequest(env.ctx, *wrapper.s, opName, opValue)
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
	L.Push(lua.LBool(checks.CachePoisonHasCacheHint(h)))
	return 1
}

// bodyCachePoisonFindReflection runs the canary lookup against the
// probe response (headers + body) with baseline-body subtraction. Args
// are needle, headers userdata, body string, baseline body string;
// returns (location_string, ok_bool).
func bodyCachePoisonFindReflection(L *lua.LState) int {
	needle := requireString(L, 1)
	var headers http.Header
	if ud, ok := L.Get(2).(*lua.LUserData); ok && ud != nil {
		if hu, ok := ud.Value.(*headersUserData); ok {
			headers = hu.h
		}
	}
	body := requireString(L, 3)
	baseline := optString(L, 4, "")
	where, ok := checks.CachePoisonFindReflection(needle, headers, []byte(body), []byte(baseline))
	L.Push(lua.LString(where))
	L.Push(lua.LBool(ok))
	return 2
}

// bodyCachePoisonResponseDiverged returns true when the probe shape
// differs meaningfully from baseline (different status, or > 25%
// length divergence).
func bodyCachePoisonResponseDiverged(L *lua.LState) int {
	status := L.CheckInt(1)
	body := requireString(L, 2)
	baseStatus := L.CheckInt(3)
	baseBody := optString(L, 4, "")
	L.Push(lua.LBool(checks.CachePoisonResponseDiverged(status, []byte(body), baseStatus, []byte(baseBody))))
	return 1
}

func bodyCachePoisonBodiesMatch(L *lua.LState) int {
	deceived := requireString(L, 1)
	baseline := requireString(L, 2)
	L.Push(lua.LBool(checks.CachePoisonBodiesMatch([]byte(deceived), []byte(baseline))))
	return 1
}

func bodyCachePoisonCCForbidsStorage(L *lua.LState) int {
	L.Push(lua.LBool(checks.CachePoisonCacheControlForbidsStorage(requireString(L, 1))))
	return 1
}

func bodyCachePoisonIsAuthLikelyPath(L *lua.LState) int {
	L.Push(lua.LBool(checks.CachePoisonIsAuthLikelyPath(requireString(L, 1))))
	return 1
}

func bodyCachePoisonDeceptionURL(L *lua.LState) int {
	deceived, err := checks.CachePoisonDeceptionURL(requireString(L, 1))
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(deceived))
	return 1
}

func bodyCachePoisonParseVary(L *lua.LState) int {
	v := requireString(L, 1)
	out := L.NewTable()
	for i, name := range checks.CachePoisonParseVary(v) {
		out.RawSetInt(i+1, lua.LString(name))
	}
	L.Push(out)
	return 1
}

// readStringList accepts a Lua string, an array table of strings, or
// nil, and returns the equivalent []string. Used by analyze_csp to
// match http.Header.Values's shape on the Go side without forcing the
// Lua author to pre-shape header arrays themselves.
func readStringList(v lua.LValue) []string {
	if v == nil || v == lua.LNil {
		return nil
	}
	if s, ok := v.(lua.LString); ok {
		return []string{string(s)}
	}
	if tbl, ok := v.(*lua.LTable); ok {
		n := tbl.Len()
		out := make([]string, 0, n)
		for i := 1; i <= n; i++ {
			out = append(out, lvalString(tbl.RawGetInt(i)))
		}
		return out
	}
	return nil
}
