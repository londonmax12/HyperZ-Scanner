package headers

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// buildHeadersTable returns the ctx.headers helper namespace. The
// surface exposes the CSP-weak / csp-bypass / hsts-weak analyzers and
// the small URL-shape helpers the csp-bypass nonce-reuse probe needs
// (append_query_param, is_absolute_or_protocol_relative). These used to
// live on ctx.body / ctx.url at the root, but they are check-specific
// to the headers family, so they were lifted into their own namespace
// when the family moved into its own subpackage.
//
// Entry points:
//
//	ctx.headers.analyze_csp(enforcing, report_only)
//	  -> { is_report_only, enforcing_count, report_only_count,
//	       weaknesses = [{directive, severity, id, detail}, ...] }
//
//	ctx.headers.csp_parse_directives(header)
//	  -> { directive_name = [source, ...], ... }
//
//	ctx.headers.csp_nonce_values(directives) -> [string]
//	ctx.headers.csp_base_uri_hijackable(directives) -> bool
//	ctx.headers.csp_script_src_allows_host(sources, host) -> (raw, ok)
//	ctx.headers.csp_confirms_jsonp(content_type, body, canary) -> bool
//	ctx.headers.csp_relative_script_srcs(body) -> [string]
//	ctx.headers.csp_bypass_jsonp_probes() -> [{host, url_tmpl}]
//	ctx.headers.csp_bypass_callback_canary() -> string
//	ctx.headers.csp_bypass_body_cap() -> int
//	ctx.headers.csp_bypass_jsonp_snippet(body, truncated) -> string
//
//	ctx.headers.parse_hsts(value)
//	  -> { directives = { name = value, ... },
//	       errors    = [{ id = ..., detail = ... }, ...] }
//
//	ctx.headers.is_absolute_or_protocol_relative(src) -> bool
//	ctx.headers.append_query_param(rawurl, key, val) -> (string, err)
func buildHeadersTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("analyze_csp", L.NewFunction(headersAnalyzeCSP))
	t.RawSetString("csp_parse_directives", L.NewFunction(headersCSPParseDirectives))
	t.RawSetString("csp_nonce_values", L.NewFunction(headersCSPNonceValues))
	t.RawSetString("csp_base_uri_hijackable", L.NewFunction(headersCSPBaseURIHijackable))
	t.RawSetString("csp_script_src_allows_host", L.NewFunction(headersCSPScriptSrcAllowsHost))
	t.RawSetString("csp_confirms_jsonp", L.NewFunction(headersCSPConfirmsJSONP))
	t.RawSetString("csp_relative_script_srcs", L.NewFunction(headersCSPRelativeScriptSrcs))
	t.RawSetString("csp_bypass_jsonp_probes", L.NewFunction(headersCSPBypassJSONPProbes))
	t.RawSetString("csp_bypass_callback_canary", L.NewFunction(headersCSPBypassCallbackCanary))
	t.RawSetString("csp_bypass_body_cap", L.NewFunction(headersCSPBypassBodyCap))
	t.RawSetString("csp_bypass_jsonp_snippet", L.NewFunction(headersCSPBypassJSONPSnippet))
	t.RawSetString("parse_hsts", L.NewFunction(headersParseHSTS))
	t.RawSetString("is_absolute_or_protocol_relative", L.NewFunction(headersIsAbsoluteOrProtocolRelative))
	t.RawSetString("append_query_param", L.NewFunction(headersAppendQueryParam))
	return t
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
			out = append(out, lua_engine.LValString(tbl.RawGetInt(i)))
		}
		return out
	}
	return nil
}

// headersAnalyzeCSP runs the CSP-weak analyzer against the enforcing +
// report-only header values and returns the deduplicated weakness
// list. Both arg slots accept either a string (a single header value),
// a Lua array of strings (multiple headers as http.Header.Values does),
// or nil (header absent). The result is { is_report_only, multi_count,
// weaknesses = [{directive, severity, id, detail}, ...] }.
func headersAnalyzeCSP(L *lua.LState) int {
	enforcing := readStringList(L.Get(1))
	reportOnly := readStringList(L.Get(2))
	out := L.NewTable()
	out.RawSetString("is_report_only", lua.LBool(CSPIsReportOnly(enforcing, reportOnly)))
	out.RawSetString("enforcing_count", lua.LNumber(len(enforcing)))
	out.RawSetString("report_only_count", lua.LNumber(len(reportOnly)))
	weaknesses := L.NewTable()
	for i, w := range AnalyzeCSP(enforcing, reportOnly) {
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

// headersCSPParseDirectives wraps CSPParseDirectivesLua. Returns
// a Lua table mapping directive name (lowercased) -> array of source
// tokens (case preserved). Authors call this to read script-src /
// style-src / base-uri off a raw CSP header value the same way the
// csp-bypass Go check does internally.
func headersCSPParseDirectives(L *lua.LState) int {
	dirs := CSPParseDirectivesLua(lua_engine.RequireString(L, 1))
	out := L.NewTable()
	for name, sources := range dirs {
		out.RawSetString(name, lua_engine.PushStringList(L, sources))
	}
	L.Push(out)
	return 1
}

// readDirectivesArg pulls a {directive = [sources]} Lua table back into
// the map shape CSPParseDirectivesLua produces. Used by the
// nonce-reuse / base-uri / script-src-allowlist helpers below so the
// Lua port hands directives back to Go for analysis without each
// helper re-parsing the raw header.
func readDirectivesArg(v lua.LValue) map[string][]string {
	tbl, ok := v.(*lua.LTable)
	if !ok {
		return nil
	}
	out := map[string][]string{}
	tbl.ForEach(func(k, val lua.LValue) {
		name := lua_engine.LValString(k)
		if name == "" {
			return
		}
		if arr, ok := val.(*lua.LTable); ok {
			n := arr.Len()
			srcs := make([]string, 0, n)
			for i := 1; i <= n; i++ {
				srcs = append(srcs, lua_engine.LValString(arr.RawGetInt(i)))
			}
			out[name] = srcs
			return
		}
		if s, ok := val.(lua.LString); ok {
			out[name] = []string{string(s)}
		}
	})
	return out
}

// headersCSPNonceValues returns the unique nonce values in script-src /
// style-src as a flat array, matching nonceValues in Go.
func headersCSPNonceValues(L *lua.LState) int {
	dirs := readDirectivesArg(L.Get(1))
	L.Push(lua_engine.PushStringList(L, CSPNonceValuesLua(dirs)))
	return 1
}

// headersCSPBaseURIHijackable reports whether base-uri is missing or
// permissive enough that a <base href> hijack precondition holds.
func headersCSPBaseURIHijackable(L *lua.LState) int {
	dirs := readDirectivesArg(L.Get(1))
	L.Push(lua.LBool(CSPBaseURIHijackableLua(dirs)))
	return 1
}

// headersCSPScriptSrcAllowsHost takes a sources array and a candidate
// host; returns (matched_raw_string, ok_bool). Same multi-return shape
// as the Go signature so Lua authors can `local raw, ok = ...` and
// quote the matched token in finding detail.
func headersCSPScriptSrcAllowsHost(L *lua.LState) int {
	srcs := readStringList(L.Get(1))
	host := lua_engine.RequireString(L, 2)
	matched, ok := CSPScriptSrcAllowsHostLua(srcs, host)
	L.Push(lua.LString(matched))
	L.Push(lua.LBool(ok))
	return 2
}

// headersCSPConfirmsJSONP reports whether (content_type, body) constitutes
// a confirmed JSONP echo of canary. The Go-side rule (JS content type +
// canary-followed-by-paren) lives in one place so this remains a thin
// forwarder.
func headersCSPConfirmsJSONP(L *lua.LState) int {
	ct := lua_engine.RequireString(L, 1)
	body := lua_engine.RequireString(L, 2)
	canary := lua_engine.RequireString(L, 3)
	L.Push(lua.LBool(CSPConfirmsJSONPLua(ct, []byte(body), canary)))
	return 1
}

// headersCSPRelativeScriptSrcs returns the unique relative <script src>
// values found in body, in sorted order. Skips absolute (scheme:) and
// protocol-relative (//) srcs - those are not affected by base-uri.
func headersCSPRelativeScriptSrcs(L *lua.LState) int {
	L.Push(lua_engine.PushStringList(L, CSPBypassRelativeScriptSrcsLua([]byte(lua_engine.RequireString(L, 1)))))
	return 1
}

// headersCSPBypassJSONPProbes returns the live JSONP-CDN probe catalogue.
// Reads on every call so a test-time table swap (overrideJSONPProbes)
// is observed by the Lua port immediately - the same way Go-side tests
// rely on the swap.
func headersCSPBypassJSONPProbes(L *lua.LState) int {
	out := L.NewTable()
	for i, p := range CSPBypassJSONPProbesLua() {
		entry := L.NewTable()
		entry.RawSetString("host", lua.LString(p.Host))
		entry.RawSetString("url_tmpl", lua.LString(p.URLTmpl))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

// headersCSPBypassCallbackCanary / headersCSPBypassBodyCap expose the
// JSONP canary name and per-probe body cap so the Lua port stamps the
// same values onto wire requests / evidence the Go check uses.
func headersCSPBypassCallbackCanary(L *lua.LState) int {
	L.Push(lua.LString(CSPBypassCallbackCanaryLua()))
	return 1
}

func headersCSPBypassBodyCap(L *lua.LState) int {
	L.Push(lua.LNumber(CSPBypassBodyCapLua()))
	return 1
}

// headersCSPBypassJSONPSnippet builds the per-finding evidence snippet
// (200-byte truncation + cap-reached suffix). Centralised so Go and
// Lua produce byte-identical Evidence.Snippet on the same probe body.
func headersCSPBypassJSONPSnippet(L *lua.LState) int {
	body := lua_engine.RequireString(L, 1)
	truncated := lvalBool(L.Get(2))
	L.Push(lua.LString(JSONPEvidenceSnippetLua([]byte(body), truncated)))
	return 1
}

// headersParseHSTS returns { directives = { name = value }, errors = [...] }.
// directives uses raw values (empty string for flag-only directives);
// the structural-error array carries the spec-fatal duplicates the Go
// parser surfaces separately.
func headersParseHSTS(L *lua.LState) int {
	parsed := ParseHSTSHeader(lua_engine.RequireString(L, 1))
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

// headersIsAbsoluteOrProtocolRelative wraps CSPIsAbsoluteOrProtocolRelativeLua.
// Lua-side scanners that walk script src attrs gate on this to drop
// hijack-immune entries (absolute or "//host/...") from candidate lists.
func headersIsAbsoluteOrProtocolRelative(L *lua.LState) int {
	L.Push(lua.LBool(CSPIsAbsoluteOrProtocolRelativeLua(lua_engine.RequireString(L, 1))))
	return 1
}

// headersAppendQueryParam wraps CSPBypassAppendQueryParamLua so the
// csp-bypass nonce-reuse probe builds the same cache-busting URL the
// Go check does. Returns (resolved_string, err_string).
func headersAppendQueryParam(L *lua.LState) int {
	rawurl := lua_engine.RequireString(L, 1)
	key := lua_engine.RequireString(L, 2)
	val := lua_engine.RequireString(L, 3)
	out, err := CSPBypassAppendQueryParamLua(rawurl, key, val)
	if err != nil {
		L.Push(lua.LString(""))
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(out))
	return 1
}

// lvalBool coerces a Lua value into a bool the same way the gopher-lua
// truth table does (LFalse and LNil are false; everything else is
// truthy). Used by the optional truncated-flag slot on the JSONP
// evidence snippet helper.
func lvalBool(v lua.LValue) bool {
	if v == nil || v == lua.LNil {
		return false
	}
	if b, ok := v.(lua.LBool); ok {
		return bool(b)
	}
	return true
}

func init() {
	lua_engine.RegisterHelperTable("headers", buildHeadersTable)
}
