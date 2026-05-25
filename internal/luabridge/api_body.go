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
	return t
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
