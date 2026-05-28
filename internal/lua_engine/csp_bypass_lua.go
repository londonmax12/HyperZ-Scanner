package lua_engine

import (
	"sort"
	"strings"
)

// This file exposes the csp-bypass check's helpers to the Lua bridge.
// Sibling to csp_bypass.go: forwards into the package-private nonce /
// host-allow / JSONP-probe helpers so the Lua port consumes the same
// rule set the active csp-bypass probes use.

// CSPParseDirectivesLua exposes the package-private parseCSP so the
// csp-bypass Lua port consumes the same first-occurrence-wins splitter
// the active probes use to read script-src / style-src / base-uri.
// Returns directive -> source-list. Directive names are lower-cased;
// source tokens preserve their case so nonce / hash byte-equality
// checks downstream stay exact.
func CSPParseDirectivesLua(header string) map[string][]string {
	return parseCSP(header)
}

// CSPNonceValuesLua exposes nonceValues so the csp-bypass Lua port
// finds the same nonce VALUES (the bit after "nonce-") in script-src
// and style-src that the Go probe compares across two responses.
func CSPNonceValuesLua(dirs map[string][]string) []string {
	return nonceValues(dirs)
}

// CSPBaseURIHijackableLua exposes baseURIIsHijackable so the Lua port
// decides "missing or permissive base-uri" the same way the Go probe
// does. true means the precondition for the <base href> hijack holds
// and the body sweep is worth running.
func CSPBaseURIHijackableLua(dirs map[string][]string) bool {
	return baseURIIsHijackable(dirs)
}

// CSPScriptSrcAllowsHostLua exposes cspScriptSrcAllowsHost so the JSONP
// probe arm gates on the same host-matching rules (bare *, scheme-only,
// wildcard subdomain incl. apex, host[:port], scheme://host[:port][/path],
// keywords ignored). Returns the original source token that matched and
// a bool, mirroring the Go signature so the Lua port can quote the exact
// CSP token responsible in finding detail.
func CSPScriptSrcAllowsHostLua(sources []string, candidateHost string) (string, bool) {
	return cspScriptSrcAllowsHost(sources, candidateHost)
}

// CSPConfirmsJSONPLua exposes confirmsJSONP so the JSONP probe arm
// applies the same JS-content-type + canary-followed-by-paren rule to
// decide a JSONP echo is conclusive. canary is the per-probe callback
// name embedded in the request.
func CSPConfirmsJSONPLua(contentType string, body []byte, canary string) bool {
	return confirmsJSONP(contentType, body, canary)
}

// CSPBypassRelativeScriptSrcsLua extracts unique relative <script src>
// values from body in sorted order. Skips absolute (scheme:) and
// protocol-relative (//) srcs - those are not affected by a <base href>
// hijack and were never the bug. The Lua port reads this list to gate
// the base-uri-hijack finding on whether the page actually depends on
// relative loads.
func CSPBypassRelativeScriptSrcsLua(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	matches := cspScriptSrcRelativeRegex.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, m := range matches {
		src := strings.TrimSpace(string(m[1]))
		if src == "" {
			continue
		}
		if isAbsoluteOrProtocolRelative(src) {
			continue
		}
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}
		out = append(out, src)
	}
	sort.Strings(out)
	return out
}

// CSPIsAbsoluteOrProtocolRelativeLua exposes isAbsoluteOrProtocolRelative
// so authors of additional CSP-related Lua checks can use the same
// scheme-or-//-detection without re-implementing it.
func CSPIsAbsoluteOrProtocolRelativeLua(src string) bool {
	return isAbsoluteOrProtocolRelative(src)
}

// CSPBypassAppendQueryParamLua exposes appendQueryParam so the Lua
// nonce-reuse probe builds the same cache-busting URL the Go check
// uses. The Lua side already has url.Parse + url:string assembly via
// the bridge, but using the Go-side helper here guarantees byte-for-
// byte identical re-fetch URLs across implementations.
func CSPBypassAppendQueryParamLua(rawurl, key, val string) (string, error) {
	return appendQueryParam(rawurl, key, val)
}

// CSPBypassJSONPProbeLua is one entry from the JSONP-CDN catalogue the
// active csp-bypass JSONP arm walks. The .lua port reads the current
// snapshot of jsonpProbes via CSPBypassJSONPProbesLua so a test that
// swaps the table (overrideJSONPProbes) flips both implementations to
// the test endpoint in lockstep.
type CSPBypassJSONPProbeLua struct {
	Host    string
	URLTmpl string
}

// CSPBypassJSONPProbesLua returns the live jsonpProbes table as a
// flat slice. Reading on every call (rather than caching) means a
// test-time table swap is observed immediately by the Lua port.
func CSPBypassJSONPProbesLua() []CSPBypassJSONPProbeLua {
	out := make([]CSPBypassJSONPProbeLua, 0, len(jsonpProbes))
	for _, p := range jsonpProbes {
		out = append(out, CSPBypassJSONPProbeLua{Host: p.host, URLTmpl: p.urlTmpl})
	}
	return out
}

// CSPBypassCallbackCanaryLua / CSPBypassBodyCapLua expose the JSONP
// canary callback name and the per-probe body cap so the Lua port
// stamps the same values the Go check uses. Constants only - no
// authoring surface for changing them, which is the point.
func CSPBypassCallbackCanaryLua() string { return cspBypassCallbackCanary }
func CSPBypassBodyCapLua() int           { return cspBypassBodyCap }

// JSONPEvidenceSnippetLua exposes jsonpEvidenceSnippet so the Lua port
// builds an identical evidence snippet (200-byte truncation + cap-
// reached suffix). Keeping it in Go means a future tweak to the
// snippet length / shape lands once.
func JSONPEvidenceSnippetLua(body []byte, truncated bool) string {
	return jsonpEvidenceSnippet(body, truncated)
}

// OverrideCSPBypassJSONPProbesForTest swaps the package-private
// jsonpProbes table for the duration of a parity test and returns a
// restore func. The checks_lua tests use this to point both the Go
// check and (transitively through CSPBypassJSONPProbesLua) the Lua
// port at a httptest endpoint without each test reaching into the
// private slice directly.
func OverrideCSPBypassJSONPProbesForTest(probes []CSPBypassJSONPProbeLua) (restore func()) {
	prev := jsonpProbes
	jsonpProbes = make([]jsonpProbe, len(probes))
	for i, p := range probes {
		jsonpProbes[i] = jsonpProbe{host: p.Host, urlTmpl: p.URLTmpl}
	}
	return func() { jsonpProbes = prev }
}
