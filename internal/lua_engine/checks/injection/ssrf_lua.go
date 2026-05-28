package injection

// This file exposes the ssrf check's helpers to the Lua bridge.
// Sibling to ssrf.go: forwards into the package-private canary URL,
// body cap, parameter-name catalogues (specific vs generic), proxy-ish
// path keywords, and error-signature table so a future tightening
// lands once.

// SSRFCanaryLua / SSRFBodyCapLua / SSRFSpecificParamNamesLua /
// SSRFGenericParamNamesLua / SSRFLooksProxyish / SSRFMatchesError are
// the algorithm inputs and pattern matcher the Lua port of the SSRF
// check reads. The canary URL, body cap, parameter-name catalogues
// (specific vs generic), proxy-ish path keywords, and error-signature
// table all stay in Go so a future tightening lands once; the rule's
// finding catalog (title / severity / detail / dedupe key) is composed
// in ssrf.lua.
func SSRFCanaryLua() string { return ssrfCanary }

func SSRFBodyCapLua() int { return ssrfBodyCap }

func SSRFSpecificParamNamesLua() []string {
	out := make([]string, len(ssrfSpecificParamNames))
	copy(out, ssrfSpecificParamNames)
	return out
}

func SSRFGenericParamNamesLua() []string {
	out := make([]string, len(ssrfGenericParamNames))
	copy(out, ssrfGenericParamNames)
	return out
}

func SSRFLooksProxyish(path string) bool { return looksProxyish(path) }

func SSRFMatchesError(body []byte) string { return ssrfMatchesError(body) }
