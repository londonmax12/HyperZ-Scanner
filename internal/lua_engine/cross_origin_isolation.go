package lua_engine

import (
	"strings"
)

// CrossOriginIsolation inspects Cross-Origin-Opener-Policy (COOP) and
// Cross-Origin-Embedder-Policy (COEP) for configurations that prevent the
// document from reaching the cross-origin isolated state, or that leave
// the window.opener / cross-origin embed defenses partially deployed.
//
// Cross-origin isolation gates the powerful platform features that became
// unsafe after Spectre: SharedArrayBuffer, performance.measureUserAgent-
// SpecificMemory(), high-resolution timers, and the JS Self-Profiling API.
// Reaching the isolated state requires BOTH of:
//
//	Cross-Origin-Opener-Policy: same-origin
//	Cross-Origin-Embedder-Policy: require-corp   (or credentialless)
//
// Either header on its own is insufficient: COOP alone hardens window
// .opener but does not isolate the agent cluster; COEP alone still
// enforces CORP on cross-origin subresources (and can break embeds that
// lack it) but does not enable cross-origin isolation without COOP.
//
// This complements [SecurityHeaders], which never fires for COOP / COEP
// (the headers are advanced opt-ins; flagging every site without them
// would be noise). The check here fires only when the response shows
// evidence the author was reaching for isolation - i.e. at least one of
// COOP or COEP is present - and surfaces the ways that goal is undone.
//
// Severity climbs with how completely the weakness defeats the policy:
// COEP set without COOP (Medium) leaves the document believing it is
// isolated when in fact the browser falls back to unsafe-none; explicit
// unsafe-none (Low) is the no-op default the header was supposed to
// improve on; allow-popups variants paired with COEP (Low) are the
// classic "I thought this enabled isolation" misconfiguration; invalid
// values and multi-header confusion are Low parse-level bugs.
type CrossOriginIsolation struct{}

// coiWeakness is one (header, problem) entry surfaced during analysis.
// The check consolidates every weakness into a single Finding (mirroring
// [HSTSWeak] / [CSPWeak]) so a response with three problems produces one
// report row with three bullets instead of three near-duplicate rows.
type coiWeakness struct {
	severity Severity
	// id is a short stable token used as a per-weakness dedupe suffix so
	// the same defect on the same host produces the same DedupeKey across
	// multiple runs and across crawled URLs.
	id     string
	detail string
}

// Recognized policy tokens. The spec defines these as case-sensitive
// lowercase tokens; we lower-case the observed value before comparison so
// a "Same-Origin" typo still maps to a known policy (and we surface the
// invalid case via the parser rather than as a missing-header).
var (
	coopValidValues = map[string]bool{
		"unsafe-none":              true,
		"same-origin-allow-popups": true,
		"same-origin":              true,
		// noopener-allow-popups is a proposed COOP value with early /
		// partial cross-browser implementation; accepted here so a
		// forward-looking site using it is not mis-flagged as invalid.
		"noopener-allow-popups": true,
	}
	coepValidValues = map[string]bool{
		"unsafe-none":    true,
		"require-corp":   true,
		"credentialless": true,
	}
)

// coiPolicyOf returns the lower-cased policy token from a COOP / COEP
// header value list, the original (pre-normalization) raw value used in
// human-readable detail text, and whether any non-empty value was seen.
//
// Only the first header instance is considered; the multi-header case is
// surfaced separately by the caller. The leading token is taken up to
// the first ';' so parameters such as `report-to="endpoint"` (used by the
// Reporting API) do not poison the token comparison.
func coiPolicyOf(values []string) (policy, raw string, present bool) {
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		raw = trimmed
		token := trimmed
		if i := strings.IndexByte(token, ';'); i >= 0 {
			token = token[:i]
		}
		policy = strings.ToLower(strings.TrimSpace(token))
		present = true
		return
	}
	return "", "", false
}
