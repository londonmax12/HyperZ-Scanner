package headers

import (
	"fmt"
	"sort"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// This file exposes the csp-weak check's helpers to the Lua bridge.
// Sibling to csp_weak.go: forwards into the package-private parser +
// per-directive analyzers so the CSP-weak rule set lives in one place.

// CSPWeakness is one (directive, weakness) pair the CSP analyzer
// produced. id is a short stable token used as a per-finding dedupe
// suffix so the same weakness on the same host re-emits the same key.
type CSPWeakness struct {
	Directive string
	Severity  lua_engine.Severity
	ID        string
	Detail    string
}

// AnalyzeCSP runs the full CSP-weak analysis pass against enforcing
// + reportOnly header values and returns the deduplicated, sorted
// weakness list the Go check produces. Both arguments are the raw
// header value sets (http.Header.Values shape); pass an empty slice
// when the header is absent. Returns nil when neither header is
// present, matching the Go check's "absence is security-headers'
// job" short-circuit.
func AnalyzeCSP(enforcing, reportOnly []string) []CSPWeakness {
	if len(enforcing) == 0 && len(reportOnly) == 0 {
		return nil
	}
	var (
		policyHeader string
		isReportOnly bool
	)
	if len(enforcing) > 0 {
		policyHeader = enforcing[0]
	} else {
		policyHeader = reportOnly[0]
		isReportOnly = true
	}
	directives := parseCSP(policyHeader)
	var weaknesses []cspWeakness
	weaknesses = append(weaknesses, analyzeScriptSrc(directives)...)
	weaknesses = append(weaknesses, analyzeStyleSrc(directives)...)
	weaknesses = append(weaknesses, analyzeObjectSrc(directives)...)
	weaknesses = append(weaknesses, analyzeBaseURI(directives)...)
	weaknesses = append(weaknesses, analyzeFrameAncestors(directives)...)
	weaknesses = append(weaknesses, analyzeFormAction(directives)...)
	if isReportOnly {
		weaknesses = append(weaknesses, cspWeakness{
			directive: "<policy>",
			severity:  lua_engine.SeverityMedium,
			id:        "report-only-only",
			detail:    "Only Content-Security-Policy-Report-Only is set; the browser collects violation reports but does not block any of the policy's would-be denials. Until the policy is delivered via Content-Security-Policy as well, none of the CSP-based XSS / framing defenses below are actually enforced.",
		})
	}
	if len(enforcing) > 1 {
		weaknesses = append(weaknesses, cspWeakness{
			directive: "<policy>",
			severity:  lua_engine.SeverityLow,
			id:        "multiple-csp-headers",
			detail:    fmt.Sprintf("Response carries %d Content-Security-Policy headers. Browsers intersect them, so the effective policy is the most restrictive of all directives across the headers - which is rarely what authors intend and tends to mask which directive is doing the blocking. Consolidate to a single CSP header.", len(enforcing)),
		})
	}
	if len(weaknesses) == 0 {
		return nil
	}
	sort.SliceStable(weaknesses, func(i, j int) bool {
		if weaknesses[i].directive != weaknesses[j].directive {
			return weaknesses[i].directive < weaknesses[j].directive
		}
		return weaknesses[i].id < weaknesses[j].id
	})
	out := make([]CSPWeakness, 0, len(weaknesses))
	for _, w := range weaknesses {
		out = append(out, CSPWeakness{
			Directive: w.directive,
			Severity:  w.severity,
			ID:        w.id,
			Detail:    w.detail,
		})
	}
	return out
}

// CSPIsReportOnly tells the Lua port whether AnalyzeCSP analyzed the
// report-only policy (because the enforcing header was absent). The
// .lua port uses this to shape the title suffix and lead-in without
// re-implementing the "which header did we just analyze" decision the
// Go check makes inside Run.
func CSPIsReportOnly(enforcing, reportOnly []string) bool {
	return len(enforcing) == 0 && len(reportOnly) > 0
}
