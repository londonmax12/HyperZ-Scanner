package checks

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

// cspPage builds a Page with the given CSP header(s). Multiple values
// produce multiple Content-Security-Policy header lines, matching what
// a server emitting two CSP headers would look like to net/http.
func cspPage(rawurl string, headers http.Header) page.Page {
	if _, ok := headers["Content-Type"]; !ok {
		headers.Set("Content-Type", "text/html; charset=utf-8")
	}
	return page.Page{
		URL:     rawurl,
		Status:  200,
		Headers: headers,
		Fetched: true,
	}
}

func cspWithEnforced(t *testing.T, policy string) []Finding {
	t.Helper()
	p := cspPage("https://example.com/page", http.Header{
		"Content-Security-Policy": {policy},
	})
	findings, err := CSPWeak{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

// expectIDs asserts the consolidated finding's Details contains an entry
// whose id-tail matches each of the given identifiers. Tests assert by
// id (the short token in cspWeakness.id) rather than full detail text so
// wording tweaks don't require sweeping test updates.
func expectIDs(t *testing.T, findings []Finding, ids ...string) {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d: %+v", len(findings), findings)
	}
	det := strings.Join(findings[0].Details, "\n")
	for _, id := range ids {
		if !strings.Contains(det, idMarker(id)) {
			t.Errorf("expected weakness %q in Details, got:\n%s", id, det)
		}
	}
}

func expectNoIDs(t *testing.T, findings []Finding, ids ...string) {
	t.Helper()
	if len(findings) == 0 {
		return
	}
	det := strings.Join(findings[0].Details, "\n")
	for _, id := range ids {
		if strings.Contains(det, idMarker(id)) {
			t.Errorf("did not expect weakness %q in Details, got:\n%s", id, det)
		}
	}
}

// idMarker turns a cspWeakness.id into a substring guaranteed to appear in
// the consolidated DedupeKey *and* the rendered detail. Detail lines start
// with "<directive> [<severity>]: <text>", so we can't anchor on the id
// itself - it isn't visible there. We re-derive the same key the check
// produced and look for a unique opening fragment in the detail text via
// a per-id keyword table.
func idMarker(id string) string {
	switch id {
	// script-src
	case "unsafe-inline":
		return "'unsafe-inline'"
	case "unsafe-eval":
		return "'unsafe-eval'"
	case "unsafe-hashes":
		return "'unsafe-hashes'"
	case "wildcard-host":
		return "\"*\""
	case "strict-dynamic-without-nonce":
		return "'strict-dynamic'"
	case "inherited-from-default":
		return "inheriting from default-src"
	case "missing-and-no-default":
		return "no restriction"
	// object-src / base-uri / frame-ancestors / form-action
	case "missing":
		return "is not set"
	case "not-none":
		return "rather than 'none'"
	// policy-level
	case "report-only-only":
		return "Content-Security-Policy-Report-Only"
	case "multiple-csp-headers":
		return "Content-Security-Policy headers"
	}
	if strings.HasPrefix(id, "scheme-only:") {
		return "scheme-only source"
	}
	return id
}

func TestCSPWeakName(t *testing.T) {
	if got := (CSPWeak{}).Name(); got != "csp-weak" {
		t.Fatalf("Name = %q, want csp-weak", got)
	}
}

func TestCSPWeakLevel(t *testing.T) {
	if got := (CSPWeak{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestCSPWeakNoCSPHeaderNoOp(t *testing.T) {
	// Absence is security-headers' job, not ours.
	p := cspPage("https://example.com/page", http.Header{})
	findings, err := CSPWeak{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for missing CSP, got %d: %+v", len(findings), findings)
	}
}

func TestCSPWeakStrictNonceBasedPolicyClean(t *testing.T) {
	// A canonical strict nonce-based policy. base-uri 'none', object-src
	// 'none', frame-ancestors 'none', form-action 'self', nonce-bootstrapped
	// strict-dynamic - this is the recommended pattern and should produce
	// zero findings.
	policy := "default-src 'none'; " +
		"script-src 'nonce-abc123' 'strict-dynamic'; " +
		"style-src 'nonce-abc123'; " +
		"img-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'none'; " +
		"frame-ancestors 'none'; " +
		"form-action 'self'"
	findings := cspWithEnforced(t, policy)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for strict policy, got %d: %+v", len(findings), findings)
	}
}

func TestCSPWeakUnsafeInlineInScriptSrcIsCritical(t *testing.T) {
	policy := "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "unsafe-inline")
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
}

func TestCSPWeakUnsafeInlineNeutralizedByNonce(t *testing.T) {
	// CSP3 browsers ignore 'unsafe-inline' when a nonce is also present.
	// The check should not flag it in that case.
	policy := "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-abc'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectNoIDs(t, findings, "unsafe-inline")
}

func TestCSPWeakUnsafeInlineNeutralizedByHash(t *testing.T) {
	policy := "default-src 'self'; script-src 'self' 'unsafe-inline' 'sha256-abcd'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectNoIDs(t, findings, "unsafe-inline")
}

func TestCSPWeakUnsafeEvalFlagged(t *testing.T) {
	policy := "default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "unsafe-eval")
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", findings[0].Severity)
	}
}

func TestCSPWeakUnsafeHashesFlagged(t *testing.T) {
	policy := "default-src 'self'; script-src 'self' 'unsafe-hashes' 'sha256-x'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "unsafe-hashes")
}

func TestCSPWeakWildcardInScriptSrcFlagged(t *testing.T) {
	policy := "default-src 'self'; script-src *; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "wildcard-host")
}

func TestCSPWeakSchemeOnlyHTTPSInScriptSrcFlagged(t *testing.T) {
	policy := "default-src 'self'; script-src 'self' https:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "scheme-only:https:")
}

func TestCSPWeakSchemeOnlyDataInScriptSrcFlagged(t *testing.T) {
	policy := "default-src 'self'; script-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "scheme-only:data:")
}

func TestCSPWeakHostPatternWildcardNotConfusedWithBareWildcard(t *testing.T) {
	// "*.example.com" is a host-pattern wildcard, not the bare "*" that
	// allowlists every origin. The check should not fire wildcard-host on it.
	policy := "default-src 'self'; script-src 'self' *.example.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectNoIDs(t, findings, "wildcard-host")
}

func TestCSPWeakStrictDynamicWithoutNonceFlagged(t *testing.T) {
	policy := "default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "strict-dynamic-without-nonce")
}

func TestCSPWeakStrictDynamicWithNonceClean(t *testing.T) {
	policy := "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectNoIDs(t, findings, "strict-dynamic-without-nonce")
}

func TestCSPWeakScriptSrcInheritedFromDefaultSrc(t *testing.T) {
	// script-src absent but default-src present: inheriting is functional
	// but worth a Low-severity nudge because future default-src loosening
	// silently loosens script policy too.
	policy := "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "inherited-from-default")
}

func TestCSPWeakScriptSrcMissingAndNoDefault(t *testing.T) {
	// Neither script-src nor default-src: scripts are unrestricted.
	policy := "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "missing-and-no-default")
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", findings[0].Severity)
	}
}

func TestCSPWeakObjectSrcMissingFlagged(t *testing.T) {
	// No object-src and no default-src.
	policy := "script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	det := strings.Join(findings[0].Details, "\n")
	if !strings.Contains(det, "object-src") {
		t.Errorf("expected object-src in Details:\n%s", det)
	}
}

func TestCSPWeakObjectSrcInheritsNoneFromDefaultSrc(t *testing.T) {
	// default-src 'none' is sufficient for object-src; should not flag.
	policy := "default-src 'none'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	// object-src inherits 'none' from default-src 'none', should not appear.
	for _, d := range func() []string {
		if len(findings) == 0 {
			return nil
		}
		return findings[0].Details
	}() {
		if strings.HasPrefix(d, "object-src ") {
			t.Errorf("object-src must not be flagged when inheriting 'none': %q", d)
		}
	}
}

func TestCSPWeakObjectSrcExplicitSelfNotNoneFlaggedLow(t *testing.T) {
	// object-src 'self' (not 'none') triggers the not-none nudge.
	policy := "default-src 'self'; script-src 'self'; object-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "not-none")
}

func TestCSPWeakBaseURIMissingFlagged(t *testing.T) {
	// base-uri does NOT inherit from default-src, so even with default-src
	// 'none' a missing base-uri must be flagged.
	policy := "default-src 'none'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	det := strings.Join(findings[0].Details, "\n")
	if !strings.Contains(det, "base-uri") {
		t.Errorf("expected base-uri in Details:\n%s", det)
	}
}

func TestCSPWeakFrameAncestorsMissingFlagged(t *testing.T) {
	policy := "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	det := strings.Join(findings[0].Details, "\n")
	if !strings.Contains(det, "frame-ancestors") {
		t.Errorf("expected frame-ancestors in Details:\n%s", det)
	}
}

func TestCSPWeakFormActionMissingFlagged(t *testing.T) {
	policy := "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
	findings := cspWithEnforced(t, policy)
	det := strings.Join(findings[0].Details, "\n")
	if !strings.Contains(det, "form-action") {
		t.Errorf("expected form-action in Details:\n%s", det)
	}
}

func TestCSPWeakReportOnlyOnlyFlagged(t *testing.T) {
	p := cspPage("https://example.com/page", http.Header{
		"Content-Security-Policy-Report-Only": {"default-src 'self'"},
	})
	findings, err := CSPWeak{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	expectIDs(t, findings, "report-only-only")
	if !strings.Contains(findings[0].Title, "Report-Only") {
		t.Errorf("Title should mention Report-Only: %q", findings[0].Title)
	}
}

func TestCSPWeakEnforcedTakesPrecedenceOverReportOnly(t *testing.T) {
	// When both headers are present, the enforced one is the policy that
	// actually applies; do not flag report-only-only.
	p := cspPage("https://example.com/page", http.Header{
		"Content-Security-Policy":             {"default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"},
		"Content-Security-Policy-Report-Only": {"default-src 'self'"},
	})
	findings, err := CSPWeak{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) > 0 {
		det := strings.Join(findings[0].Details, "\n")
		if strings.Contains(det, "Content-Security-Policy-Report-Only") {
			t.Errorf("report-only-only must not fire when an enforced policy is present:\n%s", det)
		}
	}
}

func TestCSPWeakMultipleEnforcedHeadersFlagged(t *testing.T) {
	p := cspPage("https://example.com/page", http.Header{
		"Content-Security-Policy": {
			"default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
			"script-src 'self' https://cdn.example.com",
		},
	})
	findings, err := CSPWeak{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	expectIDs(t, findings, "multiple-csp-headers")
}

func TestCSPWeakConsolidatesIntoOneFinding(t *testing.T) {
	// Worst-case sloppy CSP: 'unsafe-inline', 'unsafe-eval', wildcard host,
	// scheme-only data:, no object-src, no base-uri, no frame-ancestors,
	// no form-action. Should produce ONE finding with many Details entries.
	policy := "default-src *; script-src 'unsafe-inline' 'unsafe-eval' * data:"
	findings := cspWithEnforced(t, policy)
	if len(findings) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical (unsafe-inline dominates)", findings[0].Severity)
	}
	if len(findings[0].Details) < 5 {
		t.Errorf("expected many Details entries, got %d: %q", len(findings[0].Details), findings[0].Details)
	}
}

func TestCSPWeakSeverityIsMaxOfWeaknesses(t *testing.T) {
	// Only Low-severity weaknesses present.
	policy := "default-src 'none'; script-src 'self'; object-src 'self'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	if len(findings) == 0 {
		t.Skip("policy produced no findings; nothing to assert severity on")
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("Severity = %q, want low (only not-none nudge present)", findings[0].Severity)
	}
}

func TestCSPWeakDuplicateDirectiveFirstWins(t *testing.T) {
	// Per the CSP spec, duplicate directives in the SAME header are
	// ignored after the first. The check must mirror that, so a second
	// strict script-src does not retroactively rescue an earlier sloppy one.
	policy := "script-src 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "unsafe-inline")
}

func TestCSPWeakDirectiveNameCaseInsensitive(t *testing.T) {
	policy := "DEFAULT-SRC 'none'; Script-Src 'self' 'UNSAFE-INLINE'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "unsafe-inline")
}

func TestCSPWeakDedupeKeyPerHost(t *testing.T) {
	// Same weakness, two crawled pages on the same host - one DedupeKey.
	policy := "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	h := http.Header{"Content-Security-Policy": {policy}}
	a, _ := CSPWeak{}.Run(context.Background(), nil, nil, cspPage("https://example.com/a", h.Clone()))
	b, _ := CSPWeak{}.Run(context.Background(), nil, nil, cspPage("https://example.com/b", h.Clone()))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding per page, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeKey != b[0].DedupeKey {
		t.Errorf("DedupeKey should match across pages on same host: %q vs %q", a[0].DedupeKey, b[0].DedupeKey)
	}
}

func TestCSPWeakDedupeKeyDifferentWhenWeaknessesDiffer(t *testing.T) {
	// Two pages on the same host shipping materially different weak
	// policies should NOT collapse to the same DedupeKey - they're
	// different defects even though the check name and host match.
	hUnsafeInline := http.Header{"Content-Security-Policy": {
		"default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
	}}
	hUnsafeEval := http.Header{"Content-Security-Policy": {
		"default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
	}}
	a, _ := CSPWeak{}.Run(context.Background(), nil, nil, cspPage("https://example.com/a", hUnsafeInline))
	b, _ := CSPWeak{}.Run(context.Background(), nil, nil, cspPage("https://example.com/b", hUnsafeEval))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding per page, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeKey == b[0].DedupeKey {
		t.Errorf("DedupeKey should differ for different weaknesses: both %q", a[0].DedupeKey)
	}
}

func TestCSPWeakPopulatesEnrichedFields(t *testing.T) {
	policy := "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Target != "https://example.com/page" || f.URL != "https://example.com/page" {
		t.Errorf("Target/URL mismatch: %q / %q", f.Target, f.URL)
	}
	if f.CWE == "" || !strings.Contains(f.CWE, "CWE-79") {
		t.Errorf("CWE should reference CWE-79: %q", f.CWE)
	}
	if f.OWASP == "" || f.Remediation == "" || f.DedupeKey == "" {
		t.Errorf("OWASP/Remediation/DedupeKey must be populated: %+v", f)
	}
	if f.Evidence == nil {
		t.Fatalf("Evidence is nil")
	}
	if f.Evidence.Method != "GET" || f.Evidence.Status != 200 {
		t.Errorf("Evidence method/status = %q/%d", f.Evidence.Method, f.Evidence.Status)
	}
}

func TestCSPWeakDetailsStableOrder(t *testing.T) {
	// Two runs of the same policy should produce identical Details order
	// so reports diff cleanly across runs.
	policy := "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *; object-src 'self'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'"
	a := cspWithEnforced(t, policy)
	b := cspWithEnforced(t, policy)
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding per run, got %d and %d", len(a), len(b))
	}
	if strings.Join(a[0].Details, "\n") != strings.Join(b[0].Details, "\n") {
		t.Errorf("Details order not stable:\nA:\n%s\nB:\n%s",
			strings.Join(a[0].Details, "\n"),
			strings.Join(b[0].Details, "\n"))
	}
}

func TestCSPWeakParseEmptyAndWhitespace(t *testing.T) {
	// Empty / whitespace / extra semicolons should not panic and should
	// parse the surrounding directives correctly.
	policy := " ; default-src 'self' ;  ; script-src 'self' 'unsafe-inline' ; ; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	findings := cspWithEnforced(t, policy)
	expectIDs(t, findings, "unsafe-inline")
}

func TestParseCSPFirstDirectiveWins(t *testing.T) {
	// Direct unit test on the parser to lock the "first occurrence wins"
	// rule independently of any analyzer behavior.
	out := parseCSP("script-src 'unsafe-inline'; script-src 'self'")
	if got := strings.Join(out["script-src"], " "); got != "'unsafe-inline'" {
		t.Errorf("script-src = %q, want first occurrence to win (%q)", got, "'unsafe-inline'")
	}
}

func TestParseCSPDirectivePresentWithNoSources(t *testing.T) {
	// "upgrade-insecure-requests" has no source list; the parser must
	// represent it as an empty (non-nil) slice so callers can tell
	// "present, zero sources" from "missing".
	out := parseCSP("upgrade-insecure-requests; default-src 'self'")
	v, ok := out["upgrade-insecure-requests"]
	if !ok {
		t.Fatalf("upgrade-insecure-requests should be present in parse map")
	}
	if v == nil {
		t.Errorf("expected non-nil empty slice for sourceless directive, got nil")
	}
	if len(v) != 0 {
		t.Errorf("expected zero sources, got %v", v)
	}
}
