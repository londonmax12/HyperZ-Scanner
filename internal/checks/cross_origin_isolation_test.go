package checks

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

// coiPage builds an HTML 200 Page with the given headers. Cross-origin
// isolation only applies to top-level document responses so every test
// here defaults to text/html unless it is explicitly probing the
// non-HTML or non-200 short-circuit.
func coiPage(rawurl string, headers http.Header) page.Page {
	h := headers.Clone()
	if h == nil {
		h = http.Header{}
	}
	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", "text/html; charset=utf-8")
	}
	return page.Page{
		URL:     rawurl,
		Status:  200,
		Headers: h,
		Fetched: true,
	}
}

// coiWith runs the check against an HTML page carrying the given COOP /
// COEP header values. An empty string means "do not set this header" so
// tests can express each pairing concisely. For multi-header scenarios
// drive the check directly via coiPage.
func coiWith(t *testing.T, coop, coep string) []Finding {
	t.Helper()
	h := http.Header{}
	if coop != "" {
		h.Set("Cross-Origin-Opener-Policy", coop)
	}
	if coep != "" {
		h.Set("Cross-Origin-Embedder-Policy", coep)
	}
	p := coiPage("https://example.com/page", h)
	findings, err := CrossOriginIsolation{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

// coiExpectIDs asserts the consolidated finding's Details contains an
// entry whose marker phrase matches each of the given weakness ids.
// Tests assert by id keyword (not full detail text) so wording tweaks
// do not require sweeping test updates.
func coiExpectIDs(t *testing.T, findings []Finding, ids ...string) {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d: %+v", len(findings), findings)
	}
	det := strings.Join(findings[0].Details, "\n")
	for _, id := range ids {
		if !strings.Contains(det, coiIDMarker(id)) {
			t.Errorf("expected weakness %q in Details, got:\n%s", id, det)
		}
	}
}

func coiExpectNoIDs(t *testing.T, findings []Finding, ids ...string) {
	t.Helper()
	if len(findings) == 0 {
		return
	}
	det := strings.Join(findings[0].Details, "\n")
	for _, id := range ids {
		if strings.Contains(det, coiIDMarker(id)) {
			t.Errorf("did not expect weakness %q in Details, got:\n%s", id, det)
		}
	}
}

// coiIDMarker turns a weakness id into a substring guaranteed to appear
// in the rendered detail text. Detail lines do not carry the bare id, so
// we anchor on a unique phrase per weakness branch.
func coiIDMarker(id string) string {
	switch id {
	case "coop-multiple-headers":
		return "Cross-Origin-Opener-Policy headers"
	case "coep-multiple-headers":
		return "Cross-Origin-Embedder-Policy headers"
	case "coop-invalid-value":
		return "Cross-Origin-Opener-Policy value"
	case "coop-unsafe-none":
		return "Cross-Origin-Opener-Policy is explicitly set to unsafe-none"
	case "coop-allow-popups-with-coep":
		return "allow-popups COOP variants do not enable cross-origin isolation"
	case "coep-invalid-value":
		return "Cross-Origin-Embedder-Policy value"
	case "coep-unsafe-none":
		return "Cross-Origin-Embedder-Policy is explicitly set to unsafe-none"
	case "coop-missing-with-coep":
		return "Cross-Origin-Embedder-Policy is set but Cross-Origin-Opener-Policy is missing"
	}
	return id
}

func TestCrossOriginIsolationName(t *testing.T) {
	if got := (CrossOriginIsolation{}).Name(); got != "cross-origin-isolation" {
		t.Fatalf("Name = %q, want cross-origin-isolation", got)
	}
}

func TestCrossOriginIsolationLevel(t *testing.T) {
	if got := (CrossOriginIsolation{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestCrossOriginIsolationNoHeadersNoOp(t *testing.T) {
	// Neither COOP nor COEP set: no evidence the author was reaching
	// for isolation, so we stay quiet. SecurityHeaders also stays quiet
	// here so non-isolated sites do not get spammed.
	findings := coiWith(t, "", "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when neither header set, got %d: %+v", len(findings), findings)
	}
}

func TestCrossOriginIsolationCleanIsolationNoOp(t *testing.T) {
	findings := coiWith(t, "same-origin", "require-corp")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for clean isolation, got %d: %+v", len(findings), findings)
	}
}

func TestCrossOriginIsolationCredentiallessIsClean(t *testing.T) {
	// credentialless is a newer but spec-recognized COEP value.
	findings := coiWith(t, "same-origin", "credentialless")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for credentialless COEP, got %d: %+v", len(findings), findings)
	}
}

func TestCrossOriginIsolationCOOPAloneIsClean(t *testing.T) {
	// COOP=same-origin without COEP is a legitimate window.opener
	// hardening choice; the site is not aiming for full isolation. Do
	// not flag.
	findings := coiWith(t, "same-origin", "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for COOP-only hardening, got %d: %+v", len(findings), findings)
	}
}

func TestCrossOriginIsolationCOOPAllowPopupsAloneIsClean(t *testing.T) {
	// allow-popups alone (no COEP) is a legitimate hardening choice for
	// sites that need window.opener handed to popups (OAuth flows etc).
	findings := coiWith(t, "same-origin-allow-popups", "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for allow-popups alone, got %d: %+v", len(findings), findings)
	}
}

func TestCrossOriginIsolationCOEPWithoutCOOPIsMedium(t *testing.T) {
	findings := coiWith(t, "", "require-corp")
	coiExpectIDs(t, findings, "coop-missing-with-coep")
	if findings[0].Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium", findings[0].Severity)
	}
}

func TestCrossOriginIsolationCOEPCredentiallessWithoutCOOPIsMedium(t *testing.T) {
	findings := coiWith(t, "", "credentialless")
	coiExpectIDs(t, findings, "coop-missing-with-coep")
	if findings[0].Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium", findings[0].Severity)
	}
}

func TestCrossOriginIsolationCOEPUnsafeNoneWithoutCOOPNoPartialFlag(t *testing.T) {
	// COEP=unsafe-none plus missing COOP should flag the explicit
	// unsafe-none opt-out but NOT the partial-isolation weakness: an
	// unsafe-none COEP was never going to isolate anything regardless
	// of COOP.
	findings := coiWith(t, "", "unsafe-none")
	coiExpectIDs(t, findings, "coep-unsafe-none")
	coiExpectNoIDs(t, findings, "coop-missing-with-coep")
}

func TestCrossOriginIsolationCOOPUnsafeNoneIsLow(t *testing.T) {
	findings := coiWith(t, "unsafe-none", "require-corp")
	coiExpectIDs(t, findings, "coop-unsafe-none")
	if findings[0].Severity != SeverityLow {
		t.Errorf("Severity = %q, want low", findings[0].Severity)
	}
}

func TestCrossOriginIsolationCOEPUnsafeNoneIsLow(t *testing.T) {
	findings := coiWith(t, "same-origin", "unsafe-none")
	coiExpectIDs(t, findings, "coep-unsafe-none")
	if findings[0].Severity != SeverityLow {
		t.Errorf("Severity = %q, want low", findings[0].Severity)
	}
}

func TestCrossOriginIsolationAllowPopupsWithCOEPIsLow(t *testing.T) {
	// allow-popups paired with a strong COEP is the classic "I thought
	// this enabled isolation" misconfiguration: COEP is loaded but the
	// COOP variant cannot satisfy the isolation requirement.
	findings := coiWith(t, "same-origin-allow-popups", "require-corp")
	coiExpectIDs(t, findings, "coop-allow-popups-with-coep")
	if findings[0].Severity != SeverityLow {
		t.Errorf("Severity = %q, want low", findings[0].Severity)
	}
}

func TestCrossOriginIsolationNoopenerAllowPopupsWithCOEPIsLow(t *testing.T) {
	// The newer noopener-allow-popups COOP value also fails to enable
	// isolation, by the same rationale as same-origin-allow-popups.
	findings := coiWith(t, "noopener-allow-popups", "require-corp")
	coiExpectIDs(t, findings, "coop-allow-popups-with-coep")
}

func TestCrossOriginIsolationWhitespaceOnlyHeaderTreatedAsAbsent(t *testing.T) {
	// A whitespace-only header value is indistinguishable from no header
	// for our purposes: there is no policy to evaluate and no evidence
	// the author was reaching for isolation. Pins the call-site contract
	// that complements TestCOIPolicyOfSkipsEmptyValues.
	p := coiPage("https://example.com/page", http.Header{
		"Cross-Origin-Opener-Policy": {"   "},
	})
	findings, err := CrossOriginIsolation{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for whitespace-only COOP, got %d: %+v", len(findings), findings)
	}
}

func TestCrossOriginIsolationAllowPopupsWithInvalidCOEPFiresBoth(t *testing.T) {
	// Author set an allow-popups COOP variant alongside a typo'd COEP.
	// Two independent misconfigurations: the COEP value is invalid AND
	// the COOP variant could not enable isolation even if COEP were
	// valid. Both should surface so the author sees the conceptual
	// COOP-variant mismatch instead of only the parse complaint.
	findings := coiWith(t, "same-origin-allow-popups", "garbage")
	coiExpectIDs(t, findings, "coep-invalid-value", "coop-allow-popups-with-coep")
}

func TestCrossOriginIsolationAllowPopupsWithoutCOEPIsClean(t *testing.T) {
	// allow-popups alone (no COEP) is legitimate; isolation was never
	// the goal, so do not flag the allow-popups variant.
	findings := coiWith(t, "same-origin-allow-popups", "")
	coiExpectNoIDs(t, findings, "coop-allow-popups-with-coep")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for allow-popups without COEP, got %d: %+v", len(findings), findings)
	}
}

func TestCrossOriginIsolationCOOPInvalidValueIsLow(t *testing.T) {
	findings := coiWith(t, "totally-not-a-policy", "require-corp")
	coiExpectIDs(t, findings, "coop-invalid-value")
	if findings[0].Severity != SeverityLow {
		t.Errorf("Severity = %q, want low", findings[0].Severity)
	}
}

func TestCrossOriginIsolationCOEPInvalidValueIsLow(t *testing.T) {
	findings := coiWith(t, "same-origin", "garbage")
	coiExpectIDs(t, findings, "coep-invalid-value")
	if findings[0].Severity != SeverityLow {
		t.Errorf("Severity = %q, want low", findings[0].Severity)
	}
}

func TestCrossOriginIsolationMultipleCOOPHeadersFlagged(t *testing.T) {
	p := coiPage("https://example.com/page", http.Header{
		"Cross-Origin-Opener-Policy": {"same-origin", "unsafe-none"},
		"Cross-Origin-Embedder-Policy": {"require-corp"},
	})
	findings, err := CrossOriginIsolation{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	coiExpectIDs(t, findings, "coop-multiple-headers")
}

func TestCrossOriginIsolationMultipleCOEPHeadersFlagged(t *testing.T) {
	p := coiPage("https://example.com/page", http.Header{
		"Cross-Origin-Opener-Policy":   {"same-origin"},
		"Cross-Origin-Embedder-Policy": {"require-corp", "unsafe-none"},
	})
	findings, err := CrossOriginIsolation{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	coiExpectIDs(t, findings, "coep-multiple-headers")
}

func TestCrossOriginIsolationNonHTMLNoOp(t *testing.T) {
	// COOP / COEP on a JSON API are inert. Do not flag.
	h := http.Header{
		"Content-Type":               {"application/json"},
		"Cross-Origin-Opener-Policy": {"garbage"},
	}
	p := page.Page{
		URL: "https://example.com/api", Status: 200, Headers: h, Fetched: true,
	}
	findings, err := CrossOriginIsolation{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-HTML response, got %d: %+v", len(findings), findings)
	}
}

func TestCrossOriginIsolationNon200NoOp(t *testing.T) {
	// COOP / COEP on a 404 page do not represent a deployed policy.
	h := http.Header{
		"Content-Type":               {"text/html"},
		"Cross-Origin-Opener-Policy": {"garbage"},
	}
	p := page.Page{
		URL: "https://example.com/404", Status: 404, Headers: h, Fetched: true,
	}
	findings, err := CrossOriginIsolation{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-200 response, got %d: %+v", len(findings), findings)
	}
}

func TestCrossOriginIsolationReportToParameterDoesNotFalsePositive(t *testing.T) {
	// The Reporting-API parameter `report-to="..."` is a valid trailing
	// directive on COOP / COEP; it must not be parsed as part of the
	// policy token and must not trip invalid-value.
	findings := coiWith(t, `same-origin; report-to="coop-endpoint"`, `require-corp; report-to="coep-endpoint"`)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings with report-to parameters, got %d: %+v", len(findings), findings)
	}
}

func TestCrossOriginIsolationCaseInsensitiveValueMatch(t *testing.T) {
	// The spec defines policy tokens as lowercase, but a typo in case
	// should be normalized rather than misreported as an invalid value.
	findings := coiWith(t, "Same-Origin", "Require-Corp")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for case-variant valid values, got %d: %+v", len(findings), findings)
	}
}

func TestCrossOriginIsolationConsolidatesIntoOneFinding(t *testing.T) {
	// Worst-case sloppy isolation: both headers explicit unsafe-none.
	// Should produce ONE finding with both Details entries.
	findings := coiWith(t, "unsafe-none", "unsafe-none")
	if len(findings) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d: %+v", len(findings), findings)
	}
	if len(findings[0].Details) < 2 {
		t.Errorf("expected >=2 Details entries, got %d: %q", len(findings[0].Details), findings[0].Details)
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("Severity = %q, want low (both weaknesses are low)", findings[0].Severity)
	}
}

func TestCrossOriginIsolationSeverityIsMaxOfWeaknesses(t *testing.T) {
	// Mix a Medium (missing COOP with strong COEP) and a Low (multiple
	// COEP headers). Consolidated severity must be Medium.
	p := coiPage("https://example.com/page", http.Header{
		"Cross-Origin-Embedder-Policy": {"require-corp", "credentialless"},
	})
	findings, err := CrossOriginIsolation{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium (medium dominates low)", findings[0].Severity)
	}
}

func TestCrossOriginIsolationPopulatesEnrichedFields(t *testing.T) {
	findings := coiWith(t, "unsafe-none", "require-corp")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Target != "https://example.com/page" || f.URL != "https://example.com/page" {
		t.Errorf("Target/URL mismatch: %q / %q", f.Target, f.URL)
	}
	if !strings.Contains(f.CWE, "CWE-693") {
		t.Errorf("CWE should reference CWE-693: %q", f.CWE)
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

func TestCrossOriginIsolationDedupeKeyPerHost(t *testing.T) {
	// Same weakness, two crawled pages on the same host: one DedupeKey.
	h := http.Header{"Cross-Origin-Embedder-Policy": {"require-corp"}}
	a, _ := CrossOriginIsolation{}.Run(context.Background(), nil, nil, coiPage("https://example.com/a", h.Clone()))
	b, _ := CrossOriginIsolation{}.Run(context.Background(), nil, nil, coiPage("https://example.com/b", h.Clone()))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding per page, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeKey != b[0].DedupeKey {
		t.Errorf("DedupeKey should match across pages on same host: %q vs %q", a[0].DedupeKey, b[0].DedupeKey)
	}
}

func TestCrossOriginIsolationDedupeKeyDifferentWhenWeaknessesDiffer(t *testing.T) {
	// Two pages on the same host with materially different weak policies
	// must NOT collapse to the same DedupeKey.
	hA := http.Header{"Cross-Origin-Embedder-Policy": {"require-corp"}} // coop-missing-with-coep
	hB := http.Header{
		"Cross-Origin-Opener-Policy":   {"unsafe-none"},
		"Cross-Origin-Embedder-Policy": {"require-corp"},
	} // coop-unsafe-none
	a, _ := CrossOriginIsolation{}.Run(context.Background(), nil, nil, coiPage("https://example.com/a", hA))
	b, _ := CrossOriginIsolation{}.Run(context.Background(), nil, nil, coiPage("https://example.com/b", hB))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding per page, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeKey == b[0].DedupeKey {
		t.Errorf("DedupeKey should differ for different weaknesses: both %q", a[0].DedupeKey)
	}
}

func TestCrossOriginIsolationDetailsStableOrder(t *testing.T) {
	// Two runs of the same policy must produce identical Details order
	// so reports diff cleanly across runs.
	a := coiWith(t, "unsafe-none", "unsafe-none")
	b := coiWith(t, "unsafe-none", "unsafe-none")
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding per run, got %d and %d", len(a), len(b))
	}
	if strings.Join(a[0].Details, "\n") != strings.Join(b[0].Details, "\n") {
		t.Errorf("Details order not stable:\nA:\n%s\nB:\n%s",
			strings.Join(a[0].Details, "\n"),
			strings.Join(b[0].Details, "\n"))
	}
}

func TestCOIPolicyOfStripsParameters(t *testing.T) {
	policy, raw, ok := coiPolicyOf([]string{`same-origin; report-to="endpoint"`})
	if !ok {
		t.Fatal("expected present=true")
	}
	if policy != "same-origin" {
		t.Errorf("policy = %q, want same-origin", policy)
	}
	if !strings.HasPrefix(raw, "same-origin;") {
		t.Errorf("raw should retain parameters for user-facing detail: %q", raw)
	}
}

func TestCOIPolicyOfSkipsEmptyValues(t *testing.T) {
	policy, _, ok := coiPolicyOf([]string{"", "  ", "same-origin"})
	if !ok || policy != "same-origin" {
		t.Errorf("expected to find same-origin past empty entries, got policy=%q present=%v", policy, ok)
	}
}

func TestCOIPolicyOfAbsent(t *testing.T) {
	if _, _, ok := coiPolicyOf(nil); ok {
		t.Error("expected present=false for nil values")
	}
	if _, _, ok := coiPolicyOf([]string{"", " "}); ok {
		t.Error("expected present=false for whitespace-only values")
	}
}
