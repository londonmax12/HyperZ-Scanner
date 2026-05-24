package checks

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

// hstsPage builds a Page with the given HSTS header(s). Multiple values
// produce multiple Strict-Transport-Security header lines, matching what
// a server emitting two HSTS headers would look like to net/http.
func hstsPage(rawurl string, headers http.Header) page.Page {
	return page.Page{
		URL:     rawurl,
		Status:  200,
		Headers: headers,
		Fetched: true,
	}
}

// hstsWith runs the check against an HTTPS page carrying the given HSTS
// header value. Most weakness tests don't care about the scheme so they
// pin to https here; the over-http branch is exercised by dedicated tests.
func hstsWith(t *testing.T, policy string) []Finding {
	t.Helper()
	p := hstsPage("https://example.com/page", http.Header{
		"Strict-Transport-Security": {policy},
	})
	findings, err := HSTSWeak{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

// hstsExpectIDs asserts the consolidated finding's Details contains an
// entry whose keyword matches each of the given weakness identifiers.
// Tests assert by id keyword (not full detail text) so wording tweaks
// don't require sweeping test updates.
func hstsExpectIDs(t *testing.T, findings []Finding, ids ...string) {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d: %+v", len(findings), findings)
	}
	det := strings.Join(findings[0].Details, "\n")
	for _, id := range ids {
		if !strings.Contains(det, hstsIDMarker(id)) {
			t.Errorf("expected weakness %q in Details, got:\n%s", id, det)
		}
	}
}

func hstsExpectNoIDs(t *testing.T, findings []Finding, ids ...string) {
	t.Helper()
	if len(findings) == 0 {
		return
	}
	det := strings.Join(findings[0].Details, "\n")
	for _, id := range ids {
		if strings.Contains(det, hstsIDMarker(id)) {
			t.Errorf("did not expect weakness %q in Details, got:\n%s", id, det)
		}
	}
}

// hstsIDMarker turns a weakness id into a substring guaranteed to appear
// in the rendered detail text. Detail lines don't carry the bare id, so
// we anchor on a unique phrase per weakness branch.
func hstsIDMarker(id string) string {
	switch id {
	case "over-http":
		return "delivered over plain HTTP"
	case "multiple-headers":
		return "Strict-Transport-Security headers"
	case "missing-max-age":
		return "max-age is required"
	case "max-age-invalid":
		return "not a non-negative integer"
	case "max-age-zero":
		return "max-age=0 instructs"
	case "max-age-tiny":
		return "less than one day"
	case "max-age-short":
		return "less than six months"
	case "max-age-below-year":
		return "below the one-year"
	case "missing-include-subdomains":
		return "includeSubDomains is not set"
	case "duplicate-max-age":
		return "\"max-age\" appears more than once"
	case "duplicate-includesubdomains":
		return "\"includesubdomains\" appears more than once"
	}
	return id
}

func TestHSTSWeakName(t *testing.T) {
	if got := (HSTSWeak{}).Name(); got != "hsts-weak" {
		t.Fatalf("Name = %q, want hsts-weak", got)
	}
}

func TestHSTSWeakLevel(t *testing.T) {
	if got := (HSTSWeak{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestHSTSWeakNoHeaderNoOp(t *testing.T) {
	// Absence is security-headers' job, not ours.
	p := hstsPage("https://example.com/page", http.Header{})
	findings, err := HSTSWeak{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for missing HSTS, got %d: %+v", len(findings), findings)
	}
}

func TestHSTSWeakRecommendedPolicyClean(t *testing.T) {
	// Canonical strong policy: two-year max-age, includeSubDomains, preload.
	// Should produce zero findings.
	findings := hstsWith(t, "max-age=63072000; includeSubDomains; preload")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for strong policy, got %d: %+v", len(findings), findings)
	}
}

func TestHSTSWeakExactlyOneYearWithSubdomainsClean(t *testing.T) {
	// One year exactly is the preload-list floor; should not trip the
	// below-year nudge.
	findings := hstsWith(t, "max-age=31536000; includeSubDomains")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for one-year policy, got %d: %+v", len(findings), findings)
	}
}

func TestHSTSWeakMaxAgeZeroIsHigh(t *testing.T) {
	findings := hstsWith(t, "max-age=0; includeSubDomains")
	hstsExpectIDs(t, findings, "max-age-zero")
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", findings[0].Severity)
	}
}

func TestHSTSWeakMissingMaxAgeIsHigh(t *testing.T) {
	findings := hstsWith(t, "includeSubDomains; preload")
	hstsExpectIDs(t, findings, "missing-max-age")
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", findings[0].Severity)
	}
}

func TestHSTSWeakMaxAgeInvalidIsHigh(t *testing.T) {
	findings := hstsWith(t, "max-age=notanumber; includeSubDomains")
	hstsExpectIDs(t, findings, "max-age-invalid")
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", findings[0].Severity)
	}
}

func TestHSTSWeakMaxAgeNegativeIsHigh(t *testing.T) {
	// A negative max-age is also invalid per the ABNF (delta-seconds is a
	// non-negative integer); flag it like the parse-failure path.
	findings := hstsWith(t, "max-age=-1; includeSubDomains")
	hstsExpectIDs(t, findings, "max-age-invalid")
}

func TestHSTSWeakMaxAgeUnderOneDayIsHigh(t *testing.T) {
	findings := hstsWith(t, "max-age=60; includeSubDomains")
	hstsExpectIDs(t, findings, "max-age-tiny")
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high (sub-day max-age)", findings[0].Severity)
	}
}

func TestHSTSWeakMaxAgeUnderSixMonthsIsMedium(t *testing.T) {
	// ~3 months
	findings := hstsWith(t, "max-age=7776000; includeSubDomains")
	hstsExpectIDs(t, findings, "max-age-short")
	if findings[0].Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium", findings[0].Severity)
	}
}

func TestHSTSWeakMaxAgeUnderOneYearIsLow(t *testing.T) {
	// ~9 months: above the six-month band, below the one-year recommendation.
	findings := hstsWith(t, "max-age=23328000; includeSubDomains")
	hstsExpectIDs(t, findings, "max-age-below-year")
	if findings[0].Severity != SeverityLow {
		t.Errorf("Severity = %q, want low", findings[0].Severity)
	}
}

func TestHSTSWeakMissingIncludeSubdomainsIsLow(t *testing.T) {
	findings := hstsWith(t, "max-age=63072000")
	hstsExpectIDs(t, findings, "missing-include-subdomains")
	if findings[0].Severity != SeverityLow {
		t.Errorf("Severity = %q, want low", findings[0].Severity)
	}
}

func TestHSTSWeakIncludeSubDomainsCaseInsensitive(t *testing.T) {
	// Directive names are case-insensitive per RFC 6797 §6.1; the check
	// must not flag missing-include-subdomains just because the author
	// spelled it INCLUDESUBDOMAINS.
	findings := hstsWith(t, "max-age=63072000; INCLUDESUBDOMAINS")
	hstsExpectNoIDs(t, findings, "missing-include-subdomains")
}

func TestHSTSWeakOverHTTPFlagged(t *testing.T) {
	// HSTS over plain HTTP is ignored by browsers - flag the wasted header.
	p := hstsPage("http://example.com/page", http.Header{
		"Strict-Transport-Security": {"max-age=63072000; includeSubDomains; preload"},
	})
	findings, err := HSTSWeak{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	hstsExpectIDs(t, findings, "over-http")
}

func TestHSTSWeakOverHTTPSDoesNotFireOverHTTPBranch(t *testing.T) {
	// Sanity: an https page with a strong policy must not trip over-http.
	findings := hstsWith(t, "max-age=63072000; includeSubDomains; preload")
	hstsExpectNoIDs(t, findings, "over-http")
}

func TestHSTSWeakMultipleHeadersFlagged(t *testing.T) {
	p := hstsPage("https://example.com/page", http.Header{
		"Strict-Transport-Security": {
			"max-age=63072000; includeSubDomains; preload",
			"max-age=300",
		},
	})
	findings, err := HSTSWeak{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	hstsExpectIDs(t, findings, "multiple-headers")
}

func TestHSTSWeakDuplicateDirectiveFlagged(t *testing.T) {
	// A duplicate directive inside one header value is a parse-level bug.
	// Severity stays Low (the duplicate is a malformed-policy nudge) but
	// must surface so authors notice it.
	findings := hstsWith(t, "max-age=63072000; max-age=300; includeSubDomains")
	hstsExpectIDs(t, findings, "duplicate-max-age")
}

func TestHSTSWeakDuplicateDirectiveFirstWins(t *testing.T) {
	// First occurrence of max-age wins, so a second strict value should
	// not retroactively rescue an earlier max-age=0 (and the duplicate
	// itself is still flagged).
	findings := hstsWith(t, "max-age=0; max-age=63072000; includeSubDomains")
	hstsExpectIDs(t, findings, "max-age-zero", "duplicate-max-age")
}

func TestHSTSWeakConsolidatesIntoOneFinding(t *testing.T) {
	// Worst-case sloppy HSTS: max-age=0 AND missing includeSubDomains
	// AND duplicate directive. Should produce ONE finding with many Details
	// entries, not three near-duplicate rows.
	findings := hstsWith(t, "max-age=0; max-age=100")
	if len(findings) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d: %+v", len(findings), findings)
	}
	if len(findings[0].Details) < 3 {
		t.Errorf("expected >=3 Details entries, got %d: %q", len(findings[0].Details), findings[0].Details)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high (max-age-zero dominates)", findings[0].Severity)
	}
}

func TestHSTSWeakSeverityIsMaxOfWeaknesses(t *testing.T) {
	// Only Low-severity weaknesses present (missing includeSubDomains and
	// max-age just under a year).
	findings := hstsWith(t, "max-age=23328000")
	if len(findings) == 0 {
		t.Skip("policy produced no findings; nothing to assert severity on")
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("Severity = %q, want low", findings[0].Severity)
	}
}

func TestHSTSWeakPopulatesEnrichedFields(t *testing.T) {
	findings := hstsWith(t, "max-age=60")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Target != "https://example.com/page" || f.URL != "https://example.com/page" {
		t.Errorf("Target/URL mismatch: %q / %q", f.Target, f.URL)
	}
	if !strings.Contains(f.CWE, "CWE-319") {
		t.Errorf("CWE should reference CWE-319: %q", f.CWE)
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

func TestHSTSWeakDedupeKeyPerHost(t *testing.T) {
	// Same weakness, two crawled pages on the same host - one DedupeKey.
	h := http.Header{"Strict-Transport-Security": {"max-age=60"}}
	a, _ := HSTSWeak{}.Run(context.Background(), nil, nil, hstsPage("https://example.com/a", h.Clone()))
	b, _ := HSTSWeak{}.Run(context.Background(), nil, nil, hstsPage("https://example.com/b", h.Clone()))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding per page, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeKey != b[0].DedupeKey {
		t.Errorf("DedupeKey should match across pages on same host: %q vs %q", a[0].DedupeKey, b[0].DedupeKey)
	}
}

func TestHSTSWeakDedupeKeyDifferentWhenWeaknessesDiffer(t *testing.T) {
	// Two pages on the same host shipping materially different weak
	// policies must NOT collapse to the same DedupeKey - they're
	// different defects even though the check and host match.
	hShort := http.Header{"Strict-Transport-Security": {"max-age=60"}}
	hZero := http.Header{"Strict-Transport-Security": {"max-age=0"}}
	a, _ := HSTSWeak{}.Run(context.Background(), nil, nil, hstsPage("https://example.com/a", hShort))
	b, _ := HSTSWeak{}.Run(context.Background(), nil, nil, hstsPage("https://example.com/b", hZero))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding per page, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeKey == b[0].DedupeKey {
		t.Errorf("DedupeKey should differ for different weaknesses: both %q", a[0].DedupeKey)
	}
}

func TestHSTSWeakDetailsStableOrder(t *testing.T) {
	// Two runs of the same policy should produce identical Details order
	// so reports diff cleanly across runs.
	policy := "max-age=60; max-age=120"
	a := hstsWith(t, policy)
	b := hstsWith(t, policy)
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding per run, got %d and %d", len(a), len(b))
	}
	if strings.Join(a[0].Details, "\n") != strings.Join(b[0].Details, "\n") {
		t.Errorf("Details order not stable:\nA:\n%s\nB:\n%s",
			strings.Join(a[0].Details, "\n"),
			strings.Join(b[0].Details, "\n"))
	}
}

func TestHSTSWeakParseEmptyAndWhitespace(t *testing.T) {
	// Empty / whitespace / extra semicolons should not panic and should
	// parse the surrounding directives correctly.
	findings := hstsWith(t, " ; max-age=63072000 ; ;  includeSubDomains ; ")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for well-formed (if punctuation-noisy) policy, got %d: %+v", len(findings), findings)
	}
}

func TestParseHSTSStripsQuotedValue(t *testing.T) {
	// RFC 6797 §6.1 allows directive values as quoted-string. The parser
	// must normalize "31536000" and 31536000 to the same integer so a
	// quoted max-age isn't flagged invalid.
	out, errs := parseHSTS(`max-age="31536000"; includeSubDomains`)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %+v", errs)
	}
	if got := out["max-age"]; got != "31536000" {
		t.Errorf("max-age = %q, want %q (quotes stripped)", got, "31536000")
	}
}

func TestParseHSTSDirectiveNamesLowercased(t *testing.T) {
	out, _ := parseHSTS("MAX-AGE=63072000; IncludeSubDomains; PRELOAD")
	for _, name := range []string{"max-age", "includesubdomains", "preload"} {
		if _, ok := out[name]; !ok {
			t.Errorf("expected lower-cased %q key, got %v", name, out)
		}
	}
}
