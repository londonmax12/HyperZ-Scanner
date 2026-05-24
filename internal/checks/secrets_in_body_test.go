package checks

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

// secretsPage builds a Page with the given body and Content-Type. The
// helper mirrors cspPage / etc. so tests stay small and readable.
func secretsPage(rawurl, contentType string, body []byte) page.Page {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return page.Page{
		URL:     rawurl,
		Status:  200,
		Headers: h,
		Body:    body,
		Fetched: true,
	}
}

func runSecrets(t *testing.T, p page.Page) []Finding {
	t.Helper()
	findings, err := SecretsInBody{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findings
}

func TestSecretsInBodyName(t *testing.T) {
	if got := (SecretsInBody{}).Name(); got != "secrets-in-body" {
		t.Fatalf("Name = %q, want secrets-in-body", got)
	}
}

func TestSecretsInBodyLevel(t *testing.T) {
	if got := (SecretsInBody{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestSecretsInBodyCleanResponseNoFinding(t *testing.T) {
	body := []byte("<html><body><h1>Welcome</h1><p>Nothing interesting here.</p></body></html>")
	if got := runSecrets(t, secretsPage("https://example.com/", "text/html", body)); len(got) != 0 {
		t.Fatalf("expected 0 findings on clean body, got %d: %+v", len(got), got)
	}
}

func TestSecretsInBodyEmptyBodyNoFinding(t *testing.T) {
	if got := runSecrets(t, secretsPage("https://example.com/", "text/html", nil)); len(got) != 0 {
		t.Fatalf("expected 0 findings on empty body, got %d", len(got))
	}
}

func TestSecretsInBodyAWSAccessKeyFlaggedCritical(t *testing.T) {
	body := []byte(`<script>var k = "AKIAIOSFODNN7EXAMPLE";</script>`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/html", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
	det := strings.Join(findings[0].Details, "\n")
	if !strings.Contains(det, "AWS access key ID") {
		t.Errorf("expected AWS label in Details:\n%s", det)
	}
	// Raw secret must NOT appear verbatim in the report.
	if strings.Contains(det, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Details leaked raw secret: %s", det)
	}
}

func TestSecretsInBodyAWSSTSKeyFlagged(t *testing.T) {
	body := []byte(`config = { aws: "ASIAY34FZKBOKMUTVV7A" };`)
	findings := runSecrets(t, secretsPage("https://example.com/", "application/javascript", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyGitHubTokenFlaggedCritical(t *testing.T) {
	// 36-char body matches the documented classic-PAT length.
	body := []byte(`{"token":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}`)
	findings := runSecrets(t, secretsPage("https://example.com/", "application/json", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
}

func TestSecretsInBodyGitHubFineGrainedPATFlagged(t *testing.T) {
	// fine-grained PAT body is exactly 82 chars after the prefix.
	pat := "github_pat_" + strings.Repeat("a", 82)
	body := []byte("pat=" + pat)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyStripeLiveKeyFlaggedCritical(t *testing.T) {
	body := []byte(`stripeKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/html", body))
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
}

func TestSecretsInBodyStripeTestKeyFlaggedMedium(t *testing.T) {
	body := []byte(`stripeKey = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/html", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium for test key", findings[0].Severity)
	}
}

func TestSecretsInBodySlackTokenFlagged(t *testing.T) {
	body := []byte(`SLACK="xoxb-1234567890-abcdefghijklmnopqrstuvwx"`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/html", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", findings[0].Severity)
	}
}

func TestSecretsInBodySlackWebhookFlagged(t *testing.T) {
	body := []byte(`url=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyGoogleAPIKeyFlagged(t *testing.T) {
	// AIza + 35 url-safe chars.
	key := "AIza" + strings.Repeat("A", 35)
	body := []byte(`<script>var k = "` + key + `";</script>`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/html", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyGCPOAuthClientSecretFlagged(t *testing.T) {
	secret := "GOCSPX-" + strings.Repeat("a", 28)
	body := []byte(`GOOGLE_OAUTH_CLIENT_SECRET="` + secret + `"`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", findings[0].Severity)
	}
	det := strings.Join(findings[0].Details, "\n")
	if !strings.Contains(det, "GCP OAuth client secret") {
		t.Errorf("expected GCP OAuth label in Details:\n%s", det)
	}
}

func TestSecretsInBodyGoogleOAuthAccessTokenFlagged(t *testing.T) {
	tok := "ya29." + strings.Repeat("a", 80)
	body := []byte(`Authorization: Bearer ` + tok)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium (short-lived OAuth bearer)", findings[0].Severity)
	}
}

func TestSecretsInBodySendGridKeyFlagged(t *testing.T) {
	key := "SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43)
	body := []byte("api=" + key)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyMailgunKeyFlagged(t *testing.T) {
	// Context guard requires a nearby "mailgun" / "mg." token to keep
	// the bare key-<32hex> shape from matching unrelated cache-key
	// formats. A real Mailgun integration has the vendor name within
	// a few dozen chars - here it's the env-var label.
	body := []byte(`MAILGUN_API_KEY=key-0123456789abcdef0123456789abcdef`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyMailgunKeyWithoutContextNotFlagged(t *testing.T) {
	// Bare key-<32hex> with no Mailgun-identifying context nearby is
	// the FP shape (build-tool cache key, content digest, etc.). Must
	// not fire so the catalogue is not noisy on bundle-heavy responses.
	body := []byte(`cache=key-0123456789abcdef0123456789abcdef`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 0 {
		t.Fatalf("bare key-<hex> without context must not fire, got %d findings: %+v", len(findings), findings)
	}
}

func TestSecretsInBodyMailgunKeyWithHostContextFlagged(t *testing.T) {
	// The Mailgun client lib typically references api.mailgun.net or
	// mg.<domain> URLs; the mg. host fragment must satisfy the
	// context check on its own.
	body := []byte(`https://api.mg.example.com/v3/messages with key-0123456789abcdef0123456789abcdef`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding with mg. host context, got %d", len(findings))
	}
}

func TestSecretsInBodyNPMTokenFlagged(t *testing.T) {
	body := []byte(`NPM_TOKEN=npm_` + strings.Repeat("a", 36))
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodySupabaseSecretKeyFlaggedCritical(t *testing.T) {
	key := "sb_secret_" + strings.Repeat("a", 40)
	body := []byte(`SUPABASE_SECRET="` + key + `"`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
	det := strings.Join(findings[0].Details, "\n")
	if !strings.Contains(det, "Supabase secret API key") {
		t.Errorf("expected Supabase label in Details:\n%s", det)
	}
}

func TestSecretsInBodySupabaseAccessTokenFlaggedCritical(t *testing.T) {
	body := []byte(`sbp=sbp_0123456789abcdef0123456789abcdef01234567`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
}

func TestSecretsInBodyJWTFlaggedMedium(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	body := []byte(`Authorization: Bearer ` + jwt)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium", findings[0].Severity)
	}
}

func TestSecretsInBodyPEMPrivateKeyFlaggedCritical(t *testing.T) {
	body := []byte(`Embedded by mistake:
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxX...
-----END RSA PRIVATE KEY-----`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
	det := strings.Join(findings[0].Details, "\n")
	if !strings.Contains(det, "(key body redacted)") {
		t.Errorf("expected PEM body redaction marker:\n%s", det)
	}
	// PEM body itself must not appear in the report.
	if strings.Contains(det, "MIIEowIBAAKCAQEAxX") {
		t.Errorf("Details leaked PEM body: %s", det)
	}
}

func TestSecretsInBodyPEMOpenSSHPrivateKeyFlagged(t *testing.T) {
	body := []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
xxx
-----END OPENSSH PRIVATE KEY-----`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyPublicKeyNotFlagged(t *testing.T) {
	// PUBLIC KEY blocks (not PRIVATE) must not trigger the PEM matcher.
	body := []byte(`-----BEGIN PUBLIC KEY-----
abc
-----END PUBLIC KEY-----`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 0 {
		t.Fatalf("PUBLIC KEY block must not fire, got %d findings", len(findings))
	}
}

func TestSecretsInBodyConsolidatesMultipleSecrets(t *testing.T) {
	body := []byte(`
		aws = "AKIAIOSFODNN7EXAMPLE"
		gh  = "ghp_` + strings.Repeat("a", 36) + `"
		gk  = "AIza` + strings.Repeat("B", 35) + `"
	`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 consolidated finding, got %d", len(findings))
	}
	if len(findings[0].Details) != 3 {
		t.Errorf("want 3 Details entries, got %d: %v", len(findings[0].Details), findings[0].Details)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical (AWS / GH dominate)", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Title, "3 distinct credentials") {
		t.Errorf("Title should report 3 credentials: %q", findings[0].Title)
	}
}

func TestSecretsInBodyDeduplicatesRepeatedSameSecret(t *testing.T) {
	// Same secret bound to a constant and referenced N times must collapse
	// to one detail entry with an occurrence count.
	body := []byte(`var K = "AKIAIOSFODNN7EXAMPLE"; use(K); use(K); use(K); console.log("AKIAIOSFODNN7EXAMPLE");`)
	findings := runSecrets(t, secretsPage("https://example.com/", "application/javascript", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if len(findings[0].Details) != 1 {
		t.Errorf("want 1 Details entry, got %d: %v", len(findings[0].Details), findings[0].Details)
	}
	if !strings.Contains(findings[0].Details[0], "occurrences") {
		t.Errorf("Detail should mention occurrence count: %q", findings[0].Details[0])
	}
}

func TestSecretsInBodyDetailsOrderedBySeverityDesc(t *testing.T) {
	// AWS (Critical) + Slack (High) + JWT (Medium) - the Critical entry
	// must come first so a reviewer sees the worst leak on the first line.
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	body := []byte(`
		` + jwt + `
		xoxb-1234567890-abcdefghijklmnopqrstuvwx
		AKIAIOSFODNN7EXAMPLE
	`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if len(findings[0].Details) != 3 {
		t.Fatalf("want 3 Details entries, got %d", len(findings[0].Details))
	}
	if !strings.HasPrefix(findings[0].Details[0], "AWS access key ID") {
		t.Errorf("first detail must be the Critical AWS hit, got %q", findings[0].Details[0])
	}
	if !strings.HasPrefix(findings[0].Details[2], "JSON Web Token") {
		t.Errorf("last detail must be the Medium JWT hit, got %q", findings[0].Details[2])
	}
}

func TestSecretsInBodySkipsBinaryContentType(t *testing.T) {
	// An AWS-looking byte sequence inside a PNG body should be skipped -
	// scanning binary blobs is noise for no signal.
	body := []byte("\x89PNG\r\n\x1a\n... AKIAIOSFODNN7EXAMPLE ...")
	findings := runSecrets(t, secretsPage("https://example.com/logo.png", "image/png", body))
	if len(findings) != 0 {
		t.Fatalf("binary content-type should be skipped, got %d findings", len(findings))
	}
}

func TestSecretsInBodyScansApplicationJSON(t *testing.T) {
	body := []byte(`{"key": "AKIAIOSFODNN7EXAMPLE"}`)
	findings := runSecrets(t, secretsPage("https://example.com/api/config", "application/json", body))
	if len(findings) != 1 {
		t.Fatalf("application/json must be scannable, got %d findings", len(findings))
	}
}

func TestSecretsInBodyScansVendorJSONSubtype(t *testing.T) {
	// application/vnd.api+json carries JSON; the +json suffix must opt in.
	body := []byte(`{"data":{"key":"AKIAIOSFODNN7EXAMPLE"}}`)
	findings := runSecrets(t, secretsPage("https://example.com/api/x", "application/vnd.api+json", body))
	if len(findings) != 1 {
		t.Fatalf("vendor +json must be scannable, got %d findings", len(findings))
	}
}

func TestSecretsInBodyScansSVG(t *testing.T) {
	// SVGs are image/svg+xml but textual; +xml must opt in so an inline
	// <script> with an embedded constant is still inspected.
	body := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>var k = "AKIAIOSFODNN7EXAMPLE";</script></svg>`)
	findings := runSecrets(t, secretsPage("https://example.com/icon.svg", "image/svg+xml", body))
	if len(findings) != 1 {
		t.Fatalf("image/svg+xml must be scannable, got %d findings", len(findings))
	}
}

func TestSecretsInBodyMissingContentTypeScans(t *testing.T) {
	// No Content-Type header at all - default to scannable.
	body := []byte(`AKIAIOSFODNN7EXAMPLE`)
	findings := runSecrets(t, secretsPage("https://example.com/", "", body))
	if len(findings) != 1 {
		t.Fatalf("missing Content-Type should default to scannable, got %d", len(findings))
	}
}

func TestSecretsInBodyRedactedValueFormat(t *testing.T) {
	body := []byte(`k=AKIAIOSFODNN7EXAMPLE`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	det := findings[0].Details[0]
	if !strings.Contains(det, "AKIA") || !strings.Contains(det, "MPLE") {
		t.Errorf("redacted form should retain prefix/suffix of secret, got %q", det)
	}
	if !strings.Contains(det, "...") {
		t.Errorf("redacted form should contain ellipsis, got %q", det)
	}
}

func TestSecretsInBodyDedupeKeySameSecretSameHost(t *testing.T) {
	// Same secret on two crawled pages of the same host should collapse
	// to one issue via the per-host dedupe key.
	body := []byte(`k=AKIAIOSFODNN7EXAMPLE`)
	a, _ := SecretsInBody{}.Run(context.Background(), nil, nil,
		secretsPage("https://example.com/a", "text/plain", body))
	b, _ := SecretsInBody{}.Run(context.Background(), nil, nil,
		secretsPage("https://example.com/b", "text/plain", body))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("want 1 finding per page, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeKey != b[0].DedupeKey {
		t.Errorf("DedupeKey should match across pages on same host: %q vs %q", a[0].DedupeKey, b[0].DedupeKey)
	}
}

func TestSecretsInBodyDedupeKeyDifferentForDifferentSecrets(t *testing.T) {
	// Two different leaked keys of the same type on the same host must
	// stay distinct findings.
	a, _ := SecretsInBody{}.Run(context.Background(), nil, nil,
		secretsPage("https://example.com/a", "text/plain", []byte(`AKIAIOSFODNN7EXAMPLE`)))
	b, _ := SecretsInBody{}.Run(context.Background(), nil, nil,
		secretsPage("https://example.com/b", "text/plain", []byte(`AKIAABCDEFGHIJKLMNOP`)))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("want 1 finding per page, got %d and %d", len(a), len(b))
	}
	if a[0].DedupeKey == b[0].DedupeKey {
		t.Errorf("DedupeKey should differ for different secrets, both %q", a[0].DedupeKey)
	}
}

func TestSecretsInBodyPopulatesEnrichedFields(t *testing.T) {
	body := []byte(`k=AKIAIOSFODNN7EXAMPLE`)
	findings := runSecrets(t, secretsPage("https://example.com/p", "text/plain", body))
	f := findings[0]
	if f.Target != "https://example.com/p" || f.URL != "https://example.com/p" {
		t.Errorf("Target/URL mismatch: %q / %q", f.Target, f.URL)
	}
	if !strings.Contains(f.CWE, "CWE-798") {
		t.Errorf("CWE should reference CWE-798: %q", f.CWE)
	}
	if f.OWASP == "" || f.Remediation == "" || f.DedupeKey == "" {
		t.Errorf("OWASP/Remediation/DedupeKey must be populated: %+v", f)
	}
	if f.Evidence == nil || f.Evidence.Method != "GET" || f.Evidence.Status != 200 {
		t.Errorf("Evidence not populated correctly: %+v", f.Evidence)
	}
}

func TestSecretsInBodyStableOrderAcrossRuns(t *testing.T) {
	body := []byte(`
		AKIAIOSFODNN7EXAMPLE
		AKIAABCDEFGHIJKLMNOP
		ghp_` + strings.Repeat("a", 36) + `
	`)
	a := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	b := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("want 1 finding per run, got %d and %d", len(a), len(b))
	}
	if strings.Join(a[0].Details, "\n") != strings.Join(b[0].Details, "\n") {
		t.Errorf("Details order not stable:\nA:\n%s\nB:\n%s",
			strings.Join(a[0].Details, "\n"),
			strings.Join(b[0].Details, "\n"))
	}
}

// Per-pattern positives for entries added when the catalogue was
// decomposed and expanded. Each test asserts the pattern fires and (for
// Critical-tier entries) that the severity carries through to the
// finding. Smoke-level coverage by design; the dedup / order / redaction
// behaviour is exercised by the older table-style tests above.

func TestSecretsInBodyDigitalOceanPATFlagged(t *testing.T) {
	tok := "dop_v1_" + strings.Repeat("a", 64)
	body := []byte("DO=" + tok)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
}

func TestSecretsInBodyGitLabPATFlagged(t *testing.T) {
	tok := "glpat-" + strings.Repeat("a", 20)
	body := []byte(`{"gitlab":"` + tok + `"}`)
	findings := runSecrets(t, secretsPage("https://example.com/", "application/json", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
}

func TestSecretsInBodyPyPITokenFlagged(t *testing.T) {
	// pypi- + AgE + >=50 url-safe chars. The AgE prefix is the macaroon
	// version byte that anchors the pattern.
	tok := "pypi-AgE" + strings.Repeat("a", 60)
	body := []byte("token=" + tok)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyStripeWebhookSecretFlagged(t *testing.T) {
	body := []byte(`whsec=whsec_` + strings.Repeat("a", 32))
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", findings[0].Severity)
	}
}

func TestSecretsInBodySquareAccessTokenFlagged(t *testing.T) {
	body := []byte(`square=sq0atp-` + strings.Repeat("a", 22))
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodySlackAppTokenFlagged(t *testing.T) {
	body := []byte(`SLACK_APP=xapp-1-A12345678-12345-` + strings.Repeat("a", 40))
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyDiscordWebhookFlagged(t *testing.T) {
	url := "https://discord.com/api/webhooks/1234567890/" + strings.Repeat("a", 68)
	body := []byte("hook=" + url)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyTelegramBotTokenFlagged(t *testing.T) {
	body := []byte("TOKEN=123456789:" + strings.Repeat("a", 35))
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyOpenAIAPIKeyFlagged(t *testing.T) {
	// sk- + 20 alphanumerics + T3BlbkFJ marker + 20 alphanumerics.
	key := "sk-" + strings.Repeat("a", 20) + "T3BlbkFJ" + strings.Repeat("b", 20)
	body := []byte(`OPENAI_API_KEY="` + key + `"`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
}

func TestSecretsInBodyOpenAIProjectKeyFlagged(t *testing.T) {
	key := "sk-proj-" + strings.Repeat("a", 50)
	body := []byte(`OPENAI_API_KEY="` + key + `"`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyAnthropicAPIKeyFlagged(t *testing.T) {
	key := "sk-ant-api03-" + strings.Repeat("a", 90)
	body := []byte(`ANTHROPIC_API_KEY="` + key + `"`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
}

func TestSecretsInBodyHuggingFaceTokenFlagged(t *testing.T) {
	tok := "hf_" + strings.Repeat("a", 34)
	body := []byte("HF=" + tok)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodySentryDSNFlagged(t *testing.T) {
	dsn := "https://" + strings.Repeat("a", 32) + "@o12345.ingest.sentry.io/67890"
	body := []byte(`SENTRY_DSN="` + dsn + `"`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium (DSN is write-only)", findings[0].Severity)
	}
}

func TestSecretsInBodySentryAuthTokenFlagged(t *testing.T) {
	tok := "sntrys_" + strings.Repeat("a", 60)
	body := []byte("AUTH=" + tok)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyNewRelicLicenseKeyFlagged(t *testing.T) {
	// 40 lowercase hex + NRAL suffix.
	key := strings.Repeat("a", 40) + "NRAL"
	body := []byte("NR_LICENSE=" + key)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyNewRelicAPIKeyFlagged(t *testing.T) {
	key := "NRAK-" + strings.Repeat("A", 27)
	body := []byte("NR_API=" + key)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyShopifyAccessTokenFlagged(t *testing.T) {
	tok := "shpat_" + strings.Repeat("a", 32)
	body := []byte("SHOPIFY=" + tok)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
}

func TestSecretsInBodyLinearAPIKeyFlagged(t *testing.T) {
	tok := "lin_api_" + strings.Repeat("a", 40)
	body := []byte("LINEAR=" + tok)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

func TestSecretsInBodyNotionIntegrationTokenFlagged(t *testing.T) {
	tok := "secret_" + strings.Repeat("a", 43)
	body := []byte("NOTION=" + tok)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

// Negative: the Twilio AccountSID-shaped SK + 32-hex pattern that the
// previous catalogue flagged must NOT fire any more. The SID alone
// isn't a credential and including it produced a category error in
// reports. This test pins the regression.
func TestSecretsInBodyBareTwilioSIDNoLongerFlagged(t *testing.T) {
	body := []byte(`sid=SK0123456789abcdef0123456789abcdef`)
	findings := runSecrets(t, secretsPage("https://example.com/", "text/plain", body))
	if len(findings) != 0 {
		t.Fatalf("Twilio SID alone must not fire, got %d findings: %+v", len(findings), findings)
	}
}

func TestIsScannableContentTypeCommonCases(t *testing.T) {
	cases := map[string]bool{
		"":                          true,
		"text/html; charset=utf-8":  true,
		"text/plain":                true,
		"application/json":          true,
		"application/javascript":    true,
		"application/ld+json":       true,
		"application/vnd.api+json":  true,
		"image/svg+xml":             true,
		"image/png":                 false,
		"image/jpeg":                false,
		"video/mp4":                 false,
		"audio/mpeg":                false,
		"font/woff2":                false,
		"application/octet-stream":  false,
		"application/pdf":           false,
		"application/zip":           false,
		"application/wasm":          false,
	}
	for ct, want := range cases {
		if got := isScannableContentType(ct); got != want {
			t.Errorf("isScannableContentType(%q) = %v, want %v", ct, got, want)
		}
	}
}
