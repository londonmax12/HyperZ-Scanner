package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestFormActionInsecureName(t *testing.T) {
	if got := (FormActionInsecure{}).Name(); got != "form-action-insecure" {
		t.Fatalf("Name = %q, want form-action-insecure", got)
	}
}

func TestFormActionInsecureLevel(t *testing.T) {
	if got := (FormActionInsecure{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestFormActionInsecureFindsAbsoluteHTTP(t *testing.T) {
	body := `<html><body>
<form action="http://evil.example.com/login" method="post">
  <input type="password" name="pwd">
</form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/login",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	// Form contains a password input -> escalated to Critical.
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical (form has password field)", f.Severity)
	}
	if f.CWE != "CWE-319" {
		t.Errorf("CWE = %q, want CWE-319", f.CWE)
	}
	if !strings.Contains(f.Detail, "http://evil.example.com/login") {
		t.Errorf("Detail missing resolved action URL: %q", f.Detail)
	}
	if !strings.Contains(f.Detail, "pwd (password)") {
		t.Errorf("Detail should enumerate the password input: %q", f.Detail)
	}
}

func TestFormActionInsecureGenericFormStaysHigh(t *testing.T) {
	// A plaintext-action form without credential-shaped inputs stays at the
	// baseline High severity - the data leak is real (CSRF tokens, PII) but
	// less dramatic than leaking passwords.
	body := `<html><body>
<form action="http://api.example.com/submit" method="post">
  <input type="text" name="comment">
  <input type="hidden" name="ref">
</form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/contact",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high for non-credential form", findings[0].Severity)
	}
}

func TestFormActionInsecureCredentialNamePromotesToCritical(t *testing.T) {
	// type="text" but name matches a credential pattern - the autocomplete
	// check uses the same name-substring fallback, this check mirrors it.
	body := `<html><body>
<form action="http://payment.example.com/pay" method="post">
  <input type="text" name="cardNumber">
  <input type="text" name="cvv">
</form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/checkout",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical (cardNumber/cvv are sensitive)", findings[0].Severity)
	}
}

func TestFormActionInsecureSkipsHTTPSAction(t *testing.T) {
	body := `<html><body>
<form action="https://example.com/login"><input name="x"></form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestFormActionInsecureSkipsRelativeActionOnHTTPS(t *testing.T) {
	// Relative action inherits the page scheme; on HTTPS it's safe.
	body := `<html><body>
<form action="/login"><input name="x"></form>
<form action="submit"><input name="y"></form>
<form action=""><input name="z"></form>
<form><input name="w"></form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for relative/missing actions, got %d: %+v", len(findings), findings)
	}
}

func TestFormActionInsecureSkipsProtocolRelative(t *testing.T) {
	// //host/path inherits the page scheme; on HTTPS that resolves to HTTPS.
	body := `<html><body>
<form action="//forms.example.com/submit"><input name="x"></form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for protocol-relative action, got %d: %+v", len(findings), findings)
	}
}

func TestFormActionInsecureSkipsNonNetworkSchemes(t *testing.T) {
	body := `<html><body>
<form action="javascript:void(0)"><input name="x"></form>
<form action="mailto:foo@example.com"><input name="y"></form>
<form action="#anchor"><input name="z"></form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-network schemes, got %d: %+v", len(findings), findings)
	}
}

func TestFormActionInsecureSkippedOnHTTPPage(t *testing.T) {
	// On HTTP pages the form-action-over-HTTP issue is dominated by the page
	// itself being plaintext; other checks own that story.
	body := `<html><body>
<form action="http://example.com/submit"><input name="x"></form>
</body></html>`
	p := page.Page{
		URL:     "http://example.com/page",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on HTTP page, got %d: %+v", len(findings), findings)
	}
}

func TestFormActionInsecureCaseInsensitiveScheme(t *testing.T) {
	body := `<html><body>
<form action="HTTP://example.com/submit"><input name="x"></form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for uppercase HTTP, got %d: %+v", len(findings), findings)
	}
}

func TestFormActionInsecureSkipsNonHTMLContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"http://example.com/x"}`))
	}))
	defer srv.Close()

	// Use httpsTestClient against an HTTPS test server.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"http://example.com/x"}`))
	}))
	defer tlsSrv.Close()

	findings, err := FormActionInsecure{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(tlsSrv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-HTML response, got %d: %+v", len(findings), findings)
	}
}

func TestFormActionInsecureDedupesSameAction(t *testing.T) {
	// Same insecure action repeated -> one finding.
	body := `<html><body>
<form action="http://evil.example.com/submit"><input name="x"></form>
<form action="http://evil.example.com/submit"><input name="y"></form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (deduped), got %d: %+v", len(findings), findings)
	}
}

func TestFormActionInsecureDistinctActionsProduceDistinctFindings(t *testing.T) {
	body := `<html><body>
<form action="http://a.example.com/submit"><input name="x"></form>
<form action="http://b.example.com/submit"><input name="y"></form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	keys := map[string]struct{}{}
	for _, f := range findings {
		if _, dup := keys[f.DedupeKey]; dup {
			t.Errorf("dedupe key collision across distinct actions: %q", f.DedupeKey)
		}
		keys[f.DedupeKey] = struct{}{}
	}
}

func TestFormActionInsecurePopulatesEnrichedFields(t *testing.T) {
	body := `<html><body><form action="http://evil.example.com/submit"><input name="x"></form></body></html>`
	p := page.Page{
		URL:     "https://example.com/login",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Target != p.URL {
		t.Errorf("Target = %q, want %q", f.Target, p.URL)
	}
	if f.URL != p.URL {
		t.Errorf("URL = %q, want %q", f.URL, p.URL)
	}
	if f.OWASP == "" {
		t.Errorf("OWASP empty")
	}
	if f.Remediation == "" {
		t.Errorf("Remediation empty")
	}
	if f.DedupeKey == "" {
		t.Errorf("DedupeKey empty")
	}
	if f.Evidence == nil {
		t.Fatalf("Evidence is nil")
	}
}

func TestFormActionInsecureEmptyBody(t *testing.T) {
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(""),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty body, got %d: %+v", len(findings), findings)
	}
}

func TestFormActionInsecureSelfClosingForm(t *testing.T) {
	// Self-closing form (rare but valid XHTML) should still be picked up by
	// the tokenizer's SelfClosingTagToken handling.
	body := `<html><body><form action="http://evil.example.com/submit" /></body></html>`
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
}

func TestFormActionInsecureHonorsBaseHref(t *testing.T) {
	// A relative action="/submit" normally inherits the HTTPS page scheme.
	// A <base href="http://insecure.example.com/"> upstream changes the
	// resolution and makes the same relative action plaintext-bound.
	body := `<html><head>
<base href="http://insecure.example.com/">
</head><body>
<form action="/submit"><input type="password" name="pwd"></form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding via <base href>, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "http://insecure.example.com/submit") {
		t.Errorf("Detail should show base-resolved URL: %q", findings[0].Detail)
	}
}

func TestFormActionInsecureDetectsButtonFormaction(t *testing.T) {
	// A safe <form action="/safe"> still gets compromised if a submit
	// button inside it carries a formaction= that points off-host plaintext.
	body := `<html><body>
<form action="/safe" method="post">
  <input type="password" name="pwd">
  <button type="submit" formaction="http://evil.example.com/steal">Login</button>
</form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/login",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for button formaction override, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical (override exposes password)", f.Severity)
	}
	if !strings.Contains(f.Title, "formaction override") {
		t.Errorf("Title should call out the override: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "http://evil.example.com/steal") {
		t.Errorf("Detail missing resolved formaction URL: %q", f.Detail)
	}
}

func TestFormActionInsecureDetectsInputSubmitFormaction(t *testing.T) {
	// <input type="submit" formaction="..."> is the older alternative to
	// <button formaction>. Treated identically.
	body := `<html><body>
<form action="/safe" method="post">
  <input type="text" name="comment">
  <input type="submit" formaction="http://evil.example.com/x" value="Send">
</form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/feedback",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for input submit formaction, got %d: %+v", len(findings), findings)
	}
	// No credential field -> stays at High.
	if findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high (no credential fields)", findings[0].Severity)
	}
}

func TestFormActionInsecureNonSubmitButtonIgnored(t *testing.T) {
	// <button type="button"> is a non-submitting button. Its formaction is
	// meaningless and should not produce a finding.
	body := `<html><body>
<form action="/safe" method="post">
  <input type="password" name="pwd">
  <button type="button" formaction="http://evil.example.com/x">Click</button>
</form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/login",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (non-submit button), got %d: %+v", len(findings), findings)
	}
}

func TestFormActionInsecureGETMethodNoted(t *testing.T) {
	// GET form posting credentials over HTTP is doubly bad: not only
	// plaintext-on-wire, but the values land in the URL itself. Detail and
	// remediation should both call this out.
	body := `<html><body>
<form action="http://evil.example.com/q" method="get">
  <input type="password" name="pwd">
</form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/login",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if !strings.Contains(f.Detail, "GET") {
		t.Errorf("Detail should mention GET method: %q", f.Detail)
	}
	if !strings.Contains(f.Detail, "browser history") {
		t.Errorf("Detail should warn about URL leakage: %q", f.Detail)
	}
	if !strings.Contains(f.Remediation, "POST") {
		t.Errorf("Remediation should suggest switching to POST: %q", f.Remediation)
	}
}

func TestFormActionInsecureEnumeratesInputs(t *testing.T) {
	body := `<html><body>
<form action="http://evil.example.com/submit" method="post">
  <input type="text" name="username">
  <input type="password" name="pwd">
  <textarea name="notes"></textarea>
  <select name="country"></select>
</form>
</body></html>`
	p := page.Page{
		URL:     "https://example.com/signup",
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte(body),
	}
	findings, err := FormActionInsecure{}.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	d := findings[0].Detail
	for _, want := range []string{"username (text)", "pwd (password)", "notes (textarea)", "country (select)"} {
		if !strings.Contains(d, want) {
			t.Errorf("Detail should mention %q; got %q", want, d)
		}
	}
}
