package report

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
)

func sampleFindings() []checks.Finding {
	return []checks.Finding{
		{Check: "security-headers", Target: "http://a", Severity: checks.SeverityHigh,
			Title: "missing header X", Detail: "details A"},
		{Check: "security-headers", Target: "http://b", Severity: checks.SeverityMedium,
			Title: "missing header Y"},
		{Check: "tls", Target: "http://c", Severity: checks.SeverityLow,
			Title: "weak cipher | pipe", Detail: ""},
	}
}

func channelFrom(findings []checks.Finding) <-chan checks.Finding {
	ch := make(chan checks.Finding, len(findings))
	for _, f := range findings {
		ch <- f
	}
	close(ch)
	return ch
}

func writeFormat(t *testing.T, format string, findings []checks.Finding) string {
	t.Helper()
	return writeFormatWithMeta(t, format, findings, Metadata{})
}

func writeFormatWithMeta(t *testing.T, format string, findings []checks.Finding, meta Metadata) string {
	t.Helper()
	r, err := New(format)
	if err != nil {
		t.Fatalf("New(%q): %v", format, err)
	}
	var buf bytes.Buffer
	if err := r.Write(context.Background(), &buf, channelFrom(findings), meta); err != nil {
		t.Fatalf("Write(%q): %v", format, err)
	}
	return buf.String()
}

func sampleStacks() map[string]*fingerprint.Stack {
	return map[string]*fingerprint.Stack{
		"example.com": {Server: "nginx", Language: "php", CMS: "wordpress", Confidence: 0.5},
		"api.example.com": {Server: "openresty", Language: "node", Confidence: 0.33},
	}
}

func TestNewKnownFormats(t *testing.T) {
	for _, f := range Formats() {
		if _, err := New(f); err != nil {
			t.Errorf("New(%q): %v", f, err)
		}
	}
	for _, alias := range []string{"", "TEXT", "ndjson", "MD"} {
		if _, err := New(alias); err != nil {
			t.Errorf("New(%q): %v", alias, err)
		}
	}
}

func TestNewUnknownFormat(t *testing.T) {
	if _, err := New("yaml"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestTextReporter(t *testing.T) {
	out := writeFormat(t, "text", sampleFindings())
	for _, want := range []string{
		"[high] security-headers - http://a - missing header X",
		"    details A",
		"[medium] security-headers - http://b - missing header Y",
		"[low] tls - http://c - weak cipher | pipe",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\nfull:\n%s", want, out)
		}
	}
	// Detail-less finding must NOT have an indented detail line attached.
	if strings.Contains(out, "weak cipher | pipe\n    ") {
		t.Errorf("text output emitted blank detail line:\n%s", out)
	}
}

func TestTextReporterNoFindings(t *testing.T) {
	out := writeFormat(t, "text", nil)
	if strings.TrimSpace(out) != "no findings" {
		t.Fatalf("got %q, want \"no findings\"", out)
	}
}

func TestJSONReporterEnvelope(t *testing.T) {
	out := writeFormat(t, "json", sampleFindings())
	var got jsonEnvelope
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json decode: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(got.Findings, sampleFindings()) {
		t.Fatalf("findings = %+v\nwant %+v", got.Findings, sampleFindings())
	}
	if got.Stacks != nil {
		t.Errorf("stacks should be omitted when empty, got %v", got.Stacks)
	}
}

func TestJSONReporterEmptyFindings(t *testing.T) {
	out := writeFormat(t, "json", nil)
	var got jsonEnvelope
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if len(got.Findings) != 0 {
		t.Fatalf("findings = %v, want empty slice", got.Findings)
	}
	if !strings.Contains(out, `"findings": []`) {
		t.Errorf("empty findings should serialize as [] not null:\n%s", out)
	}
}

func TestJSONReporterIncludesStacks(t *testing.T) {
	out := writeFormatWithMeta(t, "json", sampleFindings(), Metadata{Stacks: sampleStacks()})
	var got jsonEnvelope
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if len(got.Stacks) != 2 {
		t.Fatalf("stacks = %d, want 2", len(got.Stacks))
	}
	if s := got.Stacks["example.com"]; s == nil || s.CMS != "wordpress" {
		t.Errorf("example.com stack = %+v", s)
	}
}

func TestJSONLReporterEmitsOnePerLine(t *testing.T) {
	out := writeFormat(t, "jsonl", sampleFindings())
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), out)
	}
	for i, line := range lines {
		var f checks.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("line %d: %v\n%s", i, err, line)
		}
	}
}

func TestCSVReporterIncludesHeader(t *testing.T) {
	out := writeFormat(t, "csv", sampleFindings())
	r := csv.NewReader(strings.NewReader(out))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d rows (incl. header), want 4", len(rows))
	}
	if !reflect.DeepEqual(rows[0], csvHeader) {
		t.Fatalf("header = %v, want %v", rows[0], csvHeader)
	}
	if rows[1][0] != "high" || rows[1][1] != "security-headers" || rows[1][2] != "http://a" {
		t.Fatalf("row 1 = %v", rows[1])
	}
}

func TestSARIFReporterShape(t *testing.T) {
	out := writeFormat(t, "sarif", sampleFindings())
	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("sarif decode: %v\n%s", err, out)
	}
	if doc.Version != "2.1.0" || doc.Schema == "" {
		t.Fatalf("version/schema = %q/%q", doc.Version, doc.Schema)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "hyperz" {
		t.Fatalf("driver name = %q", run.Tool.Driver.Name)
	}
	// Rule dedup: 3 findings span 2 unique checks â†’ 2 rules, sorted by ID.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(run.Tool.Driver.Rules))
	}
	ruleIDs := []string{run.Tool.Driver.Rules[0].ID, run.Tool.Driver.Rules[1].ID}
	if !sort.StringsAreSorted(ruleIDs) {
		t.Fatalf("rules not sorted: %v", ruleIDs)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}
	// Severity mapping: highâ†’error, mediumâ†’warning, lowâ†’note.
	wantLevels := map[string]string{
		"http://a": "error",
		"http://b": "warning",
		"http://c": "note",
	}
	for _, r := range run.Results {
		uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if got := r.Level; got != wantLevels[uri] {
			t.Errorf("%s level = %q, want %q", uri, got, wantLevels[uri])
		}
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	cases := map[checks.Severity]string{
		checks.SeverityCritical: "error",
		checks.SeverityHigh:     "error",
		checks.SeverityMedium:   "warning",
		checks.SeverityLow:      "note",
		checks.SeverityInfo:     "none",
		"weird":                 "none",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("%s â†’ %q, want %q", sev, got, want)
		}
	}
}

func TestMarkdownReporter(t *testing.T) {
	out := writeFormat(t, "markdown", sampleFindings())
	for _, want := range []string{
		"# hyperz scan report",
		"Total findings: **3**",
		"| Severity | Count |",
		"| high | 1 |",
		"| medium | 1 |",
		"| low | 1 |",
		"## Findings",
		`weak cipher \| pipe`, // pipe escaped
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\nfull:\n%s", want, out)
		}
	}
}

func TestMarkdownReporterEmpty(t *testing.T) {
	out := writeFormat(t, "markdown", nil)
	if !strings.Contains(out, "Total findings: **0**") {
		t.Errorf("expected zero count:\n%s", out)
	}
	if !strings.Contains(out, "_No findings._") {
		t.Errorf("expected no-findings note:\n%s", out)
	}
}

func TestWriteHelperRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "jsonl", sampleFindings()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
}

func TestWriteHelperUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "yaml", nil); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

// TestReportersDrainOnCanceledContext pins the contract that every reporter
// finishes consuming `in` even when ctx is already canceled. The scanner
// sends per-check findings unconditionally, so a reporter that bails on
// ctx.Done would (a) drop findings and (b) deadlock the upstream pipeline.
func TestReportersDrainOnCanceledContext(t *testing.T) {
	findings := sampleFindings()
	for _, format := range []string{"text", "jsonl", "csv", "json", "sarif", "markdown"} {
		t.Run(format, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			r, err := New(format)
			if err != nil {
				t.Fatalf("New(%q): %v", format, err)
			}
			var buf bytes.Buffer
			if err := r.Write(ctx, &buf, channelFrom(findings), Metadata{}); err != nil {
				t.Fatalf("Write returned %v on canceled ctx (should drain, not bail)", err)
			}
			// "missing header X" is finding[0]; the last finding's title pokes
			// at whether the reporter consumed past an early ctx.Err() check.
			for _, want := range []string{"missing header X", "weak cipher"} {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("%s missing %q - reporter dropped findings on canceled ctx", format, want)
				}
			}
		})
	}
}

func findingWithDetails() []checks.Finding {
	return []checks.Finding{{
		Check: "security-headers", Target: "http://t", URL: "http://t/p",
		Severity: checks.SeverityMedium, Title: "missing 3 security headers",
		Detail: "response from http://t/p did not include the following security headers",
		Details: []string{
			"Content-Security-Policy: Set CSP",
			"Strict-Transport-Security: Set HSTS",
			"X-Frame-Options: Set XFO",
		},
	}}
}

func TestTextReporterRendersDetailsAsBullets(t *testing.T) {
	out := writeFormat(t, "text", findingWithDetails())
	for _, want := range []string{
		"      - Content-Security-Policy: Set CSP",
		"      - Strict-Transport-Security: Set HSTS",
		"      - X-Frame-Options: Set XFO",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text missing bullet %q\nfull:\n%s", want, out)
		}
	}
}

func TestMarkdownReporterRendersDetailsAsBullets(t *testing.T) {
	out := writeFormat(t, "markdown", findingWithDetails())
	for _, want := range []string{
		"- **Detail:** response from http://t/p",
		"    - Content-Security-Policy: Set CSP",
		"    - Strict-Transport-Security: Set HSTS",
		"    - X-Frame-Options: Set XFO",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\nfull:\n%s", want, out)
		}
	}
}

func TestPDFReporterRendersDetailsAsBullets(t *testing.T) {
	out := writeFormat(t, "pdf", findingWithDetails())
	for _, want := range []string{
		"- Content-Security-Policy: Set CSP",
		"- Strict-Transport-Security: Set HSTS",
		"- X-Frame-Options: Set XFO",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("PDF missing %q", want)
		}
	}
}

func TestJSONReporterRoundTripsDetails(t *testing.T) {
	out := writeFormat(t, "json", findingWithDetails())
	var got jsonEnvelope
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(got.Findings))
	}
	want := []string{
		"Content-Security-Policy: Set CSP",
		"Strict-Transport-Security: Set HSTS",
		"X-Frame-Options: Set XFO",
	}
	if !reflect.DeepEqual(got.Findings[0].Details, want) {
		t.Errorf("Details = %v, want %v", got.Findings[0].Details, want)
	}
}

func TestCSVRendersDetailsColumn(t *testing.T) {
	out := writeFormat(t, "csv", findingWithDetails())
	r := csv.NewReader(strings.NewReader(out))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	idx := map[string]int{}
	for i, h := range rows[0] {
		idx[h] = i
	}
	i, ok := idx["details"]
	if !ok {
		t.Fatalf("CSV missing 'details' column (header=%v)", rows[0])
	}
	want := "Content-Security-Policy: Set CSP; Strict-Transport-Security: Set HSTS; X-Frame-Options: Set XFO"
	if rows[1][i] != want {
		t.Errorf("details col = %q, want %q", rows[1][i], want)
	}
}

func TestEscapePipe(t *testing.T) {
	if got := escapePipe("a|b|c"); got != `a\|b\|c` {
		t.Fatalf("escapePipe = %q", got)
	}
}

func TestPDFReporterStructure(t *testing.T) {
	out := writeFormat(t, "pdf", sampleFindings())
	if !strings.HasPrefix(out, "%PDF-1.") {
		head := out
		if len(head) > 16 {
			head = head[:16]
		}
		t.Fatalf("missing PDF magic; first 16 bytes: %q", head)
	}
	if !strings.HasSuffix(strings.TrimRight(out, "\n"), "%%EOF") {
		t.Fatalf("missing %%%%EOF trailer")
	}
	for _, marker := range []string{
		"/Type /Catalog",
		"/Type /Pages",
		"/Type /Page ",
		"/BaseFont /Helvetica",
		"xref",
		"trailer",
		"startxref",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("PDF missing structural marker %q", marker)
		}
	}
}

func TestPDFReporterRendersFindings(t *testing.T) {
	out := writeFormat(t, "pdf", sampleFindings())
	for _, want := range []string{
		"hyperz scan report",
		"Total findings: 3",
		"[high] security-headers",
		"missing header X",
		"http://a",
		"details A",
		"[low] tls",
		// pipe is not a PDF-special character, so it survives escape unchanged
		"weak cipher | pipe",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("PDF missing text %q", want)
		}
	}
}

func TestPDFReporterEmpty(t *testing.T) {
	out := writeFormat(t, "pdf", nil)
	if !strings.HasPrefix(out, "%PDF-1.") {
		t.Fatalf("empty PDF missing magic")
	}
	if !strings.Contains(out, "Total findings: 0") {
		t.Errorf("empty PDF missing zero summary")
	}
	if !strings.Contains(out, "No findings.") {
		t.Errorf("empty PDF missing no-findings note")
	}
}

func TestPDFEscape(t *testing.T) {
	cases := map[string]string{
		"plain":          "plain",
		`a\b`:            `a\\b`,
		"a(b)c":          `a\(b\)c`,
		"tab\there":      "tab?here",
		"high \xe9 byte": "high ? byte", // non-ASCII replaced
	}
	for in, want := range cases {
		if got := pdfEscape(in); got != want {
			t.Errorf("pdfEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPDFWrap(t *testing.T) {
	if got := pdfWrap("short", 10); !reflect.DeepEqual(got, []string{"short"}) {
		t.Errorf("short: %v", got)
	}
	got := pdfWrap("the quick brown fox jumps", 10)
	for _, line := range got {
		if len(line) > 10 {
			t.Errorf("wrap overflowed: %q (len %d)", line, len(line))
		}
	}
	if strings.Join(got, " ") != "the quick brown fox jumps" {
		t.Errorf("wrap dropped content: %v", got)
	}
	// Word longer than max must be hard-split rather than emitted oversized.
	long := pdfWrap("abcdefghijklmno", 5)
	for _, line := range long {
		if len(line) > 5 {
			t.Errorf("hard-split overflowed: %q", line)
		}
	}
}

func TestDedupeDropsRepeats(t *testing.T) {
	in := make(chan checks.Finding, 5)
	in <- checks.Finding{Title: "a", DedupeKey: "k1"}
	in <- checks.Finding{Title: "a-dup", DedupeKey: "k1"}
	in <- checks.Finding{Title: "b", DedupeKey: "k2"}
	in <- checks.Finding{Title: "no-key-1"} // empty key always passes through
	in <- checks.Finding{Title: "no-key-2"}
	close(in)

	got := []string{}
	for f := range Dedupe(in) {
		got = append(got, f.Title)
	}
	want := []string{"a", "b", "no-key-1", "no-key-2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dedupe got %v, want %v", got, want)
	}
}

func TestDedupeClosesOutputWhenInputCloses(t *testing.T) {
	in := make(chan checks.Finding)
	out := Dedupe(in)
	close(in)
	if _, ok := <-out; ok {
		t.Fatal("Dedupe output must close once input closes")
	}
}

func TestTextReporterRendersNewFields(t *testing.T) {
	findings := []checks.Finding{{
		Check: "security-headers", Target: "http://t", URL: "http://t/page",
		Severity: checks.SeverityMedium, Title: "missing CSP",
		CWE: "CWE-693", OWASP: "A05:2021 Security Misconfiguration",
		Remediation: "Set Content-Security-Policy",
		Evidence: &checks.Evidence{
			Method: "GET", RequestURL: "http://t/page", Status: 200,
		},
	}}
	out := writeFormat(t, "text", findings)
	for _, want := range []string{
		"http://t/page", // URL, not Target, is the location
		"refs: CWE-693 A05:2021 Security Misconfiguration",
		"fix:  Set Content-Security-Policy",
		"evidence: GET http://t/page â†’ 200",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text missing %q\nfull:\n%s", want, out)
		}
	}
}

func TestCSVRowIncludesEvidenceAndDedupe(t *testing.T) {
	findings := []checks.Finding{{
		Check: "security-headers", Target: "http://t", URL: "http://t/p",
		Severity: checks.SeverityLow, Title: "x", CWE: "CWE-1021",
		OWASP: "A05", Remediation: "set X-Frame-Options",
		Evidence:  &checks.Evidence{Method: "GET", RequestURL: "http://t/p", Status: 200},
		DedupeKey: "abc123",
	}}
	out := writeFormat(t, "csv", findings)
	r := csv.NewReader(strings.NewReader(out))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	idx := map[string]int{}
	for i, h := range rows[0] {
		idx[h] = i
	}
	for col, want := range map[string]string{
		"url":             "http://t/p",
		"cwe":             "CWE-1021",
		"owasp":           "A05",
		"remediation":     "set X-Frame-Options",
		"evidence_method": "GET",
		"evidence_url":    "http://t/p",
		"evidence_status": "200",
		"dedupe_key":      "abc123",
	} {
		i, ok := idx[col]
		if !ok {
			t.Fatalf("CSV missing column %q (header=%v)", col, rows[0])
		}
		if rows[1][i] != want {
			t.Errorf("CSV col %q = %q, want %q", col, rows[1][i], want)
		}
	}
}

func TestSARIFIncludesCWEAndFingerprint(t *testing.T) {
	findings := []checks.Finding{{
		Check: "security-headers", Target: "http://t", URL: "http://t/p",
		Severity: checks.SeverityMedium, Title: "missing CSP",
		CWE: "CWE-693", OWASP: "A05:2021", Remediation: "set it",
		DedupeKey: "fp1",
	}}
	out := writeFormat(t, "sarif", findings)
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string            `json:"id"`
						HelpURI    string            `json:"helpUri"`
						Properties map[string]string `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Properties          map[string]string `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("sarif decode: %v\n%s", err, out)
	}
	rule := doc.Runs[0].Tool.Driver.Rules[0]
	if !strings.Contains(rule.HelpURI, "cwe.mitre.org") || !strings.Contains(rule.HelpURI, "693") {
		t.Errorf("rule HelpURI = %q, want cwe.mitre.org/.../693", rule.HelpURI)
	}
	if rule.Properties["cwe"] != "CWE-693" {
		t.Errorf("rule props cwe = %q", rule.Properties["cwe"])
	}
	if rule.Properties["owasp"] != "A05:2021" {
		t.Errorf("rule props owasp = %q", rule.Properties["owasp"])
	}
	res := doc.Runs[0].Results[0]
	if res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "http://t/p" {
		t.Errorf("result URI should be URL not Target: %q",
			res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if res.PartialFingerprints["hyperz/v1"] != "fp1" {
		t.Errorf("partialFingerprints = %v", res.PartialFingerprints)
	}
	if res.Properties["remediation"] != "set it" {
		t.Errorf("result remediation = %q", res.Properties["remediation"])
	}
}

func TestTextReporterRendersStacks(t *testing.T) {
	out := writeFormatWithMeta(t, "text", sampleFindings(), Metadata{Stacks: sampleStacks()})
	for _, want := range []string{
		"detected stacks:",
		"api.example.com - server=openresty language=node (confidence=33%)",
		"example.com - server=nginx language=php cms=wordpress (confidence=50%)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text missing %q\nfull:\n%s", want, out)
		}
	}
}

func TestJSONLReporterTailsStacks(t *testing.T) {
	out := writeFormatWithMeta(t, "jsonl", sampleFindings(), Metadata{Stacks: sampleStacks()})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines (3 findings + 1 stacks tail), want 4:\n%s", len(lines), out)
	}
	var tail struct {
		Type   string                        `json:"type"`
		Stacks map[string]*fingerprint.Stack `json:"stacks"`
	}
	if err := json.Unmarshal([]byte(lines[3]), &tail); err != nil {
		t.Fatalf("decode tail: %v\n%s", err, lines[3])
	}
	if tail.Type != "stacks" {
		t.Errorf("tail type = %q, want 'stacks'", tail.Type)
	}
	if tail.Stacks["example.com"].CMS != "wordpress" {
		t.Errorf("tail stacks missing example.com CMS")
	}
}

func TestMarkdownReporterRendersStacksSection(t *testing.T) {
	out := writeFormatWithMeta(t, "markdown", sampleFindings(), Metadata{Stacks: sampleStacks()})
	for _, want := range []string{
		"## Detected stacks",
		"| Host | Server | Language",
		"| api.example.com | openresty | node",
		"| example.com | nginx | php |",
		"wordpress",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\nfull:\n%s", want, out)
		}
	}
}

func TestSARIFReporterIncludesStacks(t *testing.T) {
	out := writeFormatWithMeta(t, "sarif", sampleFindings(), Metadata{Stacks: sampleStacks()})
	var doc struct {
		Runs []struct {
			Properties struct {
				DetectedStacks map[string]struct {
					Server string `json:"server"`
					CMS    string `json:"cms"`
				} `json:"detectedStacks"`
			} `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	stacks := doc.Runs[0].Properties.DetectedStacks
	if len(stacks) != 2 {
		t.Fatalf("detectedStacks = %d, want 2:\n%s", len(stacks), out)
	}
	if stacks["example.com"].CMS != "wordpress" {
		t.Errorf("example.com CMS = %q", stacks["example.com"].CMS)
	}
}

func TestPDFReporterRendersStacksSection(t *testing.T) {
	out := writeFormatWithMeta(t, "pdf", sampleFindings(), Metadata{Stacks: sampleStacks()})
	for _, want := range []string{
		"Detected stacks",
		"example.com",
		"api.example.com",
		"server=nginx language=php cms=wordpress",
		"confidence: 50%",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("PDF missing %q", want)
		}
	}
}

// sampleStacksWithVersions extends sampleStacks with a Versions map, used
// to verify that all reporter surfaces propagate the new field.
func sampleStacksWithVersions() map[string]*fingerprint.Stack {
	return map[string]*fingerprint.Stack{
		"example.com": {
			Server:   "nginx",
			Language: "php",
			CMS:      "wordpress",
			Versions: map[string]string{
				"server":   "1.25.0",
				"language": "8.2.0",
				"cms":      "6.4.2",
			},
			Confidence: 0.5,
		},
	}
}

func TestTextReporterIncludesVersions(t *testing.T) {
	out := writeFormatWithMeta(t, "text", sampleFindings(), Metadata{Stacks: sampleStacksWithVersions()})
	want := "example.com - server=nginx/1.25.0 language=php/8.2.0 cms=wordpress/6.4.2 (confidence=50%)"
	if !strings.Contains(out, want) {
		t.Errorf("text missing %q\nfull:\n%s", want, out)
	}
}

func TestMarkdownReporterIncludesVersions(t *testing.T) {
	out := writeFormatWithMeta(t, "markdown", sampleFindings(), Metadata{Stacks: sampleStacksWithVersions()})
	// Each known identifier should be paired with its version in the table cell.
	want := "| example.com | nginx 1.25.0 | php 8.2.0 |  | wordpress 6.4.2 |"
	if !strings.Contains(out, want) {
		t.Errorf("markdown missing %q\nfull:\n%s", want, out)
	}
}

func TestPDFReporterIncludesVersions(t *testing.T) {
	out := writeFormatWithMeta(t, "pdf", sampleFindings(), Metadata{Stacks: sampleStacksWithVersions()})
	want := "server=nginx/1.25.0 language=php/8.2.0 cms=wordpress/6.4.2"
	if !strings.Contains(out, want) {
		t.Errorf("PDF missing %q", want)
	}
}

func TestJSONReporterIncludesVersionsMap(t *testing.T) {
	out := writeFormatWithMeta(t, "json", sampleFindings(), Metadata{Stacks: sampleStacksWithVersions()})
	var got jsonEnvelope
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	s := got.Stacks["example.com"]
	if s == nil {
		t.Fatalf("example.com stack missing")
	}
	if s.Versions["server"] != "1.25.0" || s.Versions["cms"] != "6.4.2" {
		t.Errorf("versions = %v, want server=1.25.0 cms=6.4.2", s.Versions)
	}
}

func TestReporterStacksOmittedWhenEmpty(t *testing.T) {
	// Empty stacks should not produce headers/sections in any format.
	for _, f := range []string{"text", "jsonl", "markdown"} {
		out := writeFormat(t, f, sampleFindings())
		for _, marker := range []string{"detected stacks", "Detected stacks"} {
			if strings.Contains(out, marker) {
				t.Errorf("%s: included %q with empty Metadata:\n%s", f, marker, out)
			}
		}
	}
}

func TestMarkdownReporterRendersExchangeBodies(t *testing.T) {
	findings := []checks.Finding{{
		Check: "active-xss", Target: "http://t", URL: "http://t/q",
		Severity: checks.SeverityHigh, Title: "reflected XSS",
		Evidence: &checks.Evidence{
			Method: "GET", RequestURL: "http://t/q?x=<script>", Status: 200,
			Exchange: &checks.Exchange{
				Method:                "GET",
				URL:                   "http://t/q?x=<script>",
				Status:                200,
				RequestBody:           "user=alice",
				RequestBodyTruncated:  true,
				ResponseBody:          "<html><script>alert(1)</script>",
				ResponseBodyTruncated: false,
			},
		},
	}}
	out := writeFormat(t, "markdown", findings)
	for _, want := range []string{
		"**Request body (truncated)**",
		"user=alice",
		"**Response body**",
		"<script>alert(1)</script>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\nfull:\n%s", want, out)
		}
	}
	// Response wasn't truncated - must not be labelled as such.
	if strings.Contains(out, "Response body (truncated)") {
		t.Errorf("markdown wrongly labelled response body as truncated:\n%s", out)
	}
}

func TestPDFReporterRendersExchangeBodies(t *testing.T) {
	findings := []checks.Finding{{
		Check: "active-sqli", Target: "http://t", URL: "http://t/q",
		Severity: checks.SeverityHigh, Title: "SQLi",
		Evidence: &checks.Evidence{
			Method: "POST", RequestURL: "http://t/q", Status: 500,
			Exchange: &checks.Exchange{
				RequestBody:           "id=1 OR 1=1",
				ResponseBody:          "syntax error near OR",
				ResponseBodyTruncated: true,
			},
		},
	}}
	out := writeFormat(t, "pdf", findings)
	for _, want := range []string{
		"request body:",
		"id=1 OR 1=1",
		// '(' and ')' are escaped in PDF content streams, so we look for the
		// raw escaped form rather than the rendered "(truncated)".
		`response body \(truncated\):`,
		"syntax error near OR",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("PDF missing %q", want)
		}
	}
}

func exhaustedBudget(t *testing.T, max int64) *httpclient.Budget {
	t.Helper()
	b := httpclient.NewBudget(max, 0, 1)
	for i := int64(0); i < max; i++ {
		if err := b.Wait(context.Background()); err != nil {
			t.Fatalf("seed wait %d: %v", i, err)
		}
	}
	// One more to trip ErrBudgetExhausted and stamp ExhaustedAt.
	_ = b.Wait(context.Background())
	return b
}

func TestTextReporterRendersBudgetExhaustion(t *testing.T) {
	out := writeFormatWithMeta(t, "text", sampleFindings(), Metadata{Budget: exhaustedBudget(t, 2)})
	for _, want := range []string{
		"request budget:",
		"requests: 2 / 2",
		"exhausted at ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\nfull:\n%s", want, out)
		}
	}
}

func TestTextReporterOmitsBudgetWhenNil(t *testing.T) {
	out := writeFormatWithMeta(t, "text", sampleFindings(), Metadata{})
	if strings.Contains(out, "request budget") {
		t.Errorf("text output included budget section when none configured:\n%s", out)
	}
}

func TestJSONReporterIncludesBudget(t *testing.T) {
	out := writeFormatWithMeta(t, "json", sampleFindings(),
		Metadata{Budget: exhaustedBudget(t, 3)})
	var got jsonEnvelope
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if got.Budget == nil {
		t.Fatalf("envelope.Budget = nil, want budget snapshot")
	}
	if got.Budget.Max != 3 || got.Budget.Requests != 3 || !got.Budget.Exhausted {
		t.Fatalf("budget = %+v, want max=3 requests=3 exhausted=true", got.Budget)
	}
}

func TestJSONReporterOmitsBudgetWhenNil(t *testing.T) {
	out := writeFormat(t, "json", sampleFindings())
	if strings.Contains(out, "request_budget") {
		t.Errorf("json envelope leaked request_budget key when no budget configured:\n%s", out)
	}
}

func TestJSONLReporterEmitsBudgetTailRecord(t *testing.T) {
	out := writeFormatWithMeta(t, "jsonl", sampleFindings(),
		Metadata{Budget: exhaustedBudget(t, 2)})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 0 {
		t.Fatal("no jsonl output")
	}
	tail := lines[len(lines)-1]
	var rec struct {
		Type   string                 `json:"type"`
		Budget map[string]interface{} `json:"budget"`
	}
	if err := json.Unmarshal([]byte(tail), &rec); err != nil {
		t.Fatalf("decode tail %q: %v", tail, err)
	}
	if rec.Type != "request_budget" {
		t.Fatalf("tail type = %q, want request_budget", rec.Type)
	}
	if rec.Budget["exhausted"] != true {
		t.Fatalf("tail budget.exhausted = %v, want true", rec.Budget["exhausted"])
	}
}

func TestMarkdownReporterRendersBudgetSection(t *testing.T) {
	out := writeFormatWithMeta(t, "markdown", sampleFindings(),
		Metadata{Budget: exhaustedBudget(t, 2)})
	for _, want := range []string{
		"## Request budget",
		"Requests: **2 / 2**",
		"exhausted at",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q\nfull:\n%s", want, out)
		}
	}
}

func TestSARIFReporterIncludesBudgetInRunProperties(t *testing.T) {
	out := writeFormatWithMeta(t, "sarif", sampleFindings(),
		Metadata{Budget: exhaustedBudget(t, 2)})
	var doc struct {
		Runs []struct {
			Properties map[string]any `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	rb, ok := doc.Runs[0].Properties["requestBudget"].(map[string]any)
	if !ok {
		t.Fatalf("run.properties.requestBudget missing or not an object: %+v", doc.Runs[0].Properties)
	}
	if rb["exhausted"] != true {
		t.Fatalf("requestBudget.exhausted = %v, want true", rb["exhausted"])
	}
}

func TestPDFReporterRendersBudgetSection(t *testing.T) {
	out := writeFormatWithMeta(t, "pdf", sampleFindings(),
		Metadata{Budget: exhaustedBudget(t, 2)})
	for _, want := range []string{
		"Request budget",
		"requests: 2 / 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("PDF stream missing %q", want)
		}
	}
}

func TestPDFReporterMultiPage(t *testing.T) {
	// Generate enough findings to force pagination.
	var many []checks.Finding
	for i := 0; i < 200; i++ {
		many = append(many, checks.Finding{
			Check: "security-headers", Target: "http://example/" + strings.Repeat("x", 3),
			Severity: checks.SeverityLow, Title: "filler row",
		})
	}
	out := writeFormat(t, "pdf", many)
	// Count /Type /Page entries (note trailing space rules out /Pages).
	pageCount := strings.Count(out, "/Type /Page ")
	if pageCount < 2 {
		t.Fatalf("expected pagination across multiple pages, got %d", pageCount)
	}
}
