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

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/fingerprint"
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
		"[high] security-headers — http://a — missing header X",
		"    details A",
		"[medium] security-headers — http://b — missing header Y",
		"[low] tls — http://c — weak cipher | pipe",
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
	// Rule dedup: 3 findings span 2 unique checks → 2 rules, sorted by ID.
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
	// Severity mapping: high→error, medium→warning, low→note.
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
			t.Errorf("%s → %q, want %q", sev, got, want)
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
		"evidence: GET http://t/page → 200",
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
		"api.example.com — server=openresty language=node (confidence=33%)",
		"example.com — server=nginx language=php cms=wordpress (confidence=50%)",
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
