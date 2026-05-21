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
	r, err := New(format)
	if err != nil {
		t.Fatalf("New(%q): %v", format, err)
	}
	var buf bytes.Buffer
	if err := r.Write(context.Background(), &buf, channelFrom(findings)); err != nil {
		t.Fatalf("Write(%q): %v", format, err)
	}
	return buf.String()
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

func TestJSONReporterEmitsArray(t *testing.T) {
	out := writeFormat(t, "json", sampleFindings())
	var got []checks.Finding
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json decode: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(got, sampleFindings()) {
		t.Fatalf("got %+v\nwant %+v", got, sampleFindings())
	}
}

func TestJSONReporterEmptyArrayNotNull(t *testing.T) {
	out := writeFormat(t, "json", nil)
	if strings.TrimSpace(out) != "[]" {
		t.Fatalf("got %q, want []", out)
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
	wantHeader := []string{"severity", "check", "target", "title", "detail"}
	if !reflect.DeepEqual(rows[0], wantHeader) {
		t.Fatalf("header = %v, want %v", rows[0], wantHeader)
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
