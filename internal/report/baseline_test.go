package report

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
)

func baselineSample() []checks.Finding {
	return []checks.Finding{
		{Check: "security-headers", Target: "http://a", URL: "http://a", Severity: checks.SeverityHigh,
			Title: "missing CSP", DedupeKey: "k-csp"},
		{Check: "tls", Target: "http://a", URL: "http://a", Severity: checks.SeverityMedium,
			Title: "weak cipher", DedupeKey: "k-tls"},
		// One unkeyed entry: must land in NoKey and be excluded from diff.
		{Check: "server-leak", Target: "http://a", URL: "http://a", Severity: checks.SeverityLow,
			Title: "banner leak"},
	}
}

func writeTempReport(t *testing.T, format, name string, findings []checks.Finding) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	var buf bytes.Buffer
	if err := Write(&buf, format, findings); err != nil {
		t.Fatalf("Write %s: %v", format, err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

func TestLoadBaselineRoundTripsAllFormats(t *testing.T) {
	want := baselineSample()
	for _, ext := range []string{"json", "jsonl", "csv", "sarif"} {
		t.Run(ext, func(t *testing.T) {
			name := "baseline." + ext
			path := writeTempReport(t, ext, name, want)
			b, err := LoadBaseline(path, "")
			if err != nil {
				t.Fatalf("LoadBaseline: %v", err)
			}
			// Two findings have keys, one is unkeyed.
			if len(b.Keys) != 2 {
				t.Fatalf("Keys = %d, want 2", len(b.Keys))
			}
			if len(b.NoKey) != 1 {
				t.Fatalf("NoKey = %d, want 1", len(b.NoKey))
			}
			for _, key := range []string{"k-csp", "k-tls"} {
				f, ok := b.Keys[key]
				if !ok {
					t.Fatalf("missing key %q in Keys", key)
				}
				if f.Check == "" || f.Severity == "" {
					t.Errorf("key %q: lost fields: %+v", key, f)
				}
			}
		})
	}
}

func TestLoadBaselineRejectsNonRoundTripFormats(t *testing.T) {
	for _, ext := range []string{"text", "markdown", "pdf"} {
		t.Run(ext, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "baseline."+ext)
			if err := os.WriteFile(path, []byte("placeholder"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := LoadBaseline(path, "")
			if err == nil {
				t.Fatal("expected error for non-round-trip format")
			}
			if !strings.Contains(err.Error(), "round-trip") {
				t.Errorf("error should explain why: %v", err)
			}
		})
	}
}

func TestLoadBaselineFormatHintOverridesExtension(t *testing.T) {
	want := baselineSample()
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.bin")
	var buf bytes.Buffer
	if err := Write(&buf, "jsonl", want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	b, err := LoadBaseline(path, "jsonl")
	if err != nil {
		t.Fatalf("LoadBaseline with hint: %v", err)
	}
	if len(b.Keys) != 2 {
		t.Fatalf("Keys = %d, want 2", len(b.Keys))
	}
}

func TestLoadBaselineDetectsSARIFFromContent(t *testing.T) {
	want := baselineSample()
	dir := t.TempDir()
	// .json extension but SARIF content should still be parsed as SARIF.
	path := filepath.Join(dir, "baseline.json")
	var buf bytes.Buffer
	if err := Write(&buf, "sarif", want); err != nil {
		t.Fatalf("Write sarif: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := LoadBaseline(path, "")
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if b.Format != "sarif" {
		t.Errorf("Format = %q, want sarif", b.Format)
	}
}

func TestLoadBaselineSARIFPreservesSeverity(t *testing.T) {
	// SARIF maps high+critical to "error"; without the properties.severity
	// emit, both would round-trip as "high". Verify the emitter+parser pair
	// keeps them distinct.
	src := []checks.Finding{
		{Check: "x", Target: "http://t", Severity: checks.SeverityCritical, Title: "c", DedupeKey: "kc"},
		{Check: "y", Target: "http://t", Severity: checks.SeverityHigh, Title: "h", DedupeKey: "kh"},
	}
	path := writeTempReport(t, "sarif", "baseline.sarif", src)
	b, err := LoadBaseline(path, "")
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if b.Keys["kc"].Severity != checks.SeverityCritical {
		t.Errorf("critical round-trip lost: %+v", b.Keys["kc"])
	}
	if b.Keys["kh"].Severity != checks.SeverityHigh {
		t.Errorf("high round-trip lost: %+v", b.Keys["kh"])
	}
}

func TestLoadBaselineMissingFile(t *testing.T) {
	if _, err := LoadBaseline(filepath.Join(t.TempDir(), "nope.json"), ""); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadBaselineStripsUTF8BOM(t *testing.T) {
	// PowerShell 5.1's `Set-Content -Encoding utf8` prefixes a BOM; editors
	// like Notepad do too. The standard library's json/csv parsers reject
	// files that start with the BOM, so LoadBaseline must trim it.
	want := baselineSample()
	var buf bytes.Buffer
	if err := Write(&buf, "json", want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.json")
	withBOM := append([]byte{0xEF, 0xBB, 0xBF}, buf.Bytes()...)
	if err := os.WriteFile(path, withBOM, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := LoadBaseline(path, "")
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(b.Keys) != 2 {
		t.Fatalf("Keys = %d, want 2 (BOM not stripped?)", len(b.Keys))
	}
}

func TestLoadBaselineEmptyJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := LoadBaseline(path, "")
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(b.Keys) != 0 || len(b.NoKey) != 0 {
		t.Fatalf("expected empty baseline, got %d keyed / %d unkeyed", len(b.Keys), len(b.NoKey))
	}
}

func TestDiffMarksNewPersistingResolved(t *testing.T) {
	baseline := &Baseline{Keys: map[string]checks.Finding{
		"persists": {Check: "p", Severity: checks.SeverityMedium, Title: "still here", DedupeKey: "persists"},
		"gone":     {Check: "g", Severity: checks.SeverityHigh, Title: "fixed in prod", DedupeKey: "gone"},
	}}
	in := make(chan checks.Finding, 3)
	in <- checks.Finding{Check: "n", Severity: checks.SeverityHigh, Title: "new!", DedupeKey: "newkey"}
	in <- checks.Finding{Check: "p", Severity: checks.SeverityMedium, Title: "still here", DedupeKey: "persists"}
	in <- checks.Finding{Check: "u", Severity: checks.SeverityLow, Title: "no key"}
	close(in)

	counts := &DiffCounts{}
	out := Diff(in, baseline, counts)

	var got []checks.Finding
	for f := range out {
		got = append(got, f)
	}
	// Resolved entries are emitted after live findings, sorted by key.
	if len(got) != 4 {
		t.Fatalf("got %d findings, want 4 (1 new + 1 persisting + 1 unkeyed + 1 resolved)", len(got))
	}
	statuses := map[string]string{}
	for _, f := range got {
		statuses[f.Title] = f.DiffStatus
	}
	wantStatus := map[string]string{
		"new!":           DiffStatusNew,
		"still here":     DiffStatusPersisting,
		"no key":         DiffStatusNew, // unkeyed always counts as new
		"fixed in prod":  DiffStatusResolved,
	}
	for title, want := range wantStatus {
		if got := statuses[title]; got != want {
			t.Errorf("%q: status = %q, want %q", title, got, want)
		}
	}
	wantCounts := DiffCounts{New: 2, Persisting: 1, Resolved: 1}
	if *counts != wantCounts {
		t.Errorf("counts = %+v, want %+v", *counts, wantCounts)
	}
}

func TestDiffEmptyBaselineMarksAllNew(t *testing.T) {
	in := make(chan checks.Finding, 2)
	in <- checks.Finding{Title: "a", DedupeKey: "k1"}
	in <- checks.Finding{Title: "b", DedupeKey: "k2"}
	close(in)
	counts := &DiffCounts{}
	out := Diff(in, &Baseline{Keys: map[string]checks.Finding{}}, counts)
	n := 0
	for f := range out {
		n++
		if f.DiffStatus != DiffStatusNew {
			t.Errorf("status = %q, want new", f.DiffStatus)
		}
	}
	if n != 2 || counts.New != 2 || counts.Resolved != 0 {
		t.Errorf("n=%d counts=%+v", n, counts)
	}
}

func TestDiffResolvedOrderIsStable(t *testing.T) {
	baseline := &Baseline{Keys: map[string]checks.Finding{
		"k-c": {DedupeKey: "k-c", Title: "C"},
		"k-a": {DedupeKey: "k-a", Title: "A"},
		"k-b": {DedupeKey: "k-b", Title: "B"},
	}}
	in := make(chan checks.Finding)
	close(in)
	out := Diff(in, baseline, &DiffCounts{})
	var titles []string
	for f := range out {
		titles = append(titles, f.Title)
	}
	wantSorted := append([]string{}, titles...)
	sort.Strings(wantSorted)
	for i := range titles {
		if titles[i] != wantSorted[i] {
			t.Fatalf("resolved order not stable: %v", titles)
		}
	}
}

func TestTapObservesEveryFinding(t *testing.T) {
	in := make(chan checks.Finding, 3)
	in <- checks.Finding{Title: "a"}
	in <- checks.Finding{Title: "b"}
	in <- checks.Finding{Title: "c"}
	close(in)

	var seen []string
	out := Tap(in, func(f checks.Finding) { seen = append(seen, f.Title) })
	var got []string
	for f := range out {
		got = append(got, f.Title)
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("forwarded = %v, want a,b,c", got)
	}
	if strings.Join(seen, ",") != "a,b,c" {
		t.Fatalf("observed = %v, want a,b,c", seen)
	}
}

func TestReporterRendersDiffStatus(t *testing.T) {
	findings := []checks.Finding{
		{Check: "x", Target: "http://t", Severity: checks.SeverityHigh, Title: "new one",
			DedupeKey: "knew", DiffStatus: DiffStatusNew},
		{Check: "x", Target: "http://t", Severity: checks.SeverityMedium, Title: "old one",
			DedupeKey: "kold", DiffStatus: DiffStatusPersisting},
	}
	counts := &DiffCounts{New: 1, Persisting: 1, Resolved: 0}

	t.Run("text", func(t *testing.T) {
		out := writeFormatWithMeta(t, "text", findings, Metadata{Diff: counts})
		for _, want := range []string{
			"+ [high] x - http://t - new one",
			"~ [medium] x - http://t - old one",
			"diff vs baseline: 1 new, 1 persisting, 0 resolved",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("text missing %q\nfull:\n%s", want, out)
			}
		}
	})

	t.Run("markdown", func(t *testing.T) {
		out := writeFormatWithMeta(t, "markdown", findings, Metadata{Diff: counts})
		for _, want := range []string{
			"## Diff vs baseline",
			"| new | 1 |",
			"| persisting | 1 |",
			"| Status | Severity",
			"| NEW |",
			"| persisting |",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("markdown missing %q\nfull:\n%s", want, out)
			}
		}
	})

	t.Run("csv", func(t *testing.T) {
		out := writeFormatWithMeta(t, "csv", findings, Metadata{Diff: counts})
		if !strings.Contains(out, "diff_status") {
			t.Errorf("csv missing diff_status column:\n%s", out)
		}
		if !strings.Contains(out, ",new\n") || !strings.Contains(out, ",persisting\n") {
			t.Errorf("csv missing per-row diff_status values:\n%s", out)
		}
	})

	t.Run("csv-without-diff-keeps-original-header", func(t *testing.T) {
		out := writeFormatWithMeta(t, "csv", findings, Metadata{})
		if strings.Contains(out, "diff_status") {
			t.Errorf("csv added diff_status when diff was off:\n%s", out)
		}
	})

	t.Run("jsonl", func(t *testing.T) {
		out := writeFormatWithMeta(t, "jsonl", findings, Metadata{Diff: counts})
		if !strings.Contains(out, `"diff_status":"new"`) {
			t.Errorf("jsonl missing diff_status field:\n%s", out)
		}
		if !strings.Contains(out, `"type":"diff_summary"`) {
			t.Errorf("jsonl missing diff_summary tail:\n%s", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out := writeFormatWithMeta(t, "json", findings, Metadata{Diff: counts})
		for _, want := range []string{
			`"diff_status": "new"`,
			`"diff_status": "persisting"`,
			`"diff_summary"`,
			`"new": 1`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("json missing %q\nfull:\n%s", want, out)
			}
		}
	})
}

func TestSARIFEmitsSeverityProperty(t *testing.T) {
	findings := []checks.Finding{{
		Check: "x", Target: "http://t", Severity: checks.SeverityCritical, Title: "crit",
		DedupeKey: "k1",
	}}
	out := writeFormat(t, "sarif", findings)
	if !strings.Contains(out, `"severity": "critical"`) {
		t.Errorf("sarif missing properties.severity:\n%s", out)
	}
}
