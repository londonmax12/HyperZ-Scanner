package report

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
)

// Metadata carries scan-level context that reporters render alongside the
// finding list. It's separate from Finding because each entry describes the
// scan/host, not an individual issue.
type Metadata struct {
	// Stacks maps a host (typically "host" or "scheme://host") to the
	// fingerprint detected for it. nil/empty when fingerprinting is
	// disabled or every detection failed.
	Stacks map[string]*fingerprint.Stack
	// Budget is the scan-wide request budget the client was wired with;
	// nil when no count cap and no global RPS were configured. Reporters
	// call Snapshot at render time so the rendered counts reflect the full
	// scan, including any in-flight checks that drained budget while the
	// streaming reporters were already running.
	Budget *httpclient.Budget
	// Diff, when non-nil, signals the scan ran with a --baseline. Reporters
	// render a diff summary (and per-finding status prefixes/columns) when
	// it's populated. Counts are read after the findings channel closes;
	// the scan command updates the same struct as findings flow through the
	// Diff overlay, so the summary printed here reflects the final tally.
	Diff *DiffCounts
}

// diffStatusPrefix returns the per-finding marker the text/markdown
// reporters prepend to lines so a reader can scan for what changed at a
// glance. Returns the empty string when no diff was performed.
func diffStatusPrefix(status string) string {
	switch status {
	case DiffStatusNew:
		return "+ "
	case DiffStatusPersisting:
		return "~ "
	case DiffStatusResolved:
		return "- "
	default:
		return ""
	}
}

// diffSummaryLine renders the one-line counter footer ("2 new, 3
// persisting, 1 resolved") or the empty string when no diff was performed.
func diffSummaryLine(d *DiffCounts) string {
	if d == nil {
		return ""
	}
	return fmt.Sprintf("diff vs baseline: %d new, %d persisting, %d resolved",
		d.New, d.Persisting, d.Resolved)
}

// diffStatusBadge returns a short human label for use in markdown table
// cells and section headers. The empty string is returned for an empty
// status so the call site can fall back to the no-diff layout.
func diffStatusBadge(status string) string {
	switch status {
	case DiffStatusNew:
		return "NEW"
	case DiffStatusPersisting:
		return "persisting"
	case DiffStatusResolved:
		return "resolved"
	default:
		return ""
	}
}

// budgetSummary writes a human-friendly multi-line summary of the budget
// snapshot. Returns the empty string when meta.Budget is nil or the budget
// had no enforcement turned on (defensive against a future "registered but
// off" path).
func budgetSummary(b *httpclient.Budget) string {
	if b == nil {
		return ""
	}
	s := b.Snapshot()
	if s.Max == 0 && s.GlobalRPS == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("request budget:\n")
	if s.Max > 0 {
		fmt.Fprintf(&sb, "  requests: %d / %d", s.Requests, s.Max)
		if s.Exhausted {
			fmt.Fprintf(&sb, " (exhausted at %s)", s.ExhaustedAt.UTC().Format(time.RFC3339))
		}
		sb.WriteByte('\n')
	} else {
		fmt.Fprintf(&sb, "  requests: %d\n", s.Requests)
	}
	if s.GlobalRPS > 0 {
		fmt.Fprintf(&sb, "  global rate: %g rps\n", s.GlobalRPS)
	}
	return sb.String()
}

// Reporter consumes findings from a channel and writes them in some format.
// Streaming reporters emit as findings arrive; aggregate reporters buffer.
//
// Implementations MUST drain `in` until it closes, even on ctx cancel or a
// writer error; because the scanner sends per-check findings unconditionally
// and a non-draining reporter will deadlock the upstream pipeline. After a
// writer error the recommended pattern is to remember the first error,
// continue ranging over `in` to a no-op, and return the saved error at the end.
//
// meta is read after the findings channel closes, so it's safe for the caller
// to keep populating the underlying maps while the scan is in flight - every
// in-tree reporter touches meta only at the end.
type Reporter interface {
	Write(ctx context.Context, w io.Writer, in <-chan checks.Finding, meta Metadata) error
}

// Formats returns the names of all supported output formats.
func Formats() []string {
	return []string{"text", "json", "jsonl", "csv", "sarif", "markdown", "pdf"}
}

func New(format string) (Reporter, error) {
	switch strings.ToLower(format) {
	case "", "text":
		return textReporter{}, nil
	case "json":
		return jsonReporter{}, nil
	case "jsonl", "ndjson":
		return jsonlReporter{}, nil
	case "csv":
		return csvReporter{}, nil
	case "sarif":
		return sarifReporter{}, nil
	case "md", "markdown":
		return markdownReporter{}, nil
	case "pdf":
		return pdfReporter{}, nil
	default:
		return nil, fmt.Errorf("unknown format %q (supported: %s)", format, strings.Join(Formats(), ", "))
	}
}

// Dedupe forwards findings from in to a new channel, dropping any whose
// DedupeKey has already been seen. Findings without a DedupeKey are always
// forwarded - checks opt into dedupe by setting a key. The returned channel
// is closed when in is closed, preserving the stream contract.
func Dedupe(in <-chan checks.Finding) <-chan checks.Finding {
	out := make(chan checks.Finding, cap(in))
	go func() {
		defer close(out)
		seen := map[string]struct{}{}
		for f := range in {
			if k := f.DedupeKey; k != "" {
				if _, ok := seen[k]; ok {
					continue
				}
				seen[k] = struct{}{}
			}
			out <- f
		}
	}()
	return out
}

// ---------- text (buffered, grouped) ----------

// textGroupURLLimit caps how many affected URLs a grouped finding prints in
// the CLI text format. The rest are folded into a trailing "... and N more"
// line; pointing users at jsonl/json/csv for the full list. Without this a
// React-style flaw rendered hundreds of times across one app drowns the
// terminal in near-identical URL lines.
const textGroupURLLimit = 10

type textReporter struct{}

func (textReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding, meta Metadata) error {
	findings := drain(ctx, in)
	if len(findings) == 0 {
		if _, err := fmt.Fprintln(w, "no findings"); err != nil {
			return err
		}
	} else {
		for _, g := range sortedGroupsBySeverity(groupFindings(findings)) {
			if err := writeTextCheckGroup(w, g); err != nil {
				return err
			}
		}
	}
	if err := writeTextStacks(w, meta.Stacks); err != nil {
		return err
	}
	if s := budgetSummary(meta.Budget); s != "" {
		if _, err := fmt.Fprintln(w, "\n"+strings.TrimRight(s, "\n")); err != nil {
			return err
		}
	}
	if s := diffSummaryLine(meta.Diff); s != "" {
		if _, err := fmt.Fprintln(w, "\n"+s); err != nil {
			return err
		}
	}
	return nil
}

// sortedGroupsBySeverity returns groups in triage order (critical first,
// info last), tie-breaking on check name so the layout is stable across
// runs with the same finding set.
func sortedGroupsBySeverity(groups []checkGroup) []checkGroup {
	rank := func(s checks.Severity) int {
		for i, sev := range severityOrder {
			if sev == s {
				return i
			}
		}
		return len(severityOrder)
	}
	sort.SliceStable(groups, func(i, j int) bool {
		ri, rj := rank(groups[i].Severity), rank(groups[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return groups[i].Check < groups[j].Check
	})
	return groups
}

func writeTextStacks(w io.Writer, stacks map[string]*fingerprint.Stack) error {
	if len(stacks) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\ndetected stacks:"); err != nil {
		return err
	}
	for _, host := range sortedHosts(stacks) {
		if _, err := fmt.Fprintf(w, "  %s - %s (confidence=%.0f%%)\n",
			host, stacks[host].Summary(), stacks[host].Confidence*100); err != nil {
			return err
		}
	}
	return nil
}

// writeTextCheckGroup emits one block per (severity, check). Groups of one
// degrade to the single-finding format so existing single-instance output
// stays byte-identical. Groups of many share title/refs/fix/detail once and
// list affected URLs (truncated to textGroupURLLimit) plus one sample
// evidence, matching the same fold-many-into-one shape the PDF reporter
// uses.
func writeTextCheckGroup(w io.Writer, g checkGroup) error {
	if len(g.All) == 1 {
		return writeTextFinding(w, g.Rep)
	}
	rep := g.Rep
	n := len(g.All)
	if _, err := fmt.Fprintf(w, "%s[%s] %s - %s (%d affected URLs)\n",
		diffStatusPrefix(rep.DiffStatus), rep.Severity, rep.Check, rep.Title, n); err != nil {
		return err
	}
	if rep.Detail != "" {
		if _, err := fmt.Fprintf(w, "    %s\n", rep.Detail); err != nil {
			return err
		}
	}
	for _, item := range rep.Details {
		if item == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "      - %s\n", item); err != nil {
			return err
		}
	}
	if tags := joinNonEmpty(" ", rep.CWE, rep.OWASP); tags != "" {
		if _, err := fmt.Fprintf(w, "    refs: %s\n", tags); err != nil {
			return err
		}
	}
	if rep.Remediation != "" {
		if _, err := fmt.Fprintf(w, "    fix:  %s\n", rep.Remediation); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "    affected:"); err != nil {
		return err
	}
	limit := textGroupURLLimit
	if limit > n {
		limit = n
	}
	for i := 0; i < limit; i++ {
		f := g.All[i]
		loc := f.URL
		if loc == "" {
			loc = f.Target
		}
		if _, err := fmt.Fprintf(w, "      - %s%s\n", diffStatusPrefix(f.DiffStatus), loc); err != nil {
			return err
		}
	}
	if n > limit {
		if _, err := fmt.Fprintf(w, "      ... and %d more (use --format=jsonl for full list)\n", n-limit); err != nil {
			return err
		}
	}
	if e := rep.Evidence; e != nil && (e.Method != "" || e.Snippet != "" || e.Status != 0) {
		reqURL := e.RequestURL
		if reqURL == "" {
			if rep.URL != "" {
				reqURL = rep.URL
			} else {
				reqURL = rep.Target
			}
		}
		if _, err := fmt.Fprintf(w, "    sample evidence: %s %s -> %d\n",
			defaultStr(e.Method, "GET"), reqURL, e.Status); err != nil {
			return err
		}
	}
	return nil
}

func writeTextFinding(w io.Writer, f checks.Finding) error {
	loc := f.URL
	if loc == "" {
		loc = f.Target
	}
	if _, err := fmt.Fprintf(w, "%s[%s] %s - %s - %s\n",
		diffStatusPrefix(f.DiffStatus), f.Severity, f.Check, loc, f.Title); err != nil {
		return err
	}
	if f.Detail != "" {
		if _, err := fmt.Fprintf(w, "    %s\n", f.Detail); err != nil {
			return err
		}
	}
	for _, item := range f.Details {
		if item == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "      - %s\n", item); err != nil {
			return err
		}
	}
	if tags := joinNonEmpty(" ", f.CWE, f.OWASP); tags != "" {
		if _, err := fmt.Fprintf(w, "    refs: %s\n", tags); err != nil {
			return err
		}
	}
	if f.Remediation != "" {
		if _, err := fmt.Fprintf(w, "    fix:  %s\n", f.Remediation); err != nil {
			return err
		}
	}
	if e := f.Evidence; e != nil && (e.Method != "" || e.Snippet != "" || e.Status != 0) {
		if _, err := fmt.Fprintf(w, "    evidence: %s %s â†’ %d\n",
			defaultStr(e.Method, "GET"), defaultStr(e.RequestURL, loc), e.Status); err != nil {
			return err
		}
	}
	return nil
}

// ---------- jsonl (streaming) ----------

type jsonlReporter struct{}

func (jsonlReporter) Write(_ context.Context, w io.Writer, in <-chan checks.Finding, meta Metadata) error {
	enc := json.NewEncoder(w)
	var writeErr error
	for f := range in {
		if writeErr != nil {
			continue
		}
		if err := enc.Encode(f); err != nil {
			writeErr = err
		}
	}
	if writeErr != nil {
		return writeErr
	}
	if len(meta.Stacks) > 0 {
		// Tagged tail record so consumers can stream past findings and pick
		// up host metadata without having to buffer the whole file.
		if err := enc.Encode(map[string]any{
			"type":   "stacks",
			"stacks": meta.Stacks,
		}); err != nil {
			return err
		}
	}
	if meta.Budget != nil {
		s := meta.Budget.Snapshot()
		if s.Max > 0 || s.GlobalRPS > 0 {
			if err := enc.Encode(map[string]any{
				"type":   "request_budget",
				"budget": s,
			}); err != nil {
				return err
			}
		}
	}
	if meta.Diff != nil {
		if err := enc.Encode(map[string]any{
			"type": "diff_summary",
			"diff": meta.Diff,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ---------- csv (streaming) ----------

type csvReporter struct{}

var csvHeader = []string{
	"severity", "check", "target", "url", "title", "detail", "details",
	"cwe", "owasp", "remediation",
	"evidence_method", "evidence_url", "evidence_status",
	"dedupe_key",
}

// csv intentionally ignores most Metadata (stacks/budget): the format is
// flat tabular finding rows and there's no natural place for per-host info
// without breaking the row contract. Use jsonl/json/markdown if you need
// both. The diff_status column is appended only when meta.Diff is non-nil
// so existing tooling that locks the header order keeps working.
func (csvReporter) Write(_ context.Context, w io.Writer, in <-chan checks.Finding, meta Metadata) error {
	cw := csv.NewWriter(w)
	header := csvHeader
	withDiff := meta.Diff != nil
	if withDiff {
		header = append(append([]string{}, csvHeader...), "diff_status")
	}
	var writeErr error
	if err := cw.Write(header); err != nil {
		writeErr = err
	}
	for f := range in {
		if writeErr != nil {
			continue
		}
		var method, eURL, status string
		if e := f.Evidence; e != nil {
			method = e.Method
			eURL = e.RequestURL
			if e.Status != 0 {
				status = strconv.Itoa(e.Status)
			}
		}
		row := []string{
			string(f.Severity), f.Check, f.Target, f.URL, f.Title, f.Detail,
			strings.Join(f.Details, "; "),
			f.CWE, f.OWASP, f.Remediation,
			method, eURL, status,
			f.DedupeKey,
		}
		if withDiff {
			row = append(row, f.DiffStatus)
		}
		if err := cw.Write(row); err != nil {
			writeErr = err
		}
	}
	if writeErr != nil {
		return writeErr
	}
	cw.Flush()
	return cw.Error()
}

// ---------- json (buffered, pretty envelope) ----------

type jsonReporter struct{}

// jsonEnvelope wraps the findings array so we have a stable place to add
// scan metadata (detected stacks today, scan time/target list tomorrow)
// without piggybacking on individual finding records.
type jsonEnvelope struct {
	Findings []checks.Finding              `json:"findings"`
	Stacks   map[string]*fingerprint.Stack `json:"detected_stacks,omitempty"`
	Budget   *httpclient.BudgetStats       `json:"request_budget,omitempty"`
	Diff     *DiffCounts                   `json:"diff_summary,omitempty"`
}

func (jsonReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding, meta Metadata) error {
	findings := drain(ctx, in)
	if findings == nil {
		findings = []checks.Finding{}
	}
	env := jsonEnvelope{Findings: findings, Stacks: meta.Stacks, Diff: meta.Diff}
	if meta.Budget != nil {
		s := meta.Budget.Snapshot()
		if s.Max > 0 || s.GlobalRPS > 0 {
			env.Budget = &s
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

// ---------- sarif (buffered) ----------

type sarifReporter struct{}

func (sarifReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding, meta Metadata) error {
	findings := drain(ctx, in)

	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifArtifactLoc struct {
		URI string `json:"uri"`
	}
	type sarifPhysicalLoc struct {
		ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysicalLoc `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             sarifMessage      `json:"message"`
		Locations           []sarifLocation   `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
		Properties          map[string]string `json:"properties,omitempty"`
	}
	type sarifRule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription sarifMessage      `json:"shortDescription"`
		HelpURI          string            `json:"helpUri,omitempty"`
		Properties       map[string]string `json:"properties,omitempty"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		InformationURI string      `json:"informationUri,omitempty"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool       sarifTool      `json:"tool"`
		Results    []sarifResult  `json:"results"`
		Properties map[string]any `json:"properties,omitempty"`
	}
	type sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	rulesSeen := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		if _, ok := rulesSeen[f.Check]; !ok {
			rule := sarifRule{
				ID:               f.Check,
				Name:             f.Check,
				ShortDescription: sarifMessage{Text: f.Check},
			}
			if f.CWE != "" {
				rule.HelpURI = cweURL(f.CWE)
				rule.Properties = map[string]string{"cwe": f.CWE}
				if f.OWASP != "" {
					rule.Properties["owasp"] = f.OWASP
				}
			} else if f.OWASP != "" {
				rule.Properties = map[string]string{"owasp": f.OWASP}
			}
			rulesSeen[f.Check] = rule
		}

		loc := f.URL
		if loc == "" {
			loc = f.Target
		}
		res := sarifResult{
			RuleID:  f.Check,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Title + ifDetail(f.Detail) + sarifDetailsSuffix(f.Details)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLoc{
					ArtifactLocation: sarifArtifactLoc{URI: loc},
				},
			}},
		}
		if f.DedupeKey != "" {
			res.PartialFingerprints = map[string]string{"hyperz/v1": f.DedupeKey}
		}
		// Always emit severity as a property: SARIF's level enum collapses
		// critical+high to "error" and info to "none", so without this the
		// original severity is unrecoverable from a SARIF baseline.
		res.Properties = map[string]string{"severity": string(f.Severity)}
		if f.CWE != "" {
			res.Properties["cwe"] = f.CWE
		}
		if f.OWASP != "" {
			res.Properties["owasp"] = f.OWASP
		}
		if f.Remediation != "" {
			res.Properties["remediation"] = f.Remediation
		}
		if f.DiffStatus != "" {
			res.Properties["diffStatus"] = f.DiffStatus
		}
		results = append(results, res)
	}

	rules := make([]sarifRule, 0, len(rulesSeen))
	for _, r := range rulesSeen {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	run := sarifRun{
		Tool:    sarifTool{Driver: sarifDriver{Name: "hyperz", Rules: rules}},
		Results: results,
	}
	if len(meta.Stacks) > 0 || meta.Budget != nil {
		run.Properties = map[string]any{}
		if len(meta.Stacks) > 0 {
			run.Properties["detectedStacks"] = meta.Stacks
		}
		if meta.Budget != nil {
			s := meta.Budget.Snapshot()
			if s.Max > 0 || s.GlobalRPS > 0 {
				run.Properties["requestBudget"] = s
			}
		}
	}
	doc := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(s checks.Severity) string {
	switch s {
	case checks.SeverityCritical, checks.SeverityHigh:
		return "error"
	case checks.SeverityMedium:
		return "warning"
	case checks.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

func ifDetail(d string) string {
	if d == "" {
		return ""
	}
	return " - " + d
}

// sarifDetailsSuffix folds a per-item Details list onto the end of the SARIF
// result message so consumers that only read message text still see the
// per-item breakdown. Returns "" when the list is empty.
func sarifDetailsSuffix(details []string) string {
	if len(details) == 0 {
		return ""
	}
	var b strings.Builder
	for _, item := range details {
		if item == "" {
			continue
		}
		b.WriteString("\n  - ")
		b.WriteString(item)
	}
	return b.String()
}

// cweURL maps a "CWE-123" id to its mitre.org page so SARIF viewers can link
// out. Anything that doesn't start with "CWE-" is returned as-is.
func cweURL(cwe string) string {
	id := strings.TrimPrefix(cwe, "CWE-")
	if id == cwe {
		return ""
	}
	return "https://cwe.mitre.org/data/definitions/" + id + ".html"
}

// ---------- markdown (buffered) ----------

type markdownReporter struct{}

func (markdownReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding, meta Metadata) error {
	findings := drain(ctx, in)

	bySev := map[checks.Severity]int{}
	for _, f := range findings {
		bySev[f.Severity]++
	}
	order := []checks.Severity{
		checks.SeverityCritical,
		checks.SeverityHigh,
		checks.SeverityMedium,
		checks.SeverityLow,
		checks.SeverityInfo,
	}

	fmt.Fprintf(w, "# hyperz scan report\n\n")
	fmt.Fprintf(w, "_generated %s_\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "Total findings: **%d**\n\n", len(findings))
	if len(findings) > 0 {
		fmt.Fprintf(w, "| Severity | Count |\n|---|---|\n")
		for _, s := range order {
			if n := bySev[s]; n > 0 {
				fmt.Fprintf(w, "| %s | %d |\n", s, n)
			}
		}
		fmt.Fprintln(w)
	}

	writeMarkdownStacks(w, meta.Stacks)
	writeMarkdownBudget(w, meta.Budget)
	writeMarkdownDiff(w, meta.Diff)

	if len(findings) == 0 {
		fmt.Fprintln(w, "_No findings._")
		return nil
	}

	withDiff := meta.Diff != nil
	fmt.Fprintf(w, "## Findings\n\n")
	if withDiff {
		fmt.Fprintf(w, "| Status | Severity | Check | URL | Title | CWE | OWASP |\n|---|---|---|---|---|---|---|\n")
	} else {
		fmt.Fprintf(w, "| Severity | Check | URL | Title | CWE | OWASP |\n|---|---|---|---|---|---|\n")
	}
	for _, f := range findings {
		loc := f.URL
		if loc == "" {
			loc = f.Target
		}
		if withDiff {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s |\n",
				diffStatusBadge(f.DiffStatus),
				f.Severity, f.Check, escapePipe(loc), escapePipe(f.Title),
				escapePipe(f.CWE), escapePipe(f.OWASP))
		} else {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n",
				f.Severity, f.Check, escapePipe(loc), escapePipe(f.Title),
				escapePipe(f.CWE), escapePipe(f.OWASP))
		}
	}

	fmt.Fprintf(w, "\n## Details\n\n")
	for _, f := range findings {
		loc := f.URL
		if loc == "" {
			loc = f.Target
		}
		header := fmt.Sprintf("### [%s] %s - %s", f.Severity, f.Check, escapePipe(f.Title))
		if f.DiffStatus != "" {
			header = fmt.Sprintf("### %s [%s] %s - %s",
				diffStatusBadge(f.DiffStatus), f.Severity, f.Check, escapePipe(f.Title))
		}
		fmt.Fprintf(w, "%s\n\n", header)
		fmt.Fprintf(w, "- **URL:** %s\n", loc)
		if tags := joinNonEmpty(", ", f.CWE, f.OWASP); tags != "" {
			fmt.Fprintf(w, "- **Refs:** %s\n", tags)
		}
		if f.Detail != "" {
			fmt.Fprintf(w, "- **Detail:** %s\n", f.Detail)
		}
		if len(f.Details) > 0 {
			if f.Detail == "" {
				fmt.Fprintf(w, "- **Details:**\n")
			}
			for _, item := range f.Details {
				if item == "" {
					continue
				}
				fmt.Fprintf(w, "    - %s\n", item)
			}
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "- **Remediation:** %s\n", f.Remediation)
		}
		if e := f.Evidence; e != nil {
			fmt.Fprintf(w, "- **Evidence:** `%s %s â†’ %d`\n",
				defaultStr(e.Method, "GET"), defaultStr(e.RequestURL, loc), e.Status)
			if e.Snippet != "" {
				fmt.Fprintf(w, "\n```\n%s\n```\n", e.Snippet)
			}
			if ex := e.Exchange; ex != nil {
				if ex.RequestBody != "" {
					label := "Request body"
					if ex.RequestBodyTruncated {
						label += " (truncated)"
					}
					fmt.Fprintf(w, "\n**%s**\n\n```\n%s\n```\n", label, ex.RequestBody)
				}
				if ex.ResponseBody != "" {
					label := "Response body"
					if ex.ResponseBodyTruncated {
						label += " (truncated)"
					}
					fmt.Fprintf(w, "\n**%s**\n\n```\n%s\n```\n", label, ex.ResponseBody)
				}
			}
		}
		if f.DedupeKey != "" {
			fmt.Fprintf(w, "- **Fingerprint:** `%s`\n", f.DedupeKey)
		}
		fmt.Fprintln(w)
	}
	return nil
}

func escapePipe(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

func writeMarkdownStacks(w io.Writer, stacks map[string]*fingerprint.Stack) {
	if len(stacks) == 0 {
		return
	}
	fmt.Fprintf(w, "## Detected stacks\n\n")
	fmt.Fprintf(w, "| Host | Server | Language | Framework | CMS | CDN | WAF | Confidence |\n")
	fmt.Fprintf(w, "|---|---|---|---|---|---|---|---|\n")
	for _, host := range sortedHosts(stacks) {
		s := stacks[host]
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %.0f%% |\n",
			escapePipe(host),
			withVersion(s.Server, s.Versions["server"]),
			withVersion(s.Language, s.Versions["language"]),
			withVersion(s.Framework, s.Versions["framework"]),
			withVersion(s.CMS, s.Versions["cms"]),
			withVersion(s.CDN, s.Versions["cdn"]),
			withVersion(s.WAF, s.Versions["waf"]),
			s.Confidence*100)
	}
	fmt.Fprintln(w)
}

func writeMarkdownDiff(w io.Writer, d *DiffCounts) {
	if d == nil {
		return
	}
	fmt.Fprintf(w, "## Diff vs baseline\n\n")
	fmt.Fprintf(w, "| Status | Count |\n|---|---|\n")
	fmt.Fprintf(w, "| new | %d |\n", d.New)
	fmt.Fprintf(w, "| persisting | %d |\n", d.Persisting)
	fmt.Fprintf(w, "| resolved | %d |\n\n", d.Resolved)
}

func writeMarkdownBudget(w io.Writer, b *httpclient.Budget) {
	if b == nil {
		return
	}
	s := b.Snapshot()
	if s.Max == 0 && s.GlobalRPS == 0 {
		return
	}
	fmt.Fprintf(w, "## Request budget\n\n")
	if s.Max > 0 {
		if s.Exhausted {
			fmt.Fprintf(w, "- Requests: **%d / %d** (exhausted at %s)\n",
				s.Requests, s.Max, s.ExhaustedAt.UTC().Format(time.RFC3339))
		} else {
			fmt.Fprintf(w, "- Requests: %d / %d\n", s.Requests, s.Max)
		}
	} else {
		fmt.Fprintf(w, "- Requests: %d\n", s.Requests)
	}
	if s.GlobalRPS > 0 {
		fmt.Fprintf(w, "- Global rate: %g rps\n", s.GlobalRPS)
	}
	fmt.Fprintln(w)
}

func withVersion(id, ver string) string {
	if id == "" || ver == "" {
		return id
	}
	return id + " " + ver
}

// ---------- helpers ----------

// drain ranges in to completion. Buffered reporters call this so they have
// the full finding slice before laying out their document. It does NOT bail
// on ctx cancel: the scanner contract is that `in` will close once all
// in-flight checks have flushed (including post-cancel ones), and dropping
// findings here would defeat that guarantee. ctx is kept on the signature
// for symmetry with the Reporter interface and future cancellation needs.
func drain(_ context.Context, in <-chan checks.Finding) []checks.Finding {
	var findings []checks.Finding
	for f := range in {
		findings = append(findings, f)
	}
	return findings
}

func joinNonEmpty(sep string, parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func sortedHosts(stacks map[string]*fingerprint.Stack) []string {
	hosts := make([]string, 0, len(stacks))
	for h := range stacks {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// Write is a one-shot helper kept for the single-target slice path.
func Write(w io.Writer, format string, findings []checks.Finding) error {
	r, err := New(format)
	if err != nil {
		return err
	}
	in := make(chan checks.Finding, len(findings))
	for _, f := range findings {
		in <- f
	}
	close(in)
	return r.Write(context.Background(), w, in, Metadata{})
}
