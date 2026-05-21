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

	"github.com/londonball/hyperz/internal/checks"
)

// Reporter consumes findings from a channel and writes them in some format.
// Streaming reporters emit as findings arrive; aggregate reporters buffer.
type Reporter interface {
	Write(ctx context.Context, w io.Writer, in <-chan checks.Finding) error
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
// forwarded — checks opt into dedupe by setting a key. The returned channel
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

// ---------- text (streaming) ----------

type textReporter struct{}

func (textReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding) error {
	count := 0
	for f := range in {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := writeTextFinding(w, f); err != nil {
			return err
		}
		count++
	}
	if count == 0 {
		_, err := fmt.Fprintln(w, "no findings")
		return err
	}
	return nil
}

func writeTextFinding(w io.Writer, f checks.Finding) error {
	loc := f.URL
	if loc == "" {
		loc = f.Target
	}
	if _, err := fmt.Fprintf(w, "[%s] %s — %s — %s\n", f.Severity, f.Check, loc, f.Title); err != nil {
		return err
	}
	if f.Detail != "" {
		if _, err := fmt.Fprintf(w, "    %s\n", f.Detail); err != nil {
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
		if _, err := fmt.Fprintf(w, "    evidence: %s %s → %d\n",
			defaultStr(e.Method, "GET"), defaultStr(e.RequestURL, loc), e.Status); err != nil {
			return err
		}
	}
	return nil
}

// ---------- jsonl (streaming) ----------

type jsonlReporter struct{}

func (jsonlReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding) error {
	enc := json.NewEncoder(w)
	for f := range in {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

// ---------- csv (streaming) ----------

type csvReporter struct{}

var csvHeader = []string{
	"severity", "check", "target", "url", "title", "detail",
	"cwe", "owasp", "remediation",
	"evidence_method", "evidence_url", "evidence_status",
	"dedupe_key",
}

func (csvReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for f := range in {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var method, eURL, status string
		if e := f.Evidence; e != nil {
			method = e.Method
			eURL = e.RequestURL
			if e.Status != 0 {
				status = strconv.Itoa(e.Status)
			}
		}
		if err := cw.Write([]string{
			string(f.Severity), f.Check, f.Target, f.URL, f.Title, f.Detail,
			f.CWE, f.OWASP, f.Remediation,
			method, eURL, status,
			f.DedupeKey,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ---------- json (buffered, pretty array) ----------

type jsonReporter struct{}

func (jsonReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding) error {
	findings := drain(ctx, in)
	if findings == nil {
		findings = []checks.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// ---------- sarif (buffered) ----------

type sarifReporter struct{}

func (sarifReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding) error {
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
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
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
			Message: sarifMessage{Text: f.Title + ifDetail(f.Detail)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLoc{
					ArtifactLocation: sarifArtifactLoc{URI: loc},
				},
			}},
		}
		if f.DedupeKey != "" {
			res.PartialFingerprints = map[string]string{"hyperz/v1": f.DedupeKey}
		}
		if f.Remediation != "" || f.CWE != "" || f.OWASP != "" {
			res.Properties = map[string]string{}
			if f.CWE != "" {
				res.Properties["cwe"] = f.CWE
			}
			if f.OWASP != "" {
				res.Properties["owasp"] = f.OWASP
			}
			if f.Remediation != "" {
				res.Properties["remediation"] = f.Remediation
			}
		}
		results = append(results, res)
	}

	rules := make([]sarifRule, 0, len(rulesSeen))
	for _, r := range rulesSeen {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	doc := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "hyperz", Rules: rules}},
			Results: results,
		}},
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
	return " — " + d
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

func (markdownReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding) error {
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

	if len(findings) == 0 {
		fmt.Fprintln(w, "_No findings._")
		return nil
	}

	fmt.Fprintf(w, "## Findings\n\n")
	fmt.Fprintf(w, "| Severity | Check | URL | Title | CWE | OWASP |\n|---|---|---|---|---|---|\n")
	for _, f := range findings {
		loc := f.URL
		if loc == "" {
			loc = f.Target
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n",
			f.Severity, f.Check, escapePipe(loc), escapePipe(f.Title),
			escapePipe(f.CWE), escapePipe(f.OWASP))
	}

	fmt.Fprintf(w, "\n## Details\n\n")
	for _, f := range findings {
		loc := f.URL
		if loc == "" {
			loc = f.Target
		}
		fmt.Fprintf(w, "### [%s] %s — %s\n\n", f.Severity, f.Check, escapePipe(f.Title))
		fmt.Fprintf(w, "- **URL:** %s\n", loc)
		if tags := joinNonEmpty(", ", f.CWE, f.OWASP); tags != "" {
			fmt.Fprintf(w, "- **Refs:** %s\n", tags)
		}
		if f.Detail != "" {
			fmt.Fprintf(w, "- **Detail:** %s\n", f.Detail)
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "- **Remediation:** %s\n", f.Remediation)
		}
		if e := f.Evidence; e != nil {
			fmt.Fprintf(w, "- **Evidence:** `%s %s → %d`\n",
				defaultStr(e.Method, "GET"), defaultStr(e.RequestURL, loc), e.Status)
			if e.Snippet != "" {
				fmt.Fprintf(w, "\n```\n%s\n```\n", e.Snippet)
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

// ---------- helpers ----------

func drain(ctx context.Context, in <-chan checks.Finding) []checks.Finding {
	var findings []checks.Finding
	for {
		select {
		case <-ctx.Done():
			return findings
		case f, ok := <-in:
			if !ok {
				return findings
			}
			findings = append(findings, f)
		}
	}
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
	return r.Write(context.Background(), w, in)
}
