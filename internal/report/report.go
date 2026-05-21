package report

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
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
	return []string{"text", "json", "jsonl", "csv", "sarif", "markdown"}
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
	default:
		return nil, fmt.Errorf("unknown format %q (supported: %s)", format, strings.Join(Formats(), ", "))
	}
}

// ---------- text (streaming) ----------

type textReporter struct{}

func (textReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding) error {
	count := 0
	for f := range in {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := fmt.Fprintf(w, "[%s] %s — %s — %s\n", f.Severity, f.Check, f.Target, f.Title); err != nil {
			return err
		}
		if f.Detail != "" {
			if _, err := fmt.Fprintf(w, "    %s\n", f.Detail); err != nil {
				return err
			}
		}
		count++
	}
	if count == 0 {
		_, err := fmt.Fprintln(w, "no findings")
		return err
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

func (csvReporter) Write(ctx context.Context, w io.Writer, in <-chan checks.Finding) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"severity", "check", "target", "title", "detail"}); err != nil {
		return err
	}
	for f := range in {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := cw.Write([]string{string(f.Severity), f.Check, f.Target, f.Title, f.Detail}); err != nil {
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
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription sarifMessage `json:"shortDescription"`
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
			rulesSeen[f.Check] = sarifRule{
				ID:               f.Check,
				Name:             f.Check,
				ShortDescription: sarifMessage{Text: f.Check},
			}
		}
		results = append(results, sarifResult{
			RuleID:  f.Check,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Title + ifDetail(f.Detail)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLoc{
					ArtifactLocation: sarifArtifactLoc{URI: f.Target},
				},
			}},
		})
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
	fmt.Fprintf(w, "| Severity | Check | Target | Title |\n|---|---|---|---|\n")
	for _, f := range findings {
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n",
			f.Severity, f.Check, f.Target, escapePipe(f.Title))
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
