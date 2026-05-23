package report

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/londonmax12/hyperz/internal/checks"
)

// Baseline is a previous scan's findings, loaded for diffing against the
// current run. Keys is the diff index (DedupeKey -> finding); NoKey holds
// findings that lacked a key in the source and are therefore excluded from
// the diff (they can't be reliably matched).
type Baseline struct {
	Keys   map[string]checks.Finding
	NoKey  []checks.Finding
	Format string
}

// baselineFormats lists the report formats that round-trip cleanly enough to
// be used as a diff baseline. text/markdown/pdf are layout-oriented and not
// included; callers get a friendly error pointing them at --format json.
var baselineFormats = map[string]bool{
	"json":  true,
	"jsonl": true,
	"csv":   true,
	"sarif": true,
}

// utf8BOM is the byte order mark editors (and PowerShell's default Set-Content
// on 5.1) prepend to UTF-8 files. The standard library's JSON/CSV parsers
// don't strip it, so we have to do it ourselves to avoid a confusing
// "invalid character 'Ã¯'" error on otherwise-valid baselines.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// LoadBaseline reads path and parses it into a Baseline. Format is detected
// by file extension first, then by content sniffing the first non-whitespace
// bytes. Pass formatHint to bypass detection (empty string = autodetect).
func LoadBaseline(path, formatHint string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	data = bytes.TrimPrefix(data, utf8BOM)
	format := strings.ToLower(formatHint)
	if format == "" {
		format = detectBaselineFormat(path, data)
	}
	switch format {
	case "json":
		return parseBaselineJSON(data)
	case "jsonl", "ndjson":
		return parseBaselineJSONL(data)
	case "csv":
		return parseBaselineCSV(data)
	case "sarif":
		return parseBaselineSARIF(data)
	case "text", "markdown", "md", "pdf":
		return nil, fmt.Errorf("baseline format %q is not round-trippable; re-run the previous scan with --format json|jsonl|csv|sarif", format)
	case "":
		return nil, fmt.Errorf("could not detect baseline format; pass --baseline-format")
	default:
		return nil, fmt.Errorf("unsupported baseline format %q (supported: json, jsonl, csv, sarif)", format)
	}
}

// detectBaselineFormat picks a format from the file extension when it
// matches a known one, otherwise sniffs the leading bytes. Returns "" when
// nothing recognizable was found.
func detectBaselineFormat(path string, data []byte) string {
	switch strings.ToLower(strings.TrimPrefix(filepath.Ext(path), ".")) {
	case "json":
		// Could be plain JSON or SARIF; sniff to tell them apart.
		if looksLikeSARIF(data) {
			return "sarif"
		}
		return "json"
	case "jsonl", "ndjson":
		return "jsonl"
	case "csv":
		return "csv"
	case "sarif":
		return "sarif"
	case "pdf":
		return "pdf"
	case "md", "markdown":
		return "markdown"
	case "txt", "text":
		return "text"
	}
	// Fall back to content sniffing.
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return ""
	}
	if trimmed[0] == '{' {
		if looksLikeSARIF(trimmed) {
			return "sarif"
		}
		// A single { could be a json envelope or the first jsonl record;
		// jsonl is line-delimited so multiple newlines between objects are
		// the strongest signal. Default to json: the envelope is permissive
		// and parseBaselineJSON accepts both flat arrays and {findings: ...}.
		return "json"
	}
	if trimmed[0] == '[' {
		return "json"
	}
	// CSV: first line should be our header.
	first, _, _ := bytes.Cut(trimmed, []byte("\n"))
	if bytes.HasPrefix(bytes.TrimSpace(first), []byte("severity,check,")) {
		return "csv"
	}
	return ""
}

func looksLikeSARIF(data []byte) bool {
	// Cheap structural sniff: don't unmarshal the whole document just to
	// check the schema. SARIF docs contain both these tokens near the top.
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	return bytes.Contains(head, []byte(`"$schema"`)) || bytes.Contains(head, []byte(`"runs"`))
}

// parseBaselineJSON accepts either the {findings: [...]} envelope this tool
// emits or a bare array, so users can hand-edit a baseline if they need to.
func parseBaselineJSON(data []byte) (*Baseline, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return emptyBaseline("json"), nil
	}
	var findings []checks.Finding
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &findings); err != nil {
			return nil, fmt.Errorf("parse baseline json array: %w", err)
		}
	} else {
		var env struct {
			Findings []checks.Finding `json:"findings"`
		}
		if err := json.Unmarshal(trimmed, &env); err != nil {
			return nil, fmt.Errorf("parse baseline json envelope: %w", err)
		}
		findings = env.Findings
	}
	return indexFindings(findings, "json"), nil
}

func parseBaselineJSONL(data []byte) (*Baseline, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Findings can carry large evidence blobs; bump the default 64KB cap.
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var findings []checks.Finding
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// Tail records the streaming reporter emits carry a "type" key
		// (stacks, request_budget). Skip them.
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &probe); err == nil && probe.Type != "" {
			continue
		}
		var f checks.Finding
		if err := json.Unmarshal(line, &f); err != nil {
			return nil, fmt.Errorf("parse baseline jsonl: %w", err)
		}
		findings = append(findings, f)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read baseline jsonl: %w", err)
	}
	return indexFindings(findings, "jsonl"), nil
}

func parseBaselineCSV(data []byte) (*Baseline, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse baseline csv: %w", err)
	}
	if len(rows) == 0 {
		return emptyBaseline("csv"), nil
	}
	header := rows[0]
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(strings.ToLower(h))] = i
	}
	required := []string{"check", "target", "severity", "title", "dedupe_key"}
	for _, c := range required {
		if _, ok := col[c]; !ok {
			return nil, fmt.Errorf("baseline csv missing required column %q (header=%v)", c, header)
		}
	}
	get := func(row []string, name string) string {
		i, ok := col[name]
		if !ok || i >= len(row) {
			return ""
		}
		return row[i]
	}
	var findings []checks.Finding
	for i, row := range rows[1:] {
		if len(row) == 0 {
			continue
		}
		f := checks.Finding{
			Check:       get(row, "check"),
			Target:      get(row, "target"),
			URL:         get(row, "url"),
			Severity:    checks.Severity(get(row, "severity")),
			Title:       get(row, "title"),
			Detail:      get(row, "detail"),
			CWE:         get(row, "cwe"),
			OWASP:       get(row, "owasp"),
			Remediation: get(row, "remediation"),
			DedupeKey:   get(row, "dedupe_key"),
		}
		method := get(row, "evidence_method")
		eURL := get(row, "evidence_url")
		statusStr := get(row, "evidence_status")
		if method != "" || eURL != "" || statusStr != "" {
			ev := &checks.Evidence{Method: method, RequestURL: eURL}
			if statusStr != "" {
				if n, err := strconv.Atoi(statusStr); err == nil {
					ev.Status = n
				} else {
					return nil, fmt.Errorf("baseline csv row %d: evidence_status %q: %w", i+2, statusStr, err)
				}
			}
			f.Evidence = ev
		}
		findings = append(findings, f)
	}
	return indexFindings(findings, "csv"), nil
}

// parseBaselineSARIF reads the SARIF 2.1.0 documents this tool emits. It
// only mines the fields the diff needs (rule id, fingerprint, severity,
// URI, message), and tolerates other valid SARIF inputs that follow the
// same shape. Severity comes from properties.severity (which the emitter
// always sets) and falls back to a level-derived best-effort mapping for
// foreign SARIF inputs.
func parseBaselineSARIF(data []byte) (*Baseline, error) {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string            `json:"id"`
						Properties map[string]string `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Properties          map[string]string `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse baseline sarif: %w", err)
	}
	var findings []checks.Finding
	for _, run := range doc.Runs {
		// Index rule properties so we can fall back to per-rule CWE/OWASP
		// when a result didn't repeat them.
		ruleProps := map[string]map[string]string{}
		for _, rule := range run.Tool.Driver.Rules {
			ruleProps[rule.ID] = rule.Properties
		}
		for _, r := range run.Results {
			title, detail := splitSARIFMessage(r.Message.Text)
			sev := checks.Severity(r.Properties["severity"])
			if checks.SeverityRank(sev) < 0 {
				sev = severityFromSARIFLevel(r.Level)
			}
			uri := ""
			if len(r.Locations) > 0 {
				uri = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
			}
			f := checks.Finding{
				Check:       r.RuleID,
				URL:         uri,
				Target:      uri,
				Severity:    sev,
				Title:       title,
				Detail:      detail,
				CWE:         pickProp(r.Properties, ruleProps[r.RuleID], "cwe"),
				OWASP:       pickProp(r.Properties, ruleProps[r.RuleID], "owasp"),
				Remediation: pickProp(r.Properties, nil, "remediation"),
				DedupeKey:   r.PartialFingerprints["hyperz/v1"],
			}
			findings = append(findings, f)
		}
	}
	return indexFindings(findings, "sarif"), nil
}

// splitSARIFMessage reverses the "title - detail" join the emitter uses in
// sarifReporter.Write (see ifDetail). When the separator isn't present the
// whole message becomes the title.
func splitSARIFMessage(msg string) (title, detail string) {
	if i := strings.Index(msg, " - "); i >= 0 {
		return msg[:i], msg[i+3:]
	}
	return msg, ""
}

// severityFromSARIFLevel is the inverse of sarifLevel, used only when a
// SARIF baseline came from a tool that didn't populate
// properties.severity. The high<->critical and info<->note ambiguity is
// resolved by picking the lower bound so the diff doesn't fabricate severity
// it can't prove.
func severityFromSARIFLevel(level string) checks.Severity {
	switch strings.ToLower(level) {
	case "error":
		return checks.SeverityHigh
	case "warning":
		return checks.SeverityMedium
	case "note":
		return checks.SeverityLow
	default:
		return checks.SeverityInfo
	}
}

func pickProp(primary, fallback map[string]string, key string) string {
	if v := primary[key]; v != "" {
		return v
	}
	return fallback[key]
}

func indexFindings(findings []checks.Finding, format string) *Baseline {
	b := &Baseline{
		Keys:   make(map[string]checks.Finding, len(findings)),
		Format: format,
	}
	for _, f := range findings {
		// DiffStatus from a prior run is meaningless context for the next
		// diff - strip it so resolved/persisting labels don't leak forward.
		f.DiffStatus = ""
		if f.DedupeKey == "" {
			b.NoKey = append(b.NoKey, f)
			continue
		}
		// First-write wins: if a baseline file somehow contains duplicate
		// keys, the later entry is dropped rather than silently overwriting.
		// In practice scan output is deduped, so collisions only happen with
		// hand-edited inputs.
		if _, exists := b.Keys[f.DedupeKey]; !exists {
			b.Keys[f.DedupeKey] = f
		}
	}
	return b
}

func emptyBaseline(format string) *Baseline {
	return &Baseline{Keys: map[string]checks.Finding{}, Format: format}
}

// BaselineFormats returns the list of formats LoadBaseline accepts. Useful
// for CLI help text.
func BaselineFormats() []string {
	out := make([]string, 0, len(baselineFormats))
	for f := range baselineFormats {
		out = append(out, f)
	}
	return out
}

