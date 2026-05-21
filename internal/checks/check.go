package checks

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/scope"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Level classifies a check by how invasive it is. Levels are ordered:
// running at a higher level includes every check at or below it.
//
// LevelPassive: only inspect responses to normal-looking requests. Safe to
// run against any target you're allowed to look at.
//
// LevelDefault: crafted probes (XSS, SQLi, traversal, etc.) that may be
// logged as attacks. Run only with authorization.
//
// LevelAggressive: noisy or heavy fuzzing; many requests, long wordlists,
// likely to trip rate limits or WAFs. Reserve for explicit deep scans.
//
// Constants are spaced (10/20/30) so future intermediate tiers can slot in
// without renumbering existing checks.
type Level int

const (
	LevelPassive    Level = 10
	LevelDefault    Level = 20
	LevelAggressive Level = 30
)

func (l Level) String() string {
	switch l {
	case LevelPassive:
		return "passive"
	case LevelDefault:
		return "default"
	case LevelAggressive:
		return "aggressive"
	default:
		return fmt.Sprintf("level(%d)", int(l))
	}
}

func ParseLevel(s string) (Level, error) {
	switch s {
	case "passive":
		return LevelPassive, nil
	case "default":
		return LevelDefault, nil
	case "aggressive":
		return LevelAggressive, nil
	default:
		return 0, fmt.Errorf("invalid level %q (want passive, default, or aggressive)", s)
	}
}

// Evidence captures the request/response artifact that justifies a finding.
// Snippet is a short, human-readable excerpt; request line, response status,
// a few headers, and/or a body fragment. kept small enough to fit inline in
// reports.
type Evidence struct {
	Method     string `json:"method,omitempty"`
	RequestURL string `json:"request_url,omitempty"`
	Status     int    `json:"status,omitempty"`
	Snippet    string `json:"snippet,omitempty"`
}

// Finding is the report-facing record of one issue at one location.
//
// Target is the scan root the user supplied. URL is where the issue was
// actually observed (which equals Target for site-wide checks, but differs
// for per-page checks discovered via crawling).
//
// DedupeKey is a stable identifier for the *issue*, not the report row —
// scope it as narrowly as the issue requires (per-page for XSS, per-host for
// missing security headers, etc.) so the same problem doesn't flood the
// output. See MakeDedupeKey and HostScope.
type Finding struct {
	Check       string    `json:"check"`
	Target      string    `json:"target"`
	URL         string    `json:"url,omitempty"`
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail,omitempty"`
	CWE         string    `json:"cwe,omitempty"`
	OWASP       string    `json:"owasp,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	Evidence    *Evidence `json:"evidence,omitempty"`
	DedupeKey   string    `json:"dedupe_key,omitempty"`
}

// MakeDedupeKey hashes its parts into a stable 16-char hex fingerprint. A
// 0x00 separator prevents accidental collisions when one part borrows from
// the next (e.g. "ab"|"c" vs "a"|"bc"). SHA-1's collision weakness doesn't
// matter here; there's no adversary, only deterministic grouping.
func MakeDedupeKey(parts ...string) string {
	h := sha1.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// HostScope returns "scheme://host" for use as a dedupe scope. Site-wide
// checks (headers, TLS config, cookie flags) should dedupe at this scope so
// the same misconfiguration doesn't fire once per crawled page. Returns the
// input unchanged if it can't be parsed.
func HostScope(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil || u.Host == "" {
		return rawurl
	}
	return u.Scheme + "://" + u.Host
}

// BuildEvidence produces a compact Evidence for an *http.Response-style
// observation. headers is rendered with one "Key: Value" per line; long
// values are truncated. snippet keeps total size bounded so reports don't
// balloon when a target returns large headers.
func BuildEvidence(method, reqURL string, status int, headers map[string][]string, bodyPreview string) *Evidence {
	const maxHeaderVal = 200
	var b strings.Builder
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	// Stable order without pulling sort: simple insertion sort, short list.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	for _, k := range keys {
		for _, v := range headers[k] {
			if len(v) > maxHeaderVal {
				v = v[:maxHeaderVal] + "…"
			}
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	if bodyPreview != "" {
		b.WriteByte('\n')
		b.WriteString(bodyPreview)
	}
	return &Evidence{
		Method:     method,
		RequestURL: reqURL,
		Status:     status,
		Snippet:    b.String(),
	}
}

type Check interface {
	Name() string
	Level() Level
	// Run inspects target and returns findings.
	//
	// scope is the user-authorized boundary of the scan. Passive checks may
	// ignore it (they only look at target, which is already in scope by the
	// time the scanner dispatches). Non-passive checks MUST consult scope
	// before probing sub-resources discovered on the page — a form on
	// /admin is only safe to fuzz if /admin is itself in scope.
	//
	// A nil scope means "no restrictions"; treat it as permissive.
	Run(ctx context.Context, client *httpclient.Client, scope *scope.Scope, target string) ([]Finding, error)
}

// Filter returns the subset of checks that should run at the given level.
// A scan at level N includes every check whose level is <= N; higher
// levels are supersets, so an aggressive scan never silently drops the
// cheap passive observations.
func Filter(all []Check, max Level) []Check {
	out := make([]Check, 0, len(all))
	for _, c := range all {
		if c.Level() <= max {
			out = append(out, c)
		}
	}
	return out
}
