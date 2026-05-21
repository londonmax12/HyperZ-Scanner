package checks

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/londonball/hyperz/internal/httpclient"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Mode classifies a check by how invasive it is.
//
// Passive checks only inspect responses to normal-looking requests; they
// don't send payloads designed to trigger vulnerabilities. They're safe to
// run against any target you're allowed to look at.
//
// Active checks send crafted probes (XSS, SQLi, traversal, etc.) and may
// be logged as attacks. Run them only against systems you have explicit
// authorization to test.
type Mode string

const (
	ModePassive Mode = "passive"
	ModeActive  Mode = "active"
)

func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModePassive:
		return ModePassive, nil
	case ModeActive:
		return ModeActive, nil
	default:
		return "", fmt.Errorf("invalid mode %q (want %q or %q)", s, ModePassive, ModeActive)
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
	Mode() Mode
	Run(ctx context.Context, client *httpclient.Client, target string) ([]Finding, error)
}

// Filter returns the subset of checks that should run for the given mode.
// Passive mode keeps only passive checks. Active mode keeps everything;
// running active probes without first making the passive observations
// would discard cheap, useful findings, so an active scan is a superset.
func Filter(all []Check, mode Mode) []Check {
	if mode == ModeActive {
		return all
	}
	out := make([]Check, 0, len(all))
	for _, c := range all {
		if c.Mode() == ModePassive {
			out = append(out, c)
		}
	}
	return out
}
