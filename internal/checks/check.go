package checks

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/page"
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
//
// Exchange, when populated, carries the structured request/response pair the
// check observed. Passive checks that only need headers can stick with
// Snippet; active checks that probe with a crafted payload should set
// Exchange so the report can show exactly what was sent and returned.
type Evidence struct {
	Method     string    `json:"method,omitempty"`
	RequestURL string    `json:"request_url,omitempty"`
	Status     int       `json:"status,omitempty"`
	Snippet    string    `json:"snippet,omitempty"`
	Exchange   *Exchange `json:"exchange,omitempty"`
}

// Exchange is a self-contained snapshot of one HTTP request/response pair
// that triggered a finding. It is safe to retain after the underlying
// *http.Response has been closed: headers are deep-copied and bodies are
// stored as strings.
//
// Bodies are captured up to the cap the recorder used; the *Truncated
// flags fire when that cap was hit so reports can call out a cut-off
// snippet rather than presenting it as a full payload.
//
// Build one with RecordExchange. Use httpclient.SnapshotRequestBody if a
// check needs to capture its outgoing request body (the body is consumed
// by the time the response returns, so a snapshot has to be taken before
// the request is sent).
type Exchange struct {
	Method                string      `json:"method,omitempty"`
	URL                   string      `json:"url,omitempty"`
	Proto                 string      `json:"proto,omitempty"`
	RequestHeaders        http.Header `json:"request_headers,omitempty"`
	RequestBody           string      `json:"request_body,omitempty"`
	RequestBodyTruncated  bool        `json:"request_body_truncated,omitempty"`
	Status                int         `json:"status,omitempty"`
	ResponseHeaders       http.Header `json:"response_headers,omitempty"`
	ResponseBody          string      `json:"response_body,omitempty"`
	ResponseBodyTruncated bool        `json:"response_body_truncated,omitempty"`
}

// RecordExchange snapshots req and resp into an Exchange. reqBody is the
// outgoing body bytes the check sent (pass nil for GET/HEAD or any request
// without a body); reqTruncated reports whether reqBody was clipped by the
// recorder. respBody is the already-read response body (typically via
// httpclient.ReadBodyCapped) and respTruncated reports whether that read
// hit its cap.
//
// req may be nil, in which case method/URL/request-headers are filled from
// resp.Request when available. resp may also be nil (e.g. a network error
// after the request was sent), in which case only the request side is
// populated. Returns nil only if both req and resp are nil.
func RecordExchange(req *http.Request, reqBody []byte, reqTruncated bool, resp *http.Response, respBody []byte, respTruncated bool) *Exchange {
	if req == nil && resp == nil {
		return nil
	}
	ex := &Exchange{}
	if req != nil {
		ex.Method = req.Method
		if req.URL != nil {
			ex.URL = req.URL.String()
		}
		ex.RequestHeaders = req.Header.Clone()
	}
	if len(reqBody) > 0 {
		ex.RequestBody = string(reqBody)
		ex.RequestBodyTruncated = reqTruncated
	}
	if resp != nil {
		ex.Status = resp.StatusCode
		ex.Proto = resp.Proto
		ex.ResponseHeaders = resp.Header.Clone()
		// Fill missing request-side fields from resp.Request - useful when
		// the caller only kept the response (e.g. client.Get returned).
		if resp.Request != nil {
			if ex.Method == "" {
				ex.Method = resp.Request.Method
			}
			if ex.URL == "" && resp.Request.URL != nil {
				ex.URL = resp.Request.URL.String()
			}
			if ex.RequestHeaders == nil {
				ex.RequestHeaders = resp.Request.Header.Clone()
			}
		}
	}
	if len(respBody) > 0 {
		ex.ResponseBody = string(respBody)
		ex.ResponseBodyTruncated = respTruncated
	}
	return ex
}

// Finding is the report-facing record of one issue at one location.
//
// Target is the scan root the user supplied. URL is where the issue was
// actually observed (which equals Target for site-wide checks, but differs
// for per-page checks discovered via crawling).
//
// DedupeKey is a stable identifier for the *issue*, not the report row -
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
	sort.Strings(keys)
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

// reporterKey carries a per-call sub-error reporter through the context that
// the scanner hands to Run. A check may swallow individual sub-probe errors
// when it can still return findings, but should call Report to leave a
// breadcrumb so a flaky host doesn't fail silently.
type reporterKey struct{}

// WithReporter attaches fn to ctx so checks running under ctx can forward
// non-fatal sub-errors. The scanner uses this to bridge per-probe failures
// into its WithErrorHandler callback. fn may be nil, in which case Report
// is a no-op.
func WithReporter(ctx context.Context, fn func(err error)) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, reporterKey{}, fn)
}

// Report forwards err to the reporter attached to ctx, if any. Use it for
// sub-failures the check chose not to surface as a fatal return error -
// e.g. one of many probes hit a network error but other probes succeeded.
// Safe to call with a nil err (no-op) or on a ctx without a reporter (no-op).
func Report(ctx context.Context, err error) {
	if err == nil {
		return
	}
	fn, _ := ctx.Value(reporterKey{}).(func(err error))
	if fn != nil {
		fn(err)
	}
}

// levelKey carries the active scan level through the context the scanner
// hands to Run. Checks may consult it to scale how invasive they are - e.g.
// a check might probe only the high-signal inputs at LevelDefault and fan
// out a full canonical sweep at LevelAggressive.
type levelKey struct{}

// WithLevel attaches lvl to ctx so checks can adjust behavior to the active
// scan level. The scanner sets this once per run; checks should treat absence
// (see LevelFrom) as "default" rather than as an error.
func WithLevel(ctx context.Context, lvl Level) context.Context {
	return context.WithValue(ctx, levelKey{}, lvl)
}

// LevelFrom returns the scan level attached to ctx, or LevelDefault if none
// was attached. A check that wants to gate aggressive behavior should compare
// against LevelAggressive directly; treating the missing case as Default
// keeps unit tests that build their own ctx working without ceremony.
func LevelFrom(ctx context.Context) Level {
	if lvl, ok := ctx.Value(levelKey{}).(Level); ok {
		return lvl
	}
	return LevelDefault
}

type Check interface {
	Name() string
	Level() Level
	// Run inspects p and returns findings.
	//
	// p is the artifact the crawler (or no-crawl feeder) already fetched
	// for this URL: status, headers, body, and any forms it found. Passive
	// checks should read these directly rather than re-fetching - on a
	// 200-page crawl with five passive checks this is roughly the
	// difference between 200 GETs and 1000. p.URL is the live URL and
	// always non-empty. p.Headers and p.Body may be nil (no fetch yet, or
	// fetch failed); checks that need them must tolerate the empty case
	// or fetch via client themselves.
	//
	// scope is the user-authorized boundary of the scan. Passive checks
	// may ignore it (they only look at p.URL, which is already in scope
	// by the time the scanner dispatches). Non-passive checks MUST
	// consult scope before probing sub-resources discovered on the page -
	// a form on /admin is only safe to fuzz if /admin is itself in scope.
	//
	// A nil scope means "no restrictions"; treat it as permissive.
	Run(ctx context.Context, client *httpclient.Client, scope *scope.Scope, p page.Page) ([]Finding, error)
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
