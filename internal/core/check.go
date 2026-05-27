package core

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/londonmax12/hyperz/internal/browser"
	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/oob"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
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

// statusOf returns resp.StatusCode or 0 when resp is nil. Centralized so
// active-check probes can build Snapshot / Evidence values without each
// open-coding the nil guard at every call site.
func statusOf(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
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
	// Details, when set, expands Detail into a list of independent entries.
	// Reporters render each item as a bullet so a finding with many facets
	// (e.g. missing security headers, multiple vulnerable params) reads as a
	// list rather than one run-on paragraph. Detail may still hold a short
	// one-line lead-in; Details carries the per-item breakdown.
	Details     []string  `json:"details,omitempty"`
	CWE         string    `json:"cwe,omitempty"`
	OWASP       string    `json:"owasp,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	Evidence    *Evidence `json:"evidence,omitempty"`
	DedupeKey   string    `json:"dedupe_key,omitempty"`

	// DiffStatus is populated only when the scan was run with --baseline. It
	// classifies the finding relative to the baseline report: "new" (absent
	// from the baseline), "persisting" (also present in the baseline), or
	// "resolved" (in the baseline but no longer observed). Checks never set
	// this directly - the diff overlay annotates findings before they reach
	// the reporter.
	DiffStatus string `json:"diff_status,omitempty"`
}

// severityRank orders severities so callers can compare or threshold against
// each other (e.g. --fail-on gating, consolidating per-rule findings into the
// worst observed severity). Use SeverityRank rather than reading the map.
var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// SeverityRank returns a comparable integer for s. Unknown severities sort
// below SeverityInfo so a malformed baseline entry can't accidentally trip a
// fail-on gate.
func SeverityRank(s Severity) int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

// ParseSeverity normalizes "Medium"/"MEDIUM"/"medium" into a Severity and
// rejects anything that isn't one of the five canonical levels. Used by CLI
// flags (e.g. --fail-on) where users type names rather than the typed
// constants.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	}
	return "", fmt.Errorf("invalid severity %q (want info, low, medium, high, or critical)", s)
}

// MakeDedupeKey hashes its parts into a stable 16-char hex fingerprint. A
// 0x00 separator prevents accidental collisions when one part borrows from
// the next (e.g. "ab"|"c" vs "a"|"bc"). SHA-1's collision weakness doesn't
// matter here; there's no adversary, only deterministic grouping.
//
// Prefer MakeKey at call sites: it standardizes the (check, scope, parts)
// shape so checks don't drift on how they assemble their URL scope.
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

// Scope is the URL granularity at which MakeKey collapses findings into a
// single dedupe key. Pick the narrowest scope that still groups truly
// identical issues - per-host for site-wide misconfiguration, per-page for
// URL-specific bugs, per-input for findings that vary by parameter.
type Scope int

const (
	// ScopeHost groups per scheme://host. Use for site-wide misconfig
	// (missing security headers, weak TLS, banner leaks) where every
	// crawled page sees the same defect.
	ScopeHost Scope = iota + 1
	// ScopePage groups per scheme://host/path. Use for bugs that live at
	// a specific URL (reflected XSS on /search, SSRF on /fetch). Query
	// strings are excluded so probes that rewrite them produce stable keys.
	ScopePage
	// ScopeParam shares ScopePage's URL component but lives in its own
	// hash subspace. Use for input-surface findings (open redirect, SQLi)
	// where the same page can have multiple independently-vulnerable
	// inputs; pass the parameter identifier(s) as variadic parts so each
	// input dedupes separately.
	ScopeParam
)

func (s Scope) String() string {
	switch s {
	case ScopeHost:
		return "host"
	case ScopePage:
		return "page"
	case ScopeParam:
		return "param"
	default:
		return fmt.Sprintf("scope(%d)", int(s))
	}
}

// MakeKey wraps MakeDedupeKey with structured URL scope extraction. It
// hashes (check, scope tag, derived URL scope, parts...) so the same
// logical issue always produces the same key regardless of which check
// site assembles it.
//
// target is the URL where the finding was observed; scope picks how much
// of it is folded into the key (see the Scope constants). An unparseable
// target is used verbatim rather than collapsing every malformed input to
// the same hash. Prefer this over assembling MakeDedupeKey parts inline -
// the helper keeps the scope shape consistent across checks.
func MakeKey(check string, scope Scope, target string, parts ...string) string {
	sc := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		switch scope {
		case ScopeHost:
			sc = u.Scheme + "://" + u.Host
		case ScopePage, ScopeParam:
			path := u.EscapedPath()
			if path == "" {
				path = "/"
			}
			sc = u.Scheme + "://" + u.Host + path
		}
	}
	all := make([]string, 0, 3+len(parts))
	all = append(all, check, scope.String(), sc)
	all = append(all, parts...)
	return MakeDedupeKey(all...)
}

// HostScope returns "scheme://host" for use as a dedupe scope. Site-wide
// checks (headers, TLS config, cookie flags) should dedupe at this scope so
// the same misconfiguration doesn't fire once per crawled page. Returns the
// input unchanged if it can't be parsed.
//
// New call sites should prefer MakeKey with ScopeHost; HostScope is kept
// for callers that need the bare scope string outside a dedupe key.
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
				v = v[:maxHeaderVal] + "â€¦"
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

// discovererKey carries the active discovery sink through the context the
// scanner hands to Run. Checks that surface new scan targets (a freshly-
// found API endpoint, a page the crawler did not visit, a parameter
// surface inside an already-known URL) call Discover to fan them back
// into the worklist. Absence means no sink is wired and Discover is a
// no-op, matching the permissive contract Reporter / OOB / Browser use
// for optional dependencies.
type discovererKey struct{}

// Discoverer is the function shape the scanner installs to absorb a
// check's emitted targets. The scanner-side implementation tags Origin
// with the emitting check's name, runs the worklist's dedupe / scope /
// host-budget filter, and otherwise discards quietly. Checks emit
// liberally; the dispatcher decides what to queue.
type Discoverer func(t target.Target)

// WithDiscoverer attaches fn to ctx so checks can emit new targets
// during Run. The scanner installs a per-check Discoverer so the
// emitter's name can be tagged into Origin before the target reaches
// the worklist; checks that surface a target from a sub-source
// (e.g. an OpenAPI document) should leave Origin empty and let the
// dispatcher fill it in. fn may be nil, in which case Discover is a
// no-op.
func WithDiscoverer(ctx context.Context, fn Discoverer) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, discovererKey{}, fn)
}

// Discover forwards t to the discoverer attached to ctx. Safe to call
// when no discoverer is attached (no-op) or with a zero Target (the
// scanner-side discoverer drops empty URLs at the worklist boundary).
// The dispatcher dedupes by canonical key, enforces scope, applies the
// per-host budget, and breaks self-loops; checks should not pre-filter
// their emissions.
func Discover(ctx context.Context, t target.Target) {
	fn, _ := ctx.Value(discovererKey{}).(Discoverer)
	if fn != nil {
		fn(t)
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

// oobKey carries the active OOB callback server through the context the
// scanner hands to Run. Checks that mint canaries (blind SSRF, blind XXE,
// blind SSTI, ...) read it via OOBFrom; absence means no listener is
// configured and the check must skip its OOB paths rather than fall
// back to a default that would emit unattributable findings.
type oobKey struct{}

// WithOOB attaches srv to ctx so checks can mint canaries against a live
// listener. The scanner sets this once per run when the operator opted
// into --oob; checks should treat a nil srv (or absence) as "OOB
// disabled" and skip the OOB-only paths.
func WithOOB(ctx context.Context, srv oob.Server) context.Context {
	if srv == nil {
		return ctx
	}
	return context.WithValue(ctx, oobKey{}, srv)
}

// OOBFrom returns the oob.Server attached to ctx, or nil if none was
// attached. A check that wants to mint a canary must guard on the nil
// return - emitting OOB findings without a listener attached would
// have no callback to correlate against.
func OOBFrom(ctx context.Context) oob.Server {
	if srv, ok := ctx.Value(oobKey{}).(oob.Server); ok {
		return srv
	}
	return nil
}

// OOBCheck is implemented by checks that mint OOB canaries during Run
// and need a post-scan pass to emit findings when those canaries
// receive callbacks. Drain is called once per check after the main
// scan phase drains and the operator-configured wait window elapses;
// the implementation should query OOBFrom(ctx) for its registrations
// and return one Finding per registration whose token observed at
// least one hit.
//
// Drain runs on a scanner-owned goroutine; the check's own Run may
// have completed across many goroutines, so any state Drain reads
// must be appropriately synchronized (the server's Registrations /
// Hits methods are already safe to call). The findings flow through
// the same out channel as phase 1.
//
// Implementations must be safe alongside the value-receiver Run shape
// that the rest of the catalog uses. The recommended pattern: store
// no state on the check struct - read everything back from
// OOBFrom(ctx).Registrations(c.Name()) during Drain.
type OOBCheck interface {
	Check
	Drain(ctx context.Context) []Finding
}

// browserKey carries the active headless-browser pool through the context
// the scanner hands to Run. Checks that need runtime JS execution (dom-xss,
// future client-side prototype-pollution chains) read it via BrowserFrom;
// absence means the operator did not opt into --js and the check must
// silently skip rather than failing - a scan without --js should not
// produce dom-xss findings, but should also not log errors for every page.
type browserKey struct{}

// WithBrowser attaches pool to ctx so checks can dispatch Visit calls. The
// scanner sets this once per run when the operator opted into --js; checks
// should treat a nil pool (or absence) as "JS disabled" and skip the
// runtime-execution paths.
func WithBrowser(ctx context.Context, pool browser.Pool) context.Context {
	if pool == nil {
		return ctx
	}
	return context.WithValue(ctx, browserKey{}, pool)
}

// BrowserFrom returns the browser.Pool attached to ctx, or nil if none was
// attached. A check that wants to drive a headless browser must guard on
// the nil return; emitting findings without a Pool would be a bug because
// there is nothing to dispatch Visit against.
func BrowserFrom(ctx context.Context) browser.Pool {
	if pool, ok := ctx.Value(browserKey{}).(browser.Pool); ok {
		return pool
	}
	return nil
}

// stackKey carries the detected fingerprint.Stack through the context the
// scanner hands to Run. Used by checks (notably content-discovery) that
// want to suppress sub-probes irrelevant to the detected stack - e.g.
// skipping /web.config on an Apache host where IIS isn't in play.
//
// fingerprint.StackGated remains the right tool for gating an entire
// check; this is for finer-grained, intra-check decisions.
type stackKey struct{}

// WithStack attaches s to ctx so checks can adjust intra-check behavior
// (entry filtering, probe selection) based on the detected stack. The
// scanner sets this once per page; a nil s is allowed and means "no
// fingerprint available", which checks must treat as permissive rather
// than as proof of absence.
func WithStack(ctx context.Context, s *fingerprint.Stack) context.Context {
	return context.WithValue(ctx, stackKey{}, s)
}

// StackFrom returns the fingerprint.Stack attached to ctx, or nil if none
// was attached. A check that wants to gate sub-probes must treat nil as
// "no information; run everything" - the same contract the scanner uses
// for whole-check gating when fingerprinting is disabled or fails.
func StackFrom(ctx context.Context) *fingerprint.Stack {
	if s, ok := ctx.Value(stackKey{}).(*fingerprint.Stack); ok {
		return s
	}
	return nil
}

// DefaultBudget is the per-check deadline the scanner applies when a check
// does not implement Budgeted. Picked to fit a check that issues a handful
// of sequential requests at the default per-request timeout without
// leaving a worker slot pinned by a pathological one (regex backtracking,
// slow body read, weird redirect chain).
const DefaultBudget = 60 * time.Second

// Budgeted is optionally implemented by checks that need a longer per-check
// deadline than DefaultBudget. The scanner wraps Run's ctx with a deadline
// of Budget(); checks that don't implement Budgeted get DefaultBudget. A
// non-positive return reverts to DefaultBudget.
//
// Opt up only when a check truly needs the headroom (deep sweeps,
// aggressive fuzzing) - a longer budget means a misbehaving check pins
// its worker slot for longer before the deadline reclaims it.
type Budgeted interface {
	Budget() time.Duration
}

// Tier classifies a check by where it sits in the worklist dispatch
// pipeline. Constants are spaced so future intermediate tiers (e.g. a
// "deferred / end-of-scan" pass that absorbs the legacy TwoPhaseCheck
// dispatch) can slot in without renumbering.
//
// Tiers drain in increasing order: every TierFingerprint check on a
// host's targets runs before any TierPassive check on the same targets,
// passive before discovery, discovery before active. A discovery
// emission re-enters the worklist at the appropriate prefix tier so an
// endpoint surfaced during active probing still gets fingerprint and
// passive coverage before active checks fire against it.
//
// Checks that do not implement Targeted default to TierActive consuming
// target.KindPage; that matches the pre-worklist single-tier dispatch
// behavior and is what every check in the catalog gets until it opts
// in to Targeted.
type Tier int

const (
	TierFingerprint Tier = iota + 1
	TierPassive
	TierDiscovery
	TierActive
)

func (t Tier) String() string {
	switch t {
	case TierFingerprint:
		return "fingerprint"
	case TierPassive:
		return "passive"
	case TierDiscovery:
		return "discovery"
	case TierActive:
		return "active"
	default:
		return fmt.Sprintf("tier(%d)", int(t))
	}
}

// Targeted is optionally implemented by checks that want to declare
// where they sit in the dispatch pipeline and which target.Kind values
// they consume. Checks that do not implement Targeted are dispatched
// at TierActive against target.KindPage, matching the pre-worklist
// behavior.
//
// Consumes() returning nil or empty is equivalent to a single
// target.KindPage entry; the dispatcher treats the empty case as
// permissive rather than as "consumes nothing".
type Targeted interface {
	Tier() Tier
	Consumes() []target.Kind
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

// TwoPhaseCheck is implemented by checks whose verdict requires observing
// the application state AFTER every page has been planted. Stored XSS is
// the canonical case: a canary submitted via /api/comments only surfaces
// later when /post/123 renders the stored content, so a single per-page
// Run() pass cannot see persistence.
//
// The scanner drives a two-phase check like this:
//
//  1. Phase 1 (during the main crawl): for each in-scope page, the scanner
//     calls Plant in place of Run. Plant fans out probes (canary plants,
//     state mutations, etc.) and accumulates its own cross-page state -
//     the scanner does not see that state directly. Plant findings flow
//     to the report immediately, same as Run findings.
//
//  2. Between phases: the scanner calls DetectURLs once. The returned
//     URLs are unioned with the in-scope crawler URL set the scanner
//     retained during phase 1. Use this to surface same-origin URLs the
//     plant responses revealed (e.g. a redirect Location, a "view your
//     post" link in the body) that weren't in the original crawl. The
//     scanner's retained set only contains URLs the crawler fed into
//     ScanAll - URLs a Plant call discovered at runtime (form-following,
//     redirect chains the check followed itself) are NOT auto-added, so
//     a check that needs phase 2 to revisit them must return them here.
//
//  3. Phase 2 (after phase 1 drains): the scanner re-fetches every URL
//     in the unioned set, respecting scope and the rate limiter, and
//     calls Detect once per (check, re-fetched page). Detect inspects
//     the body for evidence of planted state (canary echo, breakout
//     bytes round-tripping intact, etc.) and returns findings.
//
// A two-phase check still satisfies Check; the scanner uses Run only as
// a fallback when phase-2 orchestration is disabled (older scanner code,
// dry runs). Implementations should return nil findings from Run rather
// than duplicating Plant - the report would otherwise carry two copies
// of every phase-1 hit.
//
// Implementations must be safe to call concurrently from many goroutines:
// scanOne runs Plant in parallel across pages, so any shared planted-
// state map needs its own mutex.
type TwoPhaseCheck interface {
	Check
	// Plant fires once per in-scope page during phase 1. Same call
	// shape as Run; any findings returned flow out immediately.
	Plant(ctx context.Context, client *httpclient.Client, scope *scope.Scope, p page.Page) ([]Finding, error)
	// DetectURLs returns same-origin URLs the check discovered during
	// plant responses that should be added to the phase-2 re-fetch set.
	// Called once between phases, on the same goroutine as the scanner's
	// main loop, so it does not need its own synchronization beyond the
	// internal locking Plant already uses. Return nil for "no extras".
	DetectURLs() []string
	// Detect fires once per re-fetched page during phase 2. p carries
	// the freshly-fetched body/headers; the check searches it for
	// evidence of its planted state and emits findings for each hit.
	Detect(ctx context.Context, client *httpclient.Client, scope *scope.Scope, p page.Page) ([]Finding, error)
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

// FilterByName returns the subset of checks whose Name() matches the
// enable allowlist and does not match the disable denylist. Both lists
// are sets of path.Match-style glob patterns, evaluated against the
// check's Name() string.
//
// An empty enable list means "every check passes the allow stage";
// disable always subtracts from the post-enable set. A pattern that
// does not match any registered check returns its literal name via
// UnmatchedPatterns so the caller can warn the operator about a typo
// without aborting the scan.
//
// Pattern syntax is the standard path.Match: '*' matches any run of
// non-separator characters, '?' matches one, and '[abc]' matches a
// class. Check names have no separators in practice, so '*' here means
// "any characters" (e.g. "*-blind" matches every blind variant).
func FilterByName(all []Check, enable, disable []string) (kept []Check, unmatched []string) {
	kept = make([]Check, 0, len(all))
	for _, c := range all {
		name := c.Name()
		if len(enable) > 0 && !matchesAny(name, enable) {
			continue
		}
		if matchesAny(name, disable) {
			continue
		}
		kept = append(kept, c)
	}
	// Unmatched is computed independently of the kept-set walk above.
	// If --enable narrows the set before --disable ever sees a check,
	// the disable patterns must still be evaluated against the full
	// catalog so a typo there surfaces. Operators expect "pattern
	// matched no check" to mean "no check in the catalog has this
	// name", not "no check survived the enable filter".
	for _, p := range enable {
		if !patternMatchesAny(all, p) {
			unmatched = append(unmatched, p)
		}
	}
	for _, p := range disable {
		if !patternMatchesAny(all, p) {
			unmatched = append(unmatched, p)
		}
	}
	return kept, unmatched
}

// matchesAny reports whether name matches any of patterns. path.Match
// errors (malformed glob) are silently treated as no-match; the caller
// would have already gotten the same outcome by typing a literal name
// that does not exist.
func matchesAny(name string, patterns []string) bool {
	for _, p := range patterns {
		ok, err := path.Match(p, name)
		if err != nil {
			continue
		}
		if ok {
			return true
		}
	}
	return false
}

// patternMatchesAny reports whether at least one check in all matches
// pattern. Linear over the catalog, but the catalog is bounded at low
// hundreds in practice and this only runs once at scan start.
func patternMatchesAny(all []Check, pattern string) bool {
	for _, c := range all {
		ok, err := path.Match(pattern, c.Name())
		if err != nil {
			return false
		}
		if ok {
			return true
		}
	}
	return false
}
