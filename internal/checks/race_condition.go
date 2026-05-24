package checks

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// RaceCondition probes idempotency-sensitive endpoints for time-of-
// check / time-of-use bugs by firing N HTTP/1.1 requests through
// separate TCP connections that all release their final body byte
// at the same instant. This is the "single-packet attack" pattern
// popularised by Burp's race-condition tooling: by holding every
// connection at the byte-before-end-of-stream point and flushing
// every final byte through a synchronisation barrier in one tight
// goroutine fan-out, the requests land on the target within a sub-
// millisecond window. Most check-then-act races (coupon redemption,
// vote tallying, balance withdrawal, account creation against a
// uniqueness constraint) have critical sections measured in the
// hundreds of microseconds to low milliseconds, so collapsing the
// arrival window below that range materialises races that
// goroutine-only fan-outs would miss.
//
// Detection is purely structural: the check is blind to what each
// endpoint does business-logic-wise, so it never claims to have
// "stolen money" or "redeemed a coupon twice". The signal it can
// emit is response variance under parallel pressure - when N
// identical requests land within the race window and the target
// returns at least two distinct HTTP status codes, the dedup /
// uniqueness logic took different paths for different requests in
// the batch. A properly idempotent endpoint returns the same status
// for every duplicate (cached result or consistent "already done"
// error); variance is the racy half of a check-then-act split.
// Severity is fixed at Medium because the scanner cannot judge the
// business impact - the finding text directs the operator to
// confirm impact manually before grading higher.
//
// Scope gate: targets are collected from page.Forms and page.SpecOps
// and filtered to (a) non-idempotent HTTP methods (POST/PUT/PATCH/
// DELETE) and (b) URL paths matching curated state-change keywords
// (redeem, coupon, vote, withdraw, transfer, register, ...). Forms
// preserve their existing input values verbatim so a CSRF token
// the page already issued rides with every probe (CSRF tokens that
// only check membership but not single-use are themselves part of
// the race; sending N requests with the same token is the realistic
// attacker shape). SpecOps build a JSON body from spec-declared
// body params; non-body params (query, header) are kept on the URL
// where they belong.
//
// Per target: 1 baseline request to confirm reachability, then N
// (default 10) parallel single-packet probes. Each target probes
// at most once per scan; the dedupe set is keyed on (method, URL,
// body hash) so the same form on many pages does not multiply
// probe traffic.
//
// Out of scope:
//   - HTTP/2 single-packet attack. The check downgrades to HTTP/1.1
//     for the probe transport, which works against any target that
//     accepts h1 alongside h2 (the common case). Pure-h2 targets
//     where the front-end refuses h1 fall back to a degraded
//     parallel-goroutine probe without the byte-barrier; the doc
//     comment on probeSinglePacketH1 calls this out.
//   - Auth flows that require per-request token rotation (the same
//     CSRF token in every probe is the realistic attacker shape;
//     OAuth nonce / OTP flows that mint a fresh token per attempt
//     are not currently in scope).
//
// Level: Aggressive. The check issues N parallel state-mutating
// requests against the target, which is by construction noisy and
// state-changing - a vulnerable coupon endpoint will leave N redeems
// in the application database, a vulnerable vote endpoint will
// leave N spurious votes. Loads only when the operator opts in via
// --pollute, alongside the other state-mutating / disruptive checks.
type RaceCondition struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func (c *RaceCondition) Name() string { return "race-condition" }

func (c *RaceCondition) Level() Level { return LevelAggressive }

// Budget covers up to a small handful of targets per page, each
// with a sequential dial-of-N-connections (slow on TLS) plus the
// barrier + read phase. Five minutes matches request-smuggling and
// sqli-time.
func (c *RaceCondition) Budget() time.Duration { return 5 * time.Minute }

const (
	// raceParallel is the number of parallel single-packet probes
	// per target. 10 is a pragmatic balance: enough connections
	// that a race window > 1ms reliably opens for at least one
	// pair, but not so many that the sequential TLS dial phase
	// dominates the budget.
	raceParallel = 10

	// raceReadCap is the response body cap per probe. We need the
	// status line and a few headers for the variance oracle; the
	// body is hashed for finer-grained variance detection but the
	// cap stops a misbehaving target from streaming megabytes back
	// on every probe.
	raceReadCap = 8 << 10

	// raceMaxBodyBytes bounds how large a request body the check
	// is willing to assemble. A 1 MiB ceiling is more than enough
	// for any plausible form / JSON body the gate fires on; if a
	// spec declares a multi-MB body it is almost certainly a file
	// upload, which is the wrong target for race testing.
	raceMaxBodyBytes = 1 << 20

	// raceTargetsPerPage caps how many targets a single page can
	// contribute. A pathological login page with twenty action
	// forms otherwise multiplies probe traffic without adding
	// signal; capping at three keeps the per-page worst case
	// bounded.
	raceTargetsPerPage = 3
)

// raceDialTimeout bounds the TCP/TLS connect phase. Package var so
// tests can dial it down to ~100ms for the loopback test server.
var raceDialTimeout = 8 * time.Second

// raceReadTimeout bounds how long a probe waits for the response
// after releasing its final byte. Package var so tests can dial it
// down without spinning the suite on slow targets.
var raceReadTimeout = 8 * time.Second

// raceBarrierTimeout bounds how long the orchestrator waits for all
// N connections to report ready before giving up. If a target is
// dropping connections faster than we can hold them, single-packet
// is structurally impossible against it; bailing here avoids pinning
// the worker slot on an unreachable barrier.
var raceBarrierTimeout = 30 * time.Second

// Indirected so tests can inject loopback dials without touching the
// host network. In production these delegate to the system dialers
// with the supplied TLS config for HTTPS targets.
var (
	raceDialPlain = func(ctx context.Context, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: raceDialTimeout}
		return d.DialContext(ctx, "tcp", addr)
	}
	raceDialTLS = func(ctx context.Context, addr string, cfg *tls.Config) (net.Conn, error) {
		d := &net.Dialer{Timeout: raceDialTimeout}
		return tls.DialWithDialer(d, "tcp", addr, cfg)
	}
)

// racePathKeywords identifies URL paths that point at state-changing
// resources where idempotency violations have meaningful blast
// radius. Curated to be high-signal: every entry names a well-known
// race-prone endpoint shape (coupon redemption, voting, balance
// transfer, account uniqueness) rather than a generic verb that
// would match every CRUD POST in an app. Matched as case-insensitive
// substrings against the URL path.
var racePathKeywords = []string{
	// Promotion / discount / loyalty - the textbook race targets.
	"redeem", "coupon", "promo", "discount", "voucher", "gift",
	"reward", "bonus", "claim", "loyalty",
	// Social interaction - rate-limit-bypass races (one-per-user
	// constraints that race-bypass into many-per-user).
	"vote", "upvote", "downvote", "like", "favorite", "follow",
	"react",
	// Money-moving flows.
	"withdraw", "transfer", "refund", "deposit", "topup",
	"purchase", "checkout", "order", "buy", "pay",
	// Account-uniqueness constraints (sign up the same email twice).
	"register", "signup", "verify", "activate",
	// Permission / sharing toggles.
	"invite", "share",
}

// raceTarget is one resolved probe target. URL is absolute, Body is
// the request payload in wire bytes, ContentType is the matching
// content-type header (empty when the body is empty). Source is a
// short label that rides into finding evidence so the report can
// say "from form" vs "from openapi spec".
type raceTarget struct {
	Method      string
	URL         string
	Body        []byte
	ContentType string
	Source      string
}

func (c *RaceCondition) Run(ctx context.Context, _ *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil
	}
	if !sc.Allows(u) {
		return nil, nil
	}

	targets := c.collectTargets(p, sc)
	if len(targets) == 0 {
		return nil, nil
	}

	c.mu.Lock()
	if c.seen == nil {
		c.seen = map[string]struct{}{}
	}
	c.mu.Unlock()

	var findings []Finding
	var firstErr error
	probed := 0
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		if probed >= raceTargetsPerPage {
			break
		}
		key := raceTargetKey(t)
		c.mu.Lock()
		_, dup := c.seen[key]
		if !dup {
			c.seen[key] = struct{}{}
		}
		c.mu.Unlock()
		if dup {
			continue
		}
		probed++

		f, err := c.probeTarget(ctx, p.URL, t)
		if err != nil {
			Report(ctx, fmt.Errorf("race-condition probe %s %s: %w", t.Method, t.URL, err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if f != nil {
			findings = append(findings, *f)
		}
	}
	if len(findings) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return findings, nil
}

// collectTargets walks the page's forms and OpenAPI operations,
// keeping only the entries that look state-changing AND match the
// race-keyword path gate. The returned slice is deduplicated by
// (method, URL, body hash) so repeated forms on the same page do
// not produce duplicate probe traffic.
func (c *RaceCondition) collectTargets(p page.Page, sc *scope.Scope) []raceTarget {
	seen := map[string]struct{}{}
	var out []raceTarget
	add := func(t raceTarget) {
		if t.URL == "" || !raceMethodIsStateChange(t.Method) {
			return
		}
		u, err := url.Parse(t.URL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return
		}
		if !sc.Allows(u) {
			return
		}
		if !looksRaceSensitivePath(u.Path) {
			return
		}
		if len(t.Body) > raceMaxBodyBytes {
			return
		}
		k := raceTargetKey(t)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, t)
	}

	for _, f := range p.Forms {
		method := strings.ToUpper(strings.TrimSpace(f.Method))
		if method == "" {
			method = http.MethodGet
		}
		body, ct := buildRaceFormBody(f)
		add(raceTarget{
			Method:      method,
			URL:         f.Action,
			Body:        body,
			ContentType: ct,
			Source:      "form",
		})
	}

	for _, op := range p.SpecOps {
		method := strings.ToUpper(strings.TrimSpace(op.Method))
		if method == "" {
			method = http.MethodGet
		}
		body, ct := buildRaceSpecBody(op)
		add(raceTarget{
			Method:      method,
			URL:         op.URL,
			Body:        body,
			ContentType: ct,
			Source:      "openapi-spec",
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// raceMethodIsStateChange returns true for HTTP methods whose
// invocation may mutate server state. GET / HEAD / OPTIONS are
// excluded by spec (RFC 9110 §9.2 - "safe methods"); racing a safe
// method has no impact a properly-implemented endpoint can race on.
func raceMethodIsStateChange(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// looksRaceSensitivePath returns true when path contains a curated
// race-sensitive keyword. Comparison is case-insensitive substring
// match against the URL path - a strict suffix match would miss
// nested mounts like /api/v1/account/redeem.
func looksRaceSensitivePath(path string) bool {
	low := strings.ToLower(path)
	for _, kw := range racePathKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// buildRaceFormBody serializes a form's inputs to wire bytes ready
// to be sent as the probe body. The form's existing default values
// are preserved verbatim so any CSRF token the page issued rides
// with every probe. Empty inputs are kept as empty values rather
// than dropped so the wire shape matches what a browser submission
// would produce.
//
// Returns body bytes and the content-type to advertise. The Loc
// distinction in the form (GET vs POST) is honored by the caller
// via raceMethodIsStateChange; this builder always returns urlencoded
// because that is what every HTML <form> defaults to absent enctype.
func buildRaceFormBody(f page.Form) ([]byte, string) {
	method := strings.ToUpper(strings.TrimSpace(f.Method))
	if method == "" || method == http.MethodGet || method == http.MethodHead {
		// GET/HEAD have no body; the wire shape is query-string-only.
		// Race-condition does not probe these, but the builder is
		// tolerant so collectTargets's gate is the single source of
		// truth on which methods land in the prober.
		return nil, ""
	}
	body := url.Values{}
	for _, in := range f.Inputs {
		if in.Name == "" {
			continue
		}
		v := in.Value
		if v == "" && len(in.Options) > 0 {
			// <select> with options: pick the first option as a
			// realistic default. A truly empty option list means
			// the form lets the user choose any value; we leave
			// the field empty rather than fabricating.
			v = in.Options[0]
		}
		body.Set(in.Name, v)
	}
	return []byte(body.Encode()), "application/x-www-form-urlencoded"
}

// buildRaceSpecBody serializes an OpenAPI operation's declared body
// params into a JSON request body. Non-body params (query, header,
// cookie, path) are dropped here because they live on the URL or
// on headers, not in the body; the spec's URL already has path
// placeholders filled and query params left for the caller.
//
// Returns the body bytes and content-type. An operation with no
// body params returns (nil, "") so the probe sends an empty body.
func buildRaceSpecBody(op page.SpecOp) ([]byte, string) {
	method := strings.ToUpper(strings.TrimSpace(op.Method))
	if method == "" || method == http.MethodGet || method == http.MethodHead {
		return nil, ""
	}
	payload := map[string]any{}
	for _, prm := range op.Params {
		in := strings.ToLower(prm.In)
		if in != "body" && in != "formdata" {
			continue
		}
		if prm.Name == "" {
			continue
		}
		// Spec example values are preserved verbatim when present;
		// empty defaults become empty strings. The point of the
		// probe is consistency across N requests, not the cleverness
		// of the body, so a plain stringly-typed default is fine.
		payload[prm.Name] = prm.Value
	}
	if len(payload) == 0 {
		return nil, ""
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, ""
	}
	return raw, "application/json"
}

// raceTargetKey returns a stable hash of (method, URL, body) so
// the same logical target deduplicates across pages even when the
// scanner visits it from multiple parents.
func raceTargetKey(t raceTarget) string {
	h := sha1.New()
	h.Write([]byte(t.Method))
	h.Write([]byte{0})
	h.Write([]byte(t.URL))
	h.Write([]byte{0})
	h.Write(t.Body)
	return hex.EncodeToString(h.Sum(nil))
}

// probeTarget runs the single-packet attack against t and emits a
// finding when the N parallel responses show status-code variance.
// A baseline request runs first to confirm the target is actually
// reachable; if the baseline fails the probe is reported as an
// error rather than emitting a false "no race" verdict.
func (c *RaceCondition) probeTarget(ctx context.Context, pageURL string, t raceTarget) (*Finding, error) {
	parsed, err := url.Parse(t.URL)
	if err != nil {
		return nil, fmt.Errorf("parse target url: %w", err)
	}
	host, port := splitHostPortDefault(parsed)
	addr := net.JoinHostPort(host, port)
	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}

	// Baseline: one sequential request via the same raw transport
	// so any "the host isn't reachable on h1" failure surfaces here
	// rather than as a confusing zero-variance result later.
	baseStatus, _, baseErr := c.sendOne(ctx, parsed, addr, tlsCfg, t)
	if baseErr != nil {
		return nil, fmt.Errorf("baseline: %w", baseErr)
	}

	// Single-packet probe phase. Returns the per-connection results
	// in arrival order; a partial result set (some connections
	// failed to dial / write) still flows through the oracle so a
	// flaky target doesn't suppress an otherwise-strong signal.
	results := c.probeSinglePacketH1(ctx, parsed, addr, tlsCfg, t)

	verdict := evaluateRaceVerdict(baseStatus, results)
	if !verdict.Race {
		return nil, nil
	}
	return c.buildRaceFinding(pageURL, t, baseStatus, results, verdict), nil
}

// raceProbeResult is one connection's outcome from the single-packet
// fan-out. Status is the HTTP status code (0 when no response was
// received), BodyHash is a short prefix of the SHA-1 of the response
// body (empty when no body was read), Err is the transport-level
// error if any.
type raceProbeResult struct {
	Status   int
	BodyHash string
	Err      error
}

// probeSinglePacketH1 opens raceParallel TCP/TLS connections, sends
// each one its request bytes minus the last body byte, then waits
// on a shared barrier for every connection to be ready. Once all
// connections are holding the byte, the barrier releases and every
// connection writes its final byte and reads the response. The
// final-byte flush from each goroutine happens within the same
// Go-runtime scheduler window, landing all N final bytes on the
// target inside a sub-millisecond arrival window.
//
// Connections that fail to dial or fail to write the prefix are
// excluded from the barrier - the orchestrator releases when every
// SURVIVING connection is ready, so a partial fan-out (3 of 10
// dialed) still races the 3 that landed. The result slice is
// per-attempted-connection regardless of whether the probe
// completed, so the oracle can distinguish "probe failed" from
// "probe returned the same status".
//
// For empty bodies we synthesize a one-byte sentinel ("0") to give
// the barrier something to hold; the server sees a single-byte body
// arriving simultaneously across all N streams which is enough to
// land the requests in the racy window. Targets that reject the
// sentinel body produce a 4xx baseline AND 4xx parallel responses,
// which the oracle correctly classifies as "no race signal".
func (c *RaceCondition) probeSinglePacketH1(ctx context.Context, u *url.URL, addr string, tlsCfg *tls.Config, t raceTarget) []raceProbeResult {
	prefix, finalByte := splitForBarrier(buildRaceRequestBytes(u, t))

	// barrier is closed by the orchestrator once every surviving
	// connection has written its prefix and signaled ready. Each
	// goroutine blocks on it before writing finalByte.
	barrier := make(chan struct{})
	ready := make(chan struct{}, raceParallel)
	// preBarrierFailed counts goroutines that errored out before
	// reaching the barrier (dial / write-prefix). The orchestrator
	// reads it via atomic load so it can release the barrier once
	// every surviving connection is ready - touching the results
	// slice from the orchestrator while goroutines write to it
	// would be a data race that go test -race flags.
	var preBarrierFailed atomic.Int32
	results := make([]raceProbeResult, raceParallel)
	var wg sync.WaitGroup
	wg.Add(raceParallel)

	for i := 0; i < raceParallel; i++ {
		go func(idx int) {
			defer wg.Done()
			conn, err := c.dial(ctx, u, addr, tlsCfg)
			if err != nil {
				results[idx] = raceProbeResult{Err: fmt.Errorf("dial: %w", err)}
				preBarrierFailed.Add(1)
				return
			}
			defer conn.Close()
			// Write the request prefix (everything except the final
			// body byte). If this stalls beyond raceReadTimeout the
			// orchestrator's read deadline will eventually wake the
			// goroutine up; the barrier is non-fatal for late ones.
			if err := writeAllDeadline(conn, prefix, raceReadTimeout); err != nil {
				results[idx] = raceProbeResult{Err: fmt.Errorf("write prefix: %w", err)}
				preBarrierFailed.Add(1)
				return
			}
			// Signal readiness BEFORE blocking on the barrier so the
			// orchestrator can count us.
			ready <- struct{}{}
			<-barrier
			// All N goroutines unblock here. The first thing each
			// does is flush its final byte - the runtime scheduler
			// services these writes within microseconds of each
			// other.
			if err := writeAllDeadline(conn, finalByte, raceReadTimeout); err != nil {
				results[idx] = raceProbeResult{Err: fmt.Errorf("write final: %w", err)}
				return
			}
			head, err := readResponseHead(conn, raceReadTimeout)
			if err != nil && len(head) == 0 {
				results[idx] = raceProbeResult{Err: fmt.Errorf("read: %w", err)}
				return
			}
			status, body := parseResponseHead(head)
			results[idx] = raceProbeResult{
				Status:   status,
				BodyHash: hashPrefix(body),
			}
		}(i)
	}

	// Orchestrator: collect readiness signals up to a deadline.
	// Connections that fail to dial / write never report ready;
	// we count those as "won't participate" via the preBarrierFailed
	// atomic and release the barrier once the surviving set is fully
	// ready.
	deadline := time.NewTimer(raceBarrierTimeout)
	defer deadline.Stop()
	survivors := 0
collect:
	for survivors < raceParallel {
		select {
		case <-ready:
			survivors++
		case <-deadline.C:
			break collect
		case <-ctx.Done():
			break collect
		}
		if survivors+int(preBarrierFailed.Load()) >= raceParallel {
			break collect
		}
	}
	close(barrier)
	wg.Wait()
	return results
}

// raceVerdict is the oracle output: Race signals whether status
// variance was observed, StatusCounts gives the histogram for the
// finding evidence.
type raceVerdict struct {
	Race         bool
	StatusCounts map[int]int
	BodyVariety  int
	Reason       string
}

// evaluateRaceVerdict inspects N probe results plus the baseline
// status code and decides whether the variance pattern points at a
// race. The decision tree:
//
//  1. Drop results that errored out before reaching the response
//     (the variance oracle should only see complete probes; partial
//     fan-outs are noise here).
//  2. If fewer than 2 complete probes survived, no verdict.
//  3. If at least 2 distinct status codes appeared among complete
//     probes AND at least one is in the 2xx range, RACE: the dedup
//     logic took different paths.
//  4. If every probe matched the baseline status exactly, no race
//     signal (truly idempotent or all-raced - indistinguishable
//     from the outside, returned as no finding to avoid false
//     positives).
func evaluateRaceVerdict(baseStatus int, results []raceProbeResult) raceVerdict {
	statuses := map[int]int{}
	bodies := map[string]struct{}{}
	complete := 0
	hasSuccess := false
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		if r.Status == 0 {
			continue
		}
		complete++
		statuses[r.Status]++
		if r.BodyHash != "" {
			bodies[r.BodyHash] = struct{}{}
		}
		if r.Status >= 200 && r.Status < 300 {
			hasSuccess = true
		}
	}
	v := raceVerdict{StatusCounts: statuses, BodyVariety: len(bodies)}
	if complete < 2 {
		v.Reason = fmt.Sprintf("only %d/%d probes completed", complete, len(results))
		return v
	}
	if len(statuses) < 2 {
		v.Reason = fmt.Sprintf("all %d probes returned status %d (no variance)", complete, firstKey(statuses))
		return v
	}
	if !hasSuccess {
		v.Reason = "status variance present but no 2xx response in the batch"
		return v
	}
	v.Race = true
	v.Reason = fmt.Sprintf("baseline status=%d; parallel batch produced %d distinct status codes", baseStatus, len(statuses))
	return v
}

// firstKey returns one key from m, used for human-readable reason
// strings when a single-status batch needs to name that status.
func firstKey(m map[int]int) int {
	for k := range m {
		return k
	}
	return 0
}

func (c *RaceCondition) buildRaceFinding(pageURL string, t raceTarget, baseStatus int, results []raceProbeResult, v raceVerdict) *Finding {
	statusList := histogramString(v.StatusCounts)
	failures := 0
	for _, r := range results {
		if r.Err != nil {
			failures++
		}
	}

	return &Finding{
		Check:    "race-condition",
		Target:   pageURL,
		URL:      t.URL,
		Severity: SeverityMedium,
		Title:    fmt.Sprintf("Race condition signal in %s %s", t.Method, raceTitlePath(t.URL)),
		Detail: fmt.Sprintf(
			"The endpoint at %s %s produced different HTTP status codes when %d identical requests were "+
				"landed within a sub-millisecond arrival window via a single-packet attack (status histogram: %s; "+
				"baseline status=%d; %d connections failed to participate). A properly idempotent endpoint returns "+
				"the same status for every duplicate (cached result or a consistent 'already done' error); status "+
				"variance under parallel pressure is the racy half of a check-then-act split.\n\n"+
				"Severity is fixed at Medium because the business impact (double-redeem, double-spend, vote stuffing, "+
				"duplicate account creation) depends on what the endpoint does - confirm impact manually and grade "+
				"the finding higher when the racy operation moves money or violates a uniqueness constraint.",
			t.Method, t.URL, len(results)-failures, statusList, baseStatus, failures),
		Details: []string{
			fmt.Sprintf("target source: %s", t.Source),
			fmt.Sprintf("baseline response status: %d", baseStatus),
			fmt.Sprintf("parallel batch size: %d (failures: %d)", len(results), failures),
			fmt.Sprintf("status histogram: %s", statusList),
			fmt.Sprintf("response-body variety: %d distinct response hashes", v.BodyVariety),
			"reproduce with Burp's Repeater + Send group in parallel (single-packet attack), or any HTTP/2 client that supports parallel streams on one connection",
		},
		CWE:   "CWE-362",
		OWASP: "A04:2021 Insecure Design",
		Remediation: "Wrap the racy operation in a transaction with a unique constraint or row-level lock so the " +
			"check-then-act window cannot interleave. For coupon / voucher / one-shot resources, store a 'consumed' " +
			"marker on the resource and use an atomic compare-and-set ('UPDATE ... WHERE consumed=0' returning the " +
			"row count) instead of a SELECT-then-UPDATE. For vote / like / follow toggles, enforce uniqueness with " +
			"a (user_id, target_id) unique index and treat duplicate-key errors as the idempotent 'already done' " +
			"response. For account-creation flows, lean on the database's uniqueness constraint rather than an " +
			"application-level SELECT-then-INSERT.",
		Evidence: &Evidence{
			Method:     t.Method,
			RequestURL: t.URL,
			Status:     baseStatus,
			Snippet:    statusList,
		},
		DedupeKey: MakeKey("race-condition", ScopePage, t.URL, "method:"+t.Method, "body:"+raceTargetKey(t)),
	}
}

// histogramString renders a status-count map as a compact "200x7
// 409x3" string sorted by status code for readability.
func histogramString(counts map[int]int) string {
	if len(counts) == 0 {
		return "(no responses)"
	}
	keys := make([]int, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%dx%d", k, counts[k]))
	}
	return strings.Join(parts, " ")
}

// raceTitlePath returns a short path label for the finding title.
// The full URL appears in Detail; the title only needs enough path
// to disambiguate one endpoint from another on the same host.
func raceTitlePath(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

// dial picks plain TCP or TLS based on the target's scheme. Mirrors
// request-smuggling's dial so test edges with self-signed certs are
// reachable (the check is structurally about timing of the byte
// arrival, not cert validity).
func (c *RaceCondition) dial(ctx context.Context, u *url.URL, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	if u.Scheme == "https" {
		return raceDialTLS(ctx, addr, tlsCfg)
	}
	return raceDialPlain(ctx, addr)
}

// sendOne dials, sends t in full, and reads the response head. Used
// for the baseline phase where we want a single complete probe to
// confirm the target's idempotent-path response shape before the
// parallel batch runs.
func (c *RaceCondition) sendOne(ctx context.Context, u *url.URL, addr string, tlsCfg *tls.Config, t raceTarget) (int, string, error) {
	conn, err := c.dial(ctx, u, addr, tlsCfg)
	if err != nil {
		return 0, "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	wire := buildRaceRequestBytes(u, t)
	if err := writeAllDeadline(conn, []byte(wire), raceReadTimeout); err != nil {
		return 0, "", fmt.Errorf("write: %w", err)
	}
	head, err := readResponseHead(conn, raceReadTimeout)
	if err != nil && len(head) == 0 {
		return 0, "", fmt.Errorf("read: %w", err)
	}
	status, body := parseResponseHead(head)
	return status, hashPrefix(body), nil
}

// buildRaceRequestBytes serializes the target into HTTP/1.1 wire
// bytes the prober writes byte-for-byte. The request line carries
// the target's absolute path (and any query string); host comes
// from u; the body and content-type ride from the target.
func buildRaceRequestBytes(u *url.URL, t raceTarget) string {
	pathPart := u.RequestURI()
	if pathPart == "" {
		pathPart = "/"
	}
	var b strings.Builder
	b.WriteString(t.Method)
	b.WriteString(" ")
	b.WriteString(pathPart)
	b.WriteString(" HTTP/1.1\r\n")
	b.WriteString("Host: ")
	b.WriteString(u.Host)
	b.WriteString("\r\n")
	b.WriteString("User-Agent: hyperz-race-probe\r\n")
	b.WriteString("Accept: */*\r\n")
	b.WriteString("Connection: close\r\n")
	body := t.Body
	if len(body) == 0 {
		// One-byte sentinel body so the barrier has a final byte
		// to hold even on body-less methods. The server's content-
		// length parser sees a 1-byte body which it can either
		// accept (parse-tolerant frameworks) or reject (strict
		// servers). Acceptance still lands the race; rejection
		// yields a 4xx baseline AND 4xx parallel responses, which
		// the oracle correctly reports as "no race signal".
		body = []byte("0")
	}
	if t.ContentType != "" {
		b.WriteString("Content-Type: ")
		b.WriteString(t.ContentType)
		b.WriteString("\r\n")
	}
	b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

// splitForBarrier splits wire into (prefix, finalByte). The final
// byte is held back at the barrier so every probe goroutine flushes
// its terminating byte at the same instant. Wire is guaranteed
// non-empty by buildRaceRequestBytes (the sentinel body ensures a
// final byte always exists).
func splitForBarrier(wire string) ([]byte, []byte) {
	if len(wire) == 0 {
		return nil, nil
	}
	return []byte(wire[:len(wire)-1]), []byte(wire[len(wire)-1:])
}

// parseResponseHead extracts the status code and the raw bytes of
// the response head from a freshly-read head buffer. The status code
// is on the first line in "HTTP/1.1 NNN ..." format; non-conforming
// lines return 0 so the oracle classifies the probe as no-status.
func parseResponseHead(head []byte) (int, []byte) {
	if len(head) == 0 {
		return 0, nil
	}
	line := head
	if i := indexByte(head, '\n'); i >= 0 {
		line = head[:i]
	}
	parts := strings.SplitN(strings.TrimSpace(string(line)), " ", 3)
	if len(parts) < 2 {
		return 0, head
	}
	var code int
	if _, err := fmt.Sscanf(parts[1], "%d", &code); err != nil {
		return 0, head
	}
	return code, head
}

// indexByte returns the index of c in b or -1 if absent. Tiny
// inlined helper that avoids importing bytes just for one call.
func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// hashPrefix returns the first 8 hex chars of the SHA-1 of body.
// Used to bucket responses by content shape without retaining the
// full body in cache. Empty input returns empty.
func hashPrefix(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	h := sha1.Sum(body)
	return hex.EncodeToString(h[:])[:8]
}

// errProbeUnreachable surfaces from probeTarget when the baseline
// could not be established. Unused outside this file but kept
// distinct so future callers (e.g. a CLI subcommand) can match it.
var errProbeUnreachable = errors.New("race-condition: target unreachable")
