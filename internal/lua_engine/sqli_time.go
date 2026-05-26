package lua_engine

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
)

// SQLiTime probes for blind SQL injection by inducing measurable delay.
// For each sink the check measures a baseline latency, then sends each
// PayloadSQLiTime variant rendered with {{SLEEP}}=sqliTimeSleep and
// asks TimingCompare whether the probe latency exceeds baseline by
// enough of the requested sleep to be consistent with execution. Any
// candidate hit is re-issued; only payloads that trip the threshold on
// both attempts produce a finding. The confirmation step is what makes
// the check usable over the internet - a single slow request from
// network jitter would otherwise look identical to a real sleep.
//
// Request count per sink: 1 baseline + N candidate probes (fast on
// non-vulnerable sinks) + 1 confirmation per candidate that crosses
// the threshold. With sleepFor = 5s and margin = 0.3 the per-vulnerable
// cost is roughly 2 * sleepFor = 10s of wall time.
//
// Active (LevelDefault) check. Implements Budgeted because the sleep
// arithmetic legitimately needs more headroom than DefaultBudget.
type SQLiTime struct{}

const (
	// sqliTimeBodyCap caps the response body read. Body content does
	// not influence detection - latency does - so this is purely to
	// drain the response without dragging a runaway body into memory.
	sqliTimeBodyCap = 4 << 10
	// sqliTimeFillerValue replaces an empty sink.Value before payload
	// append. Empty originals (most form inputs) leave the payload
	// without a leading character, which on numeric contexts produces
	// `WHERE id= AND SLEEP(5)` (parse error, no sleep). Anchoring with
	// "1" turns it into `WHERE id=1 AND SLEEP(5)`, which executes.
	sqliTimeFillerValue = "1"
)

// sqliTimeSleep is the duration each {{SLEEP}} placeholder resolves to.
// Long enough to clearly exceed normal jitter (sub-second) but short
// enough that two confirming probes on a vulnerable sink cost ~10s of
// wall time, not minutes. Package var so tests can dial it down to 1s
// and avoid pinning the suite on real sleeps.
var sqliTimeSleep = 5 * time.Second

// sqliTimeMargin is the fraction of sqliTimeSleep TimingCompare is
// allowed to "lose" to noise. 0.3 = require ≥70% of the requested sleep
// landed. Matches the oracle's documented guidance. Package var so
// tests can widen the margin when running against a fast loopback
// server where the "expected" delay is dominated by the sleep itself.
var sqliTimeMargin = 0.3

// probe runs the baseline + confirmed-timing sweep for one sink. Returns
// a finding only when a payload's latency crosses TimingCompare's
// threshold on both the candidate probe AND a confirmation probe; a
// single fast/slow alternation is rejected as network noise.
func (c SQLiTime) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	anchor := sink.Value
	if anchor == "" {
		anchor = sqliTimeFillerValue
	}

	canary := NewCanary()
	_, _, _, _, baseLatency, err := c.send(ctx, client, sink, anchor+canary)
	if err != nil {
		return nil, err
	}

	sleepSecs := int(sqliTimeSleep / time.Second)
	for _, p := range PayloadsFor(PayloadSQLiTime) {
		if ctx.Err() != nil {
			break
		}
		payload := p.Render("", sleepSecs)

		// Cache-bust suffix per probe. Every PayloadSQLiTime template ends
		// with `-- -`, so an appended canary lands inside the SQL line
		// comment and has zero effect on execution - but it varies the
		// wire value, which means a URL- or response-keyed cache in front
		// of the target returns a fresh response each time. Without this,
		// the candidate and confirmation can both hit the same cached
		// fast path and the check silently misses real bugs.
		candWire := anchor + payload + NewCanary()
		_, _, _, _, candLatency, err := c.send(ctx, client, sink, candWire)
		if err != nil {
			Report(ctx, fmt.Errorf("sqli-time candidate %s %s=%s pl=%s: %w",
				sink.Loc, sink.Name, sink.URL, p.Name, err))
			continue
		}
		candResult := TimingCompare(baseLatency, candLatency, sqliTimeSleep, sqliTimeMargin)
		if !candResult.Vulnerable {
			continue
		}

		// Confirmation probe: a single slow request is indistinguishable
		// from a network blip; a second confirming hit collapses that
		// false-positive surface dramatically. Fresh canary so the
		// confirmation can't share a cache entry with the candidate.
		confWire := anchor + payload + NewCanary()
		confReq, confResp, confBody, confTruncated, confLatency, err := c.send(ctx, client, sink, confWire)
		if err != nil {
			Report(ctx, fmt.Errorf("sqli-time confirm %s %s=%s pl=%s: %w",
				sink.Loc, sink.Name, sink.URL, p.Name, err))
			continue
		}
		confResult := TimingCompare(baseLatency, confLatency, sqliTimeSleep, sqliTimeMargin)
		if !confResult.Vulnerable {
			// Candidate was a one-off jitter spike. Keep sweeping other
			// payloads in case a different dialect actually injects.
			continue
		}

		probeURL := ""
		method := ""
		if confReq != nil {
			method = confReq.Method
			if confReq.URL != nil {
				probeURL = confReq.URL.String()
			}
		}
		status := statusOf(confResp)
		return &Finding{
			Check:    "sqli-time",
			Target:   target,
			URL:      probeURL,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("SQL injection (time-based) in %s parameter %q", sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) responds to time-based SQL inference: payload sqli-time/%s "+
					"(wire value %q, sleep %s) produced candidate latency %s and confirmation latency %s "+
					"against baseline %s. %s. An attacker can extract database contents one bit at a time "+
					"by chaining sleep-on-condition probes.",
				sink.Name, sink.Loc, p.Name, confWire, sqliTimeSleep,
				candLatency.Round(time.Millisecond), confLatency.Round(time.Millisecond),
				baseLatency.Round(time.Millisecond), confResult.Detail),
			CWE:   "CWE-89",
			OWASP: "A03:2021 Injection",
			Remediation: "Use parameterized queries / prepared statements; time-based blind SQLi remains exploitable " +
				"even when the response body never reflects database content. Disabling SLEEP / pg_sleep / WAITFOR via " +
				"the DB user's privileges narrows the attack surface but is not a replacement for parameterized queries.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     status,
				Snippet: fmt.Sprintf("baseline=%s candidate=%s confirmation=%s threshold=%s",
					baseLatency.Round(time.Millisecond),
					candLatency.Round(time.Millisecond),
					confLatency.Round(time.Millisecond),
					confResult.Threshold.Round(time.Millisecond)),
				Exchange: RecordExchange(confReq, nil, false, confResp, confBody, confTruncated),
			},
			DedupeKey: MakeKey("sqli-time", ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}
	return nil, nil
}

// send mutates sink with wireValue, dispatches the request, reads up to
// sqliTimeBodyCap of the body, and returns the wall-clock duration of
// the whole exchange. Latency is measured around client.Do, so it
// includes connection setup on the first request to a host and any
// retries the client did internally - which is what we want, since
// those are what an attacker would observe too.
func (c SQLiTime) send(ctx context.Context, client *httpclient.Client, sink Sink, wireValue string) (*http.Request, *http.Response, []byte, bool, time.Duration, error) {
	req, err := sink.MutateRequest(ctx, wireValue)
	if err != nil {
		return nil, nil, nil, false, 0, err
	}
	start := time.Now()
	resp, err := client.Do(ctx, req)
	latency := time.Since(start)
	if err != nil {
		return req, nil, nil, false, latency, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, sqliTimeBodyCap)
	if err != nil {
		return req, resp, nil, false, latency, err
	}
	return req, resp, body, truncated, latency, nil
}
