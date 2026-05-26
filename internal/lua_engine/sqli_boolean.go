package lua_engine

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/londonmax12/hyperz/internal/httpclient"
)

// SQLiBoolean probes for SQL injection through differential response
// analysis: for each sink we send a baseline request, a truthy probe
// (`<value>' AND '1'='1`), and a falsy probe (`<value>' AND '1'='2`),
// then ask BooleanCompare whether truthy~baseline and falsy!=baseline.
// A vulnerable parameter behaves like a SQL boolean - truthy reproduces
// the baseline row set, falsy collapses to an empty one - while a
// well-parameterized input ignores the trailing payload entirely (both
// probes look like baseline).
//
// Before handing bodies to the oracle we strip the literal pair suffix
// from each variant body so a page that simply echoes its input value
// doesn't artificially diverge truthy from falsy. The baseline is
// untouched (it never carried a pair suffix to begin with), so the
// three-way comparison stays fair on echo-heavy pages.
//
// Request count per sink: 1 baseline + 2*N pair probes, stopping at the
// first pair the oracle classifies as vulnerable. With 4 curated pairs
// the worst case is 9 requests per sink.
//
// Active (LevelDefault) check.
type SQLiBoolean struct{}

// sqliBooleanBodyCap bounds the response body the check reads. Larger
// than the SQLi-error cap because the oracle's similarity scoring needs
// enough of the templated page to be comparable: a 4 KiB sample of a
// 60 KiB dashboard wouldn't capture the row-set divergence we're after.
const sqliBooleanBodyCap = 64 << 10

// probe runs the baseline + truthy/falsy sweep for one sink. Returns a
// finding only when BooleanCompare verdicts BoolVulnerable; BoolNoSignal
// and BoolIndeterminate are both treated as "no actionable evidence" so
// the check stays high-precision at the cost of missing parameters whose
// truthy/falsy split doesn't cleanly match the baseline pattern.
func (c SQLiBoolean) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	baseValue := sink.Value
	_, baseResp, baseBody, _, err := c.send(ctx, client, sink, baseValue)
	if err != nil {
		return nil, err
	}
	baseSnap := Snapshot{Status: statusOf(baseResp), Body: baseBody}

	for _, pair := range SQLiBooleanPairs() {
		if ctx.Err() != nil {
			break
		}
		truthyWire := baseValue + pair.True
		falsyWire := baseValue + pair.False

		// Pair-level send errors do not disqualify the sink: one flaky
		// request only invalidates this pair's verdict, not the next
		// pair's. Report and continue so a transient blip on the
		// string-quoted pair doesn't hide a vulnerability the numeric
		// pair would otherwise expose.
		_, tResp, tBody, _, err := c.send(ctx, client, sink, truthyWire)
		if err != nil {
			Report(ctx, fmt.Errorf("sqli-boolean truthy %s %s=%s pair=%s: %w",
				sink.Loc, sink.Name, sink.URL, pair.Name, err))
			continue
		}
		fReq, fResp, fBody, fTruncated, err := c.send(ctx, client, sink, falsyWire)
		if err != nil {
			Report(ctx, fmt.Errorf("sqli-boolean falsy %s %s=%s pair=%s: %w",
				sink.Loc, sink.Name, sink.URL, pair.Name, err))
			continue
		}

		// Strip the literal pair suffix from each variant body before
		// comparison: if the app echoes its input, leaving the suffix in
		// place would make every truthy/falsy body diverge from baseline
		// regardless of SQL behavior, producing a false positive on any
		// reflecting page.
		tStripped := bytes.ReplaceAll(tBody, []byte(pair.True), nil)
		fStripped := bytes.ReplaceAll(fBody, []byte(pair.False), nil)

		result := BooleanCompare(
			baseSnap,
			Snapshot{Status: statusOf(tResp), Body: tStripped},
			Snapshot{Status: statusOf(fResp), Body: fStripped},
		)
		if result.Decision != BoolVulnerable {
			continue
		}

		probeURL := ""
		method := ""
		if fReq != nil {
			method = fReq.Method
			if fReq.URL != nil {
				probeURL = fReq.URL.String()
			}
		}
		status := statusOf(fResp)
		return &Finding{
			Check:    "sqli-boolean",
			Target:   target,
			URL:      probeURL,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("SQL injection (boolean-based) in %s parameter %q", sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) responds to SQL boolean inference: pair sqli-boolean/%s produced "+
					"truthy~baseline (sim=%.3f, status=%d) and falsy!=baseline (sim=%.3f, status=%d). "+
					"%s. An attacker can extract database contents by chaining boolean conditions.",
				sink.Name, sink.Loc, pair.Name,
				result.TruthySim, statusOf(tResp), result.FalsySim, status, result.Detail),
			CWE:   "CWE-89",
			OWASP: "A03:2021 Injection",
			Remediation: "Use parameterized queries / prepared statements so user input is bound as a value, never " +
				"concatenated into SQL text. Boolean-based SQLi remains exploitable even when verbose errors are disabled, " +
				"so suppressing error output alone is not a fix.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     status,
				Snippet:    snippet(fBody, []byte(pair.False), false),
				Exchange:   RecordExchange(fReq, nil, false, fResp, fBody, fTruncated),
			},
			DedupeKey: MakeKey("sqli-boolean", ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}
	return nil, nil
}

// send mutates sink with wireValue, dispatches the request, and reads up
// to sqliBooleanBodyCap of the body. Mirrors the sibling checks' send
// shape so a future shared HTTP shell drops in without per-check change.
func (c SQLiBoolean) send(ctx context.Context, client *httpclient.Client, sink Sink, wireValue string) (*http.Request, *http.Response, []byte, bool, error) {
	req, err := sink.MutateRequest(ctx, wireValue)
	if err != nil {
		return nil, nil, nil, false, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, nil, false, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, sqliBooleanBodyCap)
	if err != nil {
		return req, resp, nil, false, err
	}
	return req, resp, body, truncated, nil
}
