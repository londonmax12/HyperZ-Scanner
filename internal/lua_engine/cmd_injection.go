package lua_engine

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
)

// CmdInjection probes whether a user-influenced input is concatenated
// into a shell command, by appending shell separators followed by a
// sleep (POSIX) or ping-delay (Windows) and measuring whether the
// response latency rose by the requested amount. Mirrors SQLiTime in
// shape: baseline + candidate + confirmation, with the confirmation
// rejecting one-off jitter spikes that would otherwise mascarade as
// real command execution.
//
// The PayloadCmdInject catalog covers the standard shell escape
// points: `;` / `&&` / `|` chains for POSIX, backtick / `$(...)`
// subshells for arguments inside double-quoted strings, and the
// Windows `ping -n N 127.0.0.1` analog for cmd.exe targets. A single
// curated payload per shell context keeps fan-out bounded while still
// covering both Unix and Windows backends in one sweep.
//
// Per sink: 1 baseline + N candidates (fast on non-vulnerable sinks)
// + 1 confirmation per candidate that crosses the threshold. With
// sleepFor = 5s and margin = 0.3 the per-vulnerable cost is ~2 *
// sleepFor of wall time.
//
// Active (LevelDefault) check. Implements Budgeted because the sleep
// arithmetic needs more headroom than DefaultBudget for the same
// reason SQLiTime does.
type CmdInjection struct{}

const (
	// cmdInjectionBodyCap drains the response body without dragging a
	// runaway page into memory. Body content does not influence
	// detection (latency does); a few KiB is enough to close the
	// connection cleanly.
	cmdInjectionBodyCap = 4 << 10
	// cmdInjectionFillerValue replaces an empty sink.Value so the
	// payload still has a leading byte to land against. Shell commands
	// usually tolerate empty arguments, but a missing value can break
	// the host command's parse before our injection separator fires.
	cmdInjectionFillerValue = "1"
)

// cmdInjectionSleep is the duration each {{SLEEP}} placeholder resolves
// to. Same tradeoff as sqliTimeSleep - long enough to clearly exceed
// jitter, short enough that confirmation doubles the wall time without
// blowing through the budget. Package var so tests can dial it down to
// 1s and avoid pinning the suite on real sleeps.
var cmdInjectionSleep = 5 * time.Second

// cmdInjectionMargin is the slack TimingCompare allows. 0.3 = ≥70%
// of the requested sleep must land. Package var so tests can widen
// the margin on a fast loopback server.
var cmdInjectionMargin = 0.3

// probe runs the baseline + confirmed-timing sweep for one sink. The
// candidate/confirmation structure mirrors SQLiTime: a single slow
// request is indistinguishable from a network jitter spike, so we only
// emit when both attempts cross TimingCompare's threshold.
//
// Cache-bust strategy: shell payloads have no universal comment shape
// (sh / bash / cmd.exe each diverge), so we can't hide a per-probe
// canary inside the payload the way SQLiTime can with `-- -`. Instead
// the confirmation renders a different sleep count (candSleep+1s),
// which changes the wire value and therefore the URL-keyed cache key
// without changing the detection oracle. A cache in front of the
// target can't collapse candidate and confirmation onto the same
// cached fast response.
func (c CmdInjection) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	anchor := sink.Value
	if anchor == "" {
		anchor = cmdInjectionFillerValue
	}

	canary := NewCanary()
	baseLatency, err := c.sendForTiming(ctx, client, sink, anchor+canary)
	if err != nil {
		return nil, err
	}

	candSleep := cmdInjectionSleep
	confSleep := cmdInjectionSleep + time.Second
	candSleepSecs := int(candSleep / time.Second)
	confSleepSecs := int(confSleep / time.Second)

	for _, p := range PayloadsFor(PayloadCmdInject) {
		if ctx.Err() != nil {
			break
		}
		candWire := anchor + p.Render("", candSleepSecs)

		candLatency, err := c.sendForTiming(ctx, client, sink, candWire)
		if err != nil {
			Report(ctx, fmt.Errorf("cmd-injection candidate %s %s=%s pl=%s: %w",
				sink.Loc, sink.Name, sink.URL, p.Name, err))
			continue
		}
		candResult := TimingCompare(baseLatency, candLatency, candSleep, cmdInjectionMargin)
		if !candResult.Vulnerable {
			continue
		}

		confWire := anchor + p.Render("", confSleepSecs)
		confReq, confResp, confBody, confTruncated, confLatency, err := c.sendFull(ctx, client, sink, confWire)
		if err != nil {
			Report(ctx, fmt.Errorf("cmd-injection confirm %s %s=%s pl=%s: %w",
				sink.Loc, sink.Name, sink.URL, p.Name, err))
			continue
		}
		confResult := TimingCompare(baseLatency, confLatency, confSleep, cmdInjectionMargin)
		if !confResult.Vulnerable {
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
			Check:    "cmd-injection",
			Target:   target,
			URL:      probeURL,
			Severity: SeverityCritical,
			Title:    fmt.Sprintf("OS command injection in %s parameter %q", sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) is concatenated into a shell command: payload cmd-injection/%s "+
					"(confirmation wire value %q, candidate sleep %s, confirmation sleep %s) produced "+
					"candidate latency %s and confirmation latency %s against baseline %s. %s. "+
					"An attacker can run arbitrary commands as the web server process and pivot to "+
					"filesystem read/write, network reconnaissance, or full RCE.",
				sink.Name, sink.Loc, p.Name, confWire, candSleep, confSleep,
				candLatency.Round(time.Millisecond), confLatency.Round(time.Millisecond),
				baseLatency.Round(time.Millisecond), confResult.Detail),
			CWE:   "CWE-78",
			OWASP: "A03:2021 Injection",
			Remediation: "Never pass user input to a shell. Use the language's exec API that takes an argv slice (e.g. " +
				"Go's exec.Command(name, args...), Python's subprocess with shell=False) so arguments are passed as " +
				"separate elements rather than concatenated into a shell-parsed string. When a shell is unavoidable, " +
				"strictly allowlist the permitted argument shape - blocklists of metacharacters are routinely bypassed.",
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
			DedupeKey: MakeKey("cmd-injection", ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}
	return nil, nil
}

// sendForTiming dispatches the probe and returns only the wall-clock
// latency. Used by baseline and candidate probes where the request /
// response payload would just be discarded. The body is still read and
// closed (capped at cmdInjectionBodyCap) so the connection can be
// reused for the next probe; without that drain the underlying socket
// stalls and inflates the next baseline.
func (c CmdInjection) sendForTiming(ctx context.Context, client *httpclient.Client, sink Sink, wireValue string) (time.Duration, error) {
	_, _, _, _, latency, err := c.sendFull(ctx, client, sink, wireValue)
	return latency, err
}

// sendFull dispatches the probe and returns the full exchange so the
// confirmation can attach req / resp / body to the finding's Evidence.
// Latency is measured around client.Do so it includes connection setup
// and any internal retries - i.e. what an attacker would observe.
func (c CmdInjection) sendFull(ctx context.Context, client *httpclient.Client, sink Sink, wireValue string) (*http.Request, *http.Response, []byte, bool, time.Duration, error) {
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
	body, truncated, err := httpclient.ReadBodyCapped(resp, cmdInjectionBodyCap)
	if err != nil {
		return req, resp, nil, false, latency, err
	}
	return req, resp, body, truncated, latency, nil
}
