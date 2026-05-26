package lua_engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// RaceTargetFact is the raw scan output for one probed race-condition
// target. Carries the target descriptor (method, url, source), a key
// for cross-page dedupe, plus the structural probe outcome (baseline
// status and per-connection results). Finding-shape decisions
// (severity, title, detail, remediation, dedupe scope) are made on
// the Lua side from this raw fact.
//
// Mirrors the jwt-vulns / takeover bridge pattern: scan algorithm
// (raw sockets, single-packet barrier, status histogram) stays in
// Go where it can be unit-tested against deterministic loopback
// fixtures; the rule's catalog metadata lives in the .lua file so an
// operator can rewrite the prose without recompiling the scanner.
type RaceTargetFact struct {
	Method         string
	URL            string
	BodyLen        int
	ContentType    string
	Source         string
	TargetKey      string
	BaselineStatus int
	Probes         []RaceProbeResultFact
}

// RaceProbeResultFact is one connection's outcome from the single-
// packet fan-out, in a Lua-bridge-friendly shape. Status is the HTTP
// status code (0 when the connection produced no response); BodyHash
// is a short content fingerprint; Err carries the transport-level
// error string (empty when the probe completed).
type RaceProbeResultFact struct {
	Status   int
	BodyHash string
	Err      string
}

// ScanFacts is the Lua-bridge entry point for the race-condition
// check. Same wire behaviour as Run (collects targets, probes each
// with the single-packet barrier, respects the per-page cap and the
// cross-page seen-set) but returns one RaceTargetFact per probed
// target rather than composing Findings. The Lua port iterates the
// facts, decides which represent a race signal, and builds the
// finding text + severity itself.
//
// The (sc *scope.Scope) parameter is required - the Go check is
// strict on scope and we want the bridge to inherit that without a
// silent allow-all fallback. A nil scope skips every target the same
// way the Go check does.
func (c *RaceCondition) ScanFacts(ctx context.Context, sc *scope.Scope, p page.Page) ([]RaceTargetFact, error) {
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

	var facts []RaceTargetFact
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

		fact, err := c.probeFact(ctx, p.URL, t)
		if err != nil {
			Report(ctx, fmt.Errorf("race-condition probe %s %s: %w", t.Method, t.URL, err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if fact == nil {
			continue
		}
		facts = append(facts, *fact)
	}
	if len(facts) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return facts, nil
}

// probeFact runs the same baseline + single-packet probe pair that
// probeTarget uses but returns the raw structural result (status
// histogram input, body variety input, probe count) instead of an
// already-composed *Finding. Wraps the existing probe helpers so the
// Go check's tests keep covering the wire path - this entry point is
// only the data-shape adapter for the Lua bridge.
func (c *RaceCondition) probeFact(ctx context.Context, _ string, t raceTarget) (*RaceTargetFact, error) {
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

	baseStatus, _, baseErr := c.sendOne(ctx, parsed, addr, tlsCfg, t)
	if baseErr != nil {
		return nil, fmt.Errorf("baseline: %w", baseErr)
	}

	results := c.probeSinglePacketH1(ctx, parsed, addr, tlsCfg, t)

	out := &RaceTargetFact{
		Method:         t.Method,
		URL:            t.URL,
		BodyLen:        len(t.Body),
		ContentType:    t.ContentType,
		Source:         t.Source,
		TargetKey:      raceTargetKey(t),
		BaselineStatus: baseStatus,
		Probes:         make([]RaceProbeResultFact, 0, len(results)),
	}
	for _, r := range results {
		errStr := ""
		if r.Err != nil {
			errStr = r.Err.Error()
		}
		out.Probes = append(out.Probes, RaceProbeResultFact{
			Status:   r.Status,
			BodyHash: r.BodyHash,
			Err:      errStr,
		})
	}
	return out, nil
}

// RaceParallel exposes the per-target parallel probe count so the
// Lua port can stamp the same value into evidence text the Go check
// uses. Lua reads the constant rather than hard-coding it so a
// future tuning lands once.
func RaceParallel() int { return raceParallel }

// RaceTargetsPerPage exposes the per-page target cap. The Lua bridge
// already enforces it inside ScanFacts; this accessor lets the .lua
// finding text reference the same cap value the gate uses.
func RaceTargetsPerPage() int { return raceTargetsPerPage }

// SetRaceTimeoutsForTest dials the production dial / read / barrier
// timeouts down to the supplied values so parity tests in another
// package (checks_lua) can exercise the single-packet probe path
// without each test wedging for 8 seconds per failed dial. Returns
// the restore func tests defer in t.Cleanup. Mirrors the TLSAudit
// per-knob test hooks exported elsewhere in this file family.
func SetRaceTimeoutsForTest(dial, read, barrier time.Duration) (restore func()) {
	prevDial := raceDialTimeout
	prevRead := raceReadTimeout
	prevBarrier := raceBarrierTimeout
	raceDialTimeout = dial
	raceReadTimeout = read
	raceBarrierTimeout = barrier
	return func() {
		raceDialTimeout = prevDial
		raceReadTimeout = prevRead
		raceBarrierTimeout = prevBarrier
	}
}
