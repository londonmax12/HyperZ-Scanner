package checks

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// CRLFInjection probes whether a user-influenced input is reflected
// unescaped into a response header line, allowing CR/LF bytes to inject a
// new header (HTTP response splitting, CWE-113). For each candidate Sink
// the check sends a payload that smuggles a uniquely-named header carrying
// a fresh canary; if that header appears on the parsed response, the
// server must have decoded the request value and rendered the CR/LF into
// the response stream verbatim.
//
// Only LocQuery and LocForm sinks are probed. Go's net/http transport
// rejects CR/LF in outbound header values (so LocHeader / LocCookie sinks
// cannot carry the payload from a Go client), and path / JSON locations
// require encoder-specific shapes that aren't worth the false-positive
// surface for the small added coverage.
//
// This is an active (LevelDefault) check; it only runs when the user opts
// into a `default` or `aggressive` scan. Per-host rate limiting in the
// HTTP client governs probe pacing.
type CRLFInjection struct{}

func (CRLFInjection) Name() string { return "crlf-injection" }

func (CRLFInjection) Level() Level { return LevelDefault }

const (
	// crlfCanaryHeader is the header name the probe smuggles into a
	// response. Specific enough that a hit is almost certainly ours
	// (no legitimate framework emits this name), short enough that it
	// fits comfortably alongside the canary token without bloating the
	// payload past what URL encoders treat as a single value.
	crlfCanaryHeader = "X-Hyperz-CRLF"
	crlfBodyCap      = 4 << 10
)

func (c CRLFInjection) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if !sc.Allows(u) {
		return nil, nil
	}

	sinks := SinksFor(p)
	if len(sinks) == 0 {
		return nil, nil
	}

	variants := crlfPayloadVariants(LevelFrom(ctx))

	var findings []Finding
	var firstErr error
	seen := map[string]struct{}{}
	for _, sink := range sinks {
		if ctx.Err() != nil {
			break
		}
		if sink.Loc != LocQuery && sink.Loc != LocForm {
			continue
		}
		// Sub-scope: a form action off-host (or off-scope) must not be
		// probed even though the run-level scope check above passed.
		if u2, err := url.Parse(sink.URL); err == nil && !sc.Allows(u2) {
			continue
		}
		f, err := c.probeSink(ctx, client, p.URL, sink, variants)
		if err != nil {
			Report(ctx, fmt.Errorf("probe param %q (%s): %w", sink.Name, sink.Loc, err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if f == nil {
			continue
		}
		if _, dup := seen[f.DedupeKey]; dup {
			continue
		}
		seen[f.DedupeKey] = struct{}{}
		findings = append(findings, *f)
	}
	if firstErr != nil && len(findings) == 0 {
		return nil, firstErr
	}
	return findings, nil
}

// crlfPayloadVariants returns the line-terminator sequences to try, in
// order, for one sink. The full CRLF form is the textbook payload and
// hits the widest range of vulnerable handlers; LF-only and CR-only
// variants catch servers whose filter strips one byte but not the other.
// Aggressive scans also try a multi-byte form some Java / Tomcat
// stacks have historically truncated down to CR/LF.
func crlfPayloadVariants(lvl Level) []string {
	base := []string{"\r\n", "\n", "\r"}
	if lvl >= LevelAggressive {
		// Multi-byte aliasing: U+560A / U+560D have low bytes 0x0A /
		// 0x0D, and some legacy decoders (older Tomcat, certain Java
		// servlet stacks) historically truncated multi-byte chars to
		// their low byte, folding these into LF/CR. Not "overlong
		// UTF-8" (which is illegal byte sequences like 0xC0 0x8A);
		// this is just an aliasing trick. Encoded as the raw bytes;
		// the URL encoder will %-escape them on send.
		base = append(base, "嘊嘍")
	}
	return base
}

// probeSink runs the payload variants against one sink and returns the
// first finding (and stops; one vulnerable sink doesn't need three near-
// identical findings). Returns (nil, nil) if no variant triggered.
func (c CRLFInjection) probeSink(ctx context.Context, client *httpclient.Client, target string, sink Sink, variants []string) (*Finding, error) {
	for _, sep := range variants {
		if ctx.Err() != nil {
			return nil, nil
		}
		canary := NewCanary()
		payload := "hyperz" + sep + crlfCanaryHeader + ": " + canary
		f, err := c.probe(ctx, client, target, sink, payload, canary, sep)
		if err != nil {
			return nil, err
		}
		if f != nil {
			return f, nil
		}
	}
	return nil, nil
}

// probe issues one DoNoFollow request with payload overlaid onto sink and
// inspects the parsed response headers for crlfCanaryHeader carrying
// canary. A hit proves the server decoded the CR/LF bytes and wrote
// them onto a response header line.
func (c CRLFInjection) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink, payload, canary, sep string) (*Finding, error) {
	req, err := sink.MutateRequest(ctx, payload)
	if err != nil {
		return nil, err
	}
	resp, err := client.DoNoFollow(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	got := resp.Header.Get(crlfCanaryHeader)
	if got != canary {
		return nil, nil
	}

	body, truncated, err := httpclient.ReadBodyCapped(resp, crlfBodyCap)
	if err != nil {
		return nil, err
	}
	probeURL := req.URL.String()
	return &Finding{
		Check:    c.Name(),
		Target:   target,
		URL:      probeURL,
		Severity: SeverityHigh,
		Title:    fmt.Sprintf("CRLF header injection via %s %q", sink.Loc, sink.Name),
		Detail: fmt.Sprintf(
			"Parameter %q (%s) is reflected into a response header without filtering CR/LF bytes. "+
				"The probe injected %s into the value and the parsed response carried %s: %s, "+
				"proving the server wrote a fresh header line from attacker-controlled input. "+
				"This enables HTTP response splitting: an attacker can append arbitrary headers (Set-Cookie for session fixation, cache-control for poisoning) or a full second response body for stored XSS via downstream caches.",
			sink.Name, sink.Loc, crlfSepLabel(sep), crlfCanaryHeader, got),
		CWE:   "CWE-113",
		OWASP: "A03:2021 Injection",
		Remediation: "Reject or strip CR (\\r) and LF (\\n) bytes from any value that flows into a response header (Location, Set-Cookie, custom headers). " +
			"Prefer the framework's typed setters that perform this validation automatically rather than concatenating raw strings into the header stream. " +
			"At the edge, configure the reverse proxy / WAF to drop responses whose header section contains unexpected line terminators.",
		Evidence: &Evidence{
			Method:     req.Method,
			RequestURL: probeURL,
			Status:     resp.StatusCode,
			Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
		},
		// Dedupe per (page, loc, param): the same vulnerable param hit
		// from many entry points is one issue. Loc keeps a `next` query
		// distinct from a `next` form field on the same page.
		DedupeKey: MakeKey(c.Name(), ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
	}, nil
}

// crlfSepLabel returns a human-readable label for the line-terminator
// variant that triggered the hit, so the finding detail can disambiguate
// "server filters \r but not \n" from a full-CRLF break.
func crlfSepLabel(sep string) string {
	switch sep {
	case "\r\n":
		return "CRLF (\\r\\n)"
	case "\n":
		return "LF only (\\n)"
	case "\r":
		return "CR only (\\r)"
	}
	// Hex-encode anything else (e.g. the aggressive overlong form) so the
	// label stays printable and the reader can see which exact byte
	// sequence broke the filter.
	var b strings.Builder
	for _, r := range sep {
		fmt.Fprintf(&b, "U+%04X ", r)
	}
	return strings.TrimSpace(b.String())
}

// Compile-time check: CRLFInjection satisfies Check.
var _ Check = CRLFInjection{}
