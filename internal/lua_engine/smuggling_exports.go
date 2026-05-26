package lua_engine

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"time"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// SmugglingVariantFact is the raw per-variant measurement the Lua
// request-smuggling port consumes. One entry per attempted variant
// (CL.TE, TE.CL, H2.CL); Probed=false for variants the host doesn't
// support (e.g. H2.CL on a server that did not negotiate h2). The
// timing oracle decision (Confirmed) is computed Go-side because the
// oracle math (TimingCompare + absolute floor) lives there; the rule
// catalog (severity, title, detail, remediation, dedupe-key shape)
// stays in the .lua file.
type SmugglingVariantFact struct {
	Label       string
	FrontEnd    string
	BackEnd     string
	Description string
	Proto       string // "http1" or "http2"
	BaselineMS  int64
	Probe1MS    int64
	Probe2MS    int64
	ThresholdMS int64
	Confirmed   bool
	Probed      bool
	SkipReason  string
}

// SmugglingHostFact bundles one per-host scan into the shape the Lua
// bridge surfaces. HostKey is "scheme://host[:port]"; FromCache is
// true when the per-LuaCheck cache returned a prior result for this
// host (the Lua port still emits one finding per Page on the same
// host, but it does not re-probe).
type SmugglingHostFact struct {
	HostKey   string
	Variants  []SmugglingVariantFact
	FromCache bool
}

// ScanFacts is the Lua bridge entry point. Behaviourally identical
// to Run with one shape change: returns the raw per-variant probe
// data instead of a composed *Finding, and lets the Lua side decide
// which confirmed variant to surface (and how to phrase it) when the
// host has more than one.
//
// Per-host caching keeps cross-page Run calls cheap: a host that
// confirmed on the first page returns the same variant set from the
// cache on subsequent pages, with FromCache=true so the Lua port can
// skip the "no new finding" emit. Same semantics as the Go check's
// Run (which short-circuits on the same cache map); the Lua port
// inherits the dedupe-per-host behaviour for free.
func (c *RequestSmuggling) ScanFacts(ctx context.Context, sc *scope.Scope, p page.Page) (*SmugglingHostFact, error) {
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

	hostKey := u.Scheme + "://" + u.Host

	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]*Finding{}
	}
	if c.smuggleVariants == nil {
		c.smuggleVariants = map[string][]SmugglingVariantFact{}
	}
	if _, ok := c.cache[hostKey]; ok {
		variants := c.cachedVariants(hostKey)
		c.mu.Unlock()
		return &SmugglingHostFact{
			HostKey:   hostKey,
			Variants:  variants,
			FromCache: true,
		}, nil
	}
	c.mu.Unlock()

	variants, err := c.evaluateHostFacts(ctx, u)
	if err != nil {
		// Mirror Run's cancellation handling: ctx-cancel must not be
		// cached as "host is clean", so callers re-evaluate next time.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil
		}
		// Cache a negative result so a flaky baseline doesn't make us
		// re-probe a confirmed-broken host on every subsequent Page.
		c.mu.Lock()
		c.cache[hostKey] = nil
		c.smuggleVariants[hostKey] = variants
		c.mu.Unlock()
		Report(ctx, err)
		return &SmugglingHostFact{HostKey: hostKey, Variants: variants}, nil
	}

	c.mu.Lock()
	// Synthesise a cache-sentinel Finding for the cache map so a later
	// Page on the same host short-circuits via the FromCache path.
	// Composition (severity, title, etc) is Lua-side; the sentinel just
	// flips the cache state so subsequent ScanFacts calls skip
	// re-probing.
	c.cache[hostKey] = &Finding{Check: "request-smuggling", Target: hostKey}
	c.smuggleVariants[hostKey] = variants
	c.mu.Unlock()

	return &SmugglingHostFact{HostKey: hostKey, Variants: variants}, nil
}

// cachedVariants returns the previously-stored variant slice for
// hostKey or nil when no scan ran. Must be called with c.mu held by
// the caller; this is the shared accessor ScanFacts uses for the
// cache-hit path.
func (c *RequestSmuggling) cachedVariants(hostKey string) []SmugglingVariantFact {
	v, ok := c.smuggleVariants[hostKey]
	if !ok {
		return nil
	}
	out := make([]SmugglingVariantFact, len(v))
	copy(out, v)
	return out
}

// evaluateHostFacts is the ScanFacts equivalent of evaluateHost.
// Probes every applicable variant once and returns the raw per-
// variant timing data (whether confirmed or not). Re-uses the same
// HTTP/1.1 and HTTP/2 probe wire paths the Go check exercises so
// timing oracle agreement is structurally guaranteed.
func (c *RequestSmuggling) evaluateHostFacts(ctx context.Context, u *url.URL) ([]SmugglingVariantFact, error) {
	host, port := splitHostPortDefault(u)
	addr := net.JoinHostPort(host, port)
	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	baseline, err := c.measureBaseline(ctx, u, addr, tlsCfg)
	if err != nil {
		return nil, err
	}

	variants := []smugglingVariant{variantCLTE(), variantTECL()}
	skipH2 := ""
	if u.Scheme == "https" {
		negotiated, alpnErr := c.negotiateALPN(ctx, addr, tlsCfg)
		switch {
		case alpnErr != nil:
			skipH2 = "alpn negotiation failed: " + alpnErr.Error()
		case negotiated != "h2":
			skipH2 = "server did not negotiate h2"
		default:
			variants = append(variants, variantH2CL())
		}
	} else {
		skipH2 = "scheme is http; h2 probe inapplicable"
	}

	out := make([]SmugglingVariantFact, 0, len(variants)+1)
	for _, v := range variants {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		fact := SmugglingVariantFact{
			Label:       v.label,
			FrontEnd:    v.frontEnd,
			BackEnd:     v.backEnd,
			Description: v.description,
			Proto:       smugglingProtoName(v.proto),
			BaselineMS:  baseline.Milliseconds(),
			ThresholdMS: smugglingHangThreshold.Milliseconds(),
			Probed:      true,
		}
		probe1, p1err := c.runVariant(ctx, u, addr, tlsCfg, v)
		if p1err != nil {
			fact.SkipReason = "probe1 transport error: " + p1err.Error()
			fact.Probed = false
			out = append(out, fact)
			continue
		}
		fact.Probe1MS = probe1.Milliseconds()
		if !c.timingHit(baseline, probe1) {
			out = append(out, fact)
			continue
		}
		select {
		case <-time.After(smugglingConfirmDelay):
		case <-ctx.Done():
			return out, ctx.Err()
		}
		probe2, p2err := c.runVariant(ctx, u, addr, tlsCfg, v)
		if p2err != nil {
			fact.SkipReason = "probe2 transport error: " + p2err.Error()
			out = append(out, fact)
			continue
		}
		fact.Probe2MS = probe2.Milliseconds()
		if c.timingHit(baseline, probe2) {
			fact.Confirmed = true
		}
		out = append(out, fact)
	}

	if skipH2 != "" {
		out = append(out, SmugglingVariantFact{
			Label:       "H2.CL",
			FrontEnd:    "HTTP/2 content-length",
			BackEnd:     "HTTP/1.1 Content-Length",
			Description: "HTTP/2 front-end downgrades to HTTP/1.1 back-end without rewriting content-length",
			Proto:       "http2",
			Probed:      false,
			SkipReason:  skipH2,
		})
	}
	return out, nil
}

// smugglingProtoName maps the internal smugglingProto enum to the
// stable string the Lua bridge surfaces. Centralised so the wire-
// shape label stays in one place; the Lua-side switch keys on these
// names so a renumbering of the enum constants cannot drift the
// surface.
func smugglingProtoName(p smugglingProto) string {
	switch p {
	case smugglingProtoHTTP1:
		return "http1"
	case smugglingProtoHTTP2:
		return "http2"
	}
	return ""
}

// SmugglingHangThresholdMS exposes the absolute floor (in ms) the
// timing oracle uses for confirmation. The Lua port stamps this into
// evidence text so the operator sees the same number the gate uses.
func SmugglingHangThresholdMS() int64 { return smugglingHangThreshold.Milliseconds() }

// SetSmugglingTimingsForTest dials the production hang threshold,
// probe timeout, and confirmation jitter down to test-friendly
// values so parity tests in checks_lua can exercise the timing
// oracle without each probe waiting 5-12 real seconds. Returns the
// restore func tests defer in t.Cleanup.
func SetSmugglingTimingsForTest(hang, probe, confirm time.Duration) (restore func()) {
	prevHang := smugglingHangThreshold
	prevProbe := smugglingProbeTimeout
	prevConfirm := smugglingConfirmDelay
	smugglingHangThreshold = hang
	smugglingProbeTimeout = probe
	smugglingConfirmDelay = confirm
	return func() {
		smugglingHangThreshold = prevHang
		smugglingProbeTimeout = prevProbe
		smugglingConfirmDelay = prevConfirm
	}
}

// SetSmugglingDialPlainForTest points the production raw-socket TCP
// dialer at the supplied address so parity tests in another package
// can route probes through a local mock listener without touching
// the host network. Used by the request-smuggling Lua parity tests
// the same way withTestSmugglingDial is used by the in-package tests.
func SetSmugglingDialPlainForTest(addr string) (restore func()) {
	prev := smugglingDialPlain
	smugglingDialPlain = func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	return func() { smugglingDialPlain = prev }
}
