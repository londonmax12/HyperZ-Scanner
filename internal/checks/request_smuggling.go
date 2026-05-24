package checks

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// RequestSmuggling probes the target's HTTP front-end / back-end parser pair
// for desynchronization (HTTP Request Smuggling). Three variants are sent,
// each timed against a clean baseline measured on the same transport:
//
//   - CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding.
//     The probe carries an incomplete chunked body that the front-end
//     truncates at CL bytes; the back-end's TE parser is left waiting for
//     the chunk terminator that never arrives and hangs.
//   - TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length.
//     The probe declares CL=6 but the chunked body ends after 5 bytes; the
//     front-end accepts the zero chunk and forwards, the back-end's CL
//     parser hangs waiting for the missing 6th byte.
//   - H2.CL: HTTP/2 front-end downgrades to HTTP/1.1 for the back-end,
//     translating a non-zero content-length pseudo-header into a CL line.
//     The probe carries the wrong amount of DATA so the downgraded request
//     leaves the back-end waiting for bytes that will never arrive over
//     the multiplexed stream.
//
// Detection is purely timing-based: the probe never sends a smuggled
// suffix that would land on the next user's request, so the only state
// disturbed is the single connection the probe rode in on (which the
// front-end drops when the back-end's hang propagates). Any candidate
// timing hit is re-issued; only probes that cross the threshold on both
// attempts produce a finding so network jitter and noisy WAFs do not
// fire it.
//
// This is the most invasive check in the catalog: it issues deliberately
// malformed requests over a raw socket that bypasses the standard
// httpclient transport (Go's net/http would normalize CL/TE conflicts
// and refuse to send the payloads). Even though the timing-only probes
// do not poison downstream user requests, the malformed traffic is
// loud and many production WAFs will flag and possibly block the
// scanner source IP. Loads only when the operator opts in via
// --pollute, alongside the other state-mutating / disruptive checks.
//
// Level: Aggressive. Findings dedupe per host since smuggling is a
// front-end/back-end pairing property, not a per-page bug.
type RequestSmuggling struct {
	mu    sync.Mutex
	cache map[string]*Finding // key = scheme://host[:port]; nil entry = probed clean
}

func (c *RequestSmuggling) Name() string { return "request-smuggling" }

func (c *RequestSmuggling) Level() Level { return LevelAggressive }

// Budget grants headroom for the per-host probe sequence. Worst case:
// 1 baseline measurement (~3 samples) + 3 variant probes + 3 confirmation
// re-probes, each capable of hanging up to smugglingProbeTimeout. The 5
// minute ceiling matches sqli-time's reasoning.
func (c *RequestSmuggling) Budget() time.Duration { return 5 * time.Minute }

const (
	// smugglingBaselineSamples is how many baseline measurements we take
	// before probing. Median of 3 is enough to reject one transient
	// spike without burning a minute on the baseline alone.
	smugglingBaselineSamples = 3

	// smugglingDialTimeout bounds the connect phase. Targets that take
	// longer to accept a socket aren't ones we can usefully probe.
	smugglingDialTimeout = 8 * time.Second

	// smugglingReadCap bounds how much response we read into memory
	// per probe. We only inspect the status line and a few headers;
	// 8 KiB is comfortably above any sane front-end's error response.
	smugglingReadCap = 8 << 10
)

// smugglingProbeTimeout caps how long a single probe waits for a
// response. The hang is the signal, but a probe that runs forever
// pins the worker slot, so we read with a deadline and treat any
// read beyond smugglingHangThreshold as confirmation. Package var so
// tests can dial it down to ~100ms instead of waiting real seconds.
var smugglingProbeTimeout = 12 * time.Second

// smugglingHangThreshold is the absolute floor above which a probe
// latency counts as a back-end hang. TimingCompare also enforces a
// baseline-relative threshold; this absolute floor stops a slow but
// non-vulnerable target from cascading both probe attempts into
// false positives just because the baseline itself was slow. Package
// var so tests can dial it down without spinning the suite on real
// hangs.
var smugglingHangThreshold = 5 * time.Second

// smugglingConfirmDelay is the gap between a candidate probe hit and
// the confirmation re-probe on the same variant. Transient back-pressure
// (a GC pause on the back-end, a momentary upstream stall) can hold a
// connection open for a few seconds; re-probing inside that window
// risks counting the same transient as two independent confirmations.
// Package var so tests can dial it down.
var smugglingConfirmDelay = 1500 * time.Millisecond

// Indirected so tests can intercept the network dial. In production
// these delegate to the system dialers; the production net.Dial /
// tls.Dial split honors smugglingDialTimeout and uses the supplied
// TLS config (Server Name, InsecureSkipVerify) so probes survive
// self-signed test edges that the baseline httpclient would refuse.
var (
	smugglingDialPlain = func(ctx context.Context, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: smugglingDialTimeout}
		return d.DialContext(ctx, "tcp", addr)
	}
	smugglingDialTLS = func(ctx context.Context, addr string, cfg *tls.Config) (net.Conn, error) {
		d := &net.Dialer{Timeout: smugglingDialTimeout}
		return tls.DialWithDialer(d, "tcp", addr, cfg)
	}
)

func (c *RequestSmuggling) Run(ctx context.Context, _ *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
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
	if cached, ok := c.cache[hostKey]; ok {
		c.mu.Unlock()
		if cached == nil {
			return nil, nil
		}
		// Re-emit the cached positive with the current page URL so the
		// finding ties to a URL the user actually saw.
		f := *cached
		f.Target = p.URL
		f.URL = p.URL
		return []Finding{f}, nil
	}
	c.mu.Unlock()

	finding, err := c.evaluateHost(ctx, u)
	if err != nil {
		// Context cancellation isn't a smuggling signal and isn't an
		// error worth reporting. Crucially, we also don't cache: a
		// fresh ctx on a later page should re-evaluate the host rather
		// than treat a cancel as proof the host is clean.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil
		}
		c.mu.Lock()
		c.cache[hostKey] = finding
		c.mu.Unlock()
		Report(ctx, fmt.Errorf("request-smuggling %s: %w", hostKey, err))
		return nil, nil
	}
	c.mu.Lock()
	c.cache[hostKey] = finding
	c.mu.Unlock()
	if finding == nil {
		return nil, nil
	}
	f := *finding
	f.Target = p.URL
	f.URL = p.URL
	return []Finding{f}, nil
}

// evaluateHost runs the per-host probe sequence. Order: baseline first,
// then HTTP/1.1 variants (CL.TE, TE.CL), then HTTP/2 (H2.CL) if ALPN
// negotiates h2. The first variant that confirms wins; we don't fan
// out further once a finding is established, since the per-host
// recommendation is identical regardless of which parser disagreed.
func (c *RequestSmuggling) evaluateHost(ctx context.Context, u *url.URL) (*Finding, error) {
	host, port := splitHostPortDefault(u)
	addr := net.JoinHostPort(host, port)
	tlsCfg := &tls.Config{
		ServerName: host,
		// Smuggling probes test framing disagreement between the front-
		// and back-end, which is orthogonal to cert validity. Refusing
		// to probe self-signed or expired-cert targets would silently
		// skip most staging environments where smuggling is most worth
		// catching. The check never sends authenticated traffic or
		// confidential bytes over the connection, so accepting any
		// cert here does not change the safety profile of the probe.
		InsecureSkipVerify: true,
		// ALPN: offer h2 so the H2.CL probe can run when supported.
		// We negotiate per-probe rather than once per host because the
		// HTTP/1.1 probes deliberately reuse no connection.
		NextProtos: []string{"h2", "http/1.1"},
	}

	baseline, err := c.measureBaseline(ctx, u, addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}

	variants := []smugglingVariant{
		variantCLTE(),
		variantTECL(),
	}
	// Only probe H2.CL when the server advertises h2 via ALPN. A bare
	// HTTPS handshake that selects http/1.1 means h2 isn't on the wire,
	// so the variant is inapplicable.
	if u.Scheme == "https" {
		negotiated, err := c.negotiateALPN(ctx, addr, tlsCfg)
		if err == nil && negotiated == "h2" {
			variants = append(variants, variantH2CL())
		}
	}

	for _, v := range variants {
		// Each variant can take up to smugglingProbeTimeout twice; bail
		// the whole loop on cancellation rather than burning the rest
		// of the budget on a request the caller has given up on.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		probe1, p1err := c.runVariant(ctx, u, addr, tlsCfg, v)
		if p1err != nil {
			// A transport-layer failure on the probe itself (TLS error,
			// dial refused, etc.) is not a smuggling signal. Move on
			// to the next variant rather than failing the whole host.
			continue
		}
		if !c.timingHit(baseline, probe1) {
			continue
		}
		// Wait out any short-lived transient (GC pause, upstream stall)
		// before the confirmation probe so we are not measuring the
		// same back-pressure event twice.
		select {
		case <-time.After(smugglingConfirmDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		// Re-issue to filter jitter. Both attempts must cross the
		// threshold before we call it.
		probe2, p2err := c.runVariant(ctx, u, addr, tlsCfg, v)
		if p2err != nil {
			continue
		}
		if !c.timingHit(baseline, probe2) {
			continue
		}
		return c.buildFinding(u, v, baseline, probe1, probe2), nil
	}
	return nil, nil
}

// timingHit reports whether the probe latency is anomalous relative to
// the baseline. We require both the relative threshold (probe lands at
// least 70% of the requested hang above baseline) and an absolute floor
// (probe latency >= smugglingHangThreshold) so a slow target whose
// baseline already sits at several seconds can't trip the check just
// by widening the jitter band.
func (c *RequestSmuggling) timingHit(baseline, probe time.Duration) bool {
	if probe < smugglingHangThreshold {
		return false
	}
	res := TimingCompare(baseline, probe, smugglingHangThreshold, 0.3)
	return res.Vulnerable
}

// measureBaseline issues smugglingBaselineSamples well-formed GETs over
// the same transport class and returns the median latency. Median (not
// mean) so one stalled sample can't drag the baseline up enough to
// suppress a real hang.
func (c *RequestSmuggling) measureBaseline(ctx context.Context, u *url.URL, addr string, tlsCfg *tls.Config) (time.Duration, error) {
	samples := make([]time.Duration, 0, smugglingBaselineSamples)
	for i := 0; i < smugglingBaselineSamples; i++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		d, err := c.sendBaseline(ctx, u, addr, tlsCfg)
		if err != nil {
			// One bad baseline sample shouldn't sink the check; keep
			// going if at least one other sample succeeds.
			continue
		}
		samples = append(samples, d)
	}
	if len(samples) == 0 {
		return 0, errors.New("no baseline samples succeeded")
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], nil
}

// sendBaseline does one well-formed GET / over a raw socket so the
// baseline is measured on the same transport the probes will use,
// rather than via the httpclient (which has connection pooling,
// retries, and middleware that would distort the timing reference).
func (c *RequestSmuggling) sendBaseline(ctx context.Context, u *url.URL, addr string, tlsCfg *tls.Config) (time.Duration, error) {
	conn, err := c.dial(ctx, u, addr, tlsCfg)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	req := buildBaselineRequest(u.Host)
	start := time.Now()
	if err := writeAllDeadline(conn, []byte(req), smugglingProbeTimeout); err != nil {
		return 0, err
	}
	if _, err := readResponseHead(conn, smugglingProbeTimeout); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// runVariant dispatches to the right wire path (HTTP/1.1 vs HTTP/2)
// for the variant, sends the probe, and returns the wall-clock latency
// observed. Transport errors are returned to the caller; a probe that
// completes with any HTTP response (including 4xx/5xx) is a successful
// measurement.
func (c *RequestSmuggling) runVariant(ctx context.Context, u *url.URL, addr string, tlsCfg *tls.Config, v smugglingVariant) (time.Duration, error) {
	switch v.proto {
	case smugglingProtoHTTP1:
		return c.runHTTP1Variant(ctx, u, addr, tlsCfg, v)
	case smugglingProtoHTTP2:
		return c.runHTTP2Variant(ctx, u, addr, tlsCfg, v)
	default:
		return 0, fmt.Errorf("unknown proto %d", v.proto)
	}
}

func (c *RequestSmuggling) runHTTP1Variant(ctx context.Context, u *url.URL, addr string, tlsCfg *tls.Config, v smugglingVariant) (time.Duration, error) {
	conn, err := c.dial(ctx, u, addr, tlsCfg)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	req := v.buildHTTP1(u.Host)
	start := time.Now()
	if err := writeAllDeadline(conn, []byte(req), smugglingProbeTimeout); err != nil {
		return 0, err
	}
	if _, err := readResponseHead(conn, smugglingProbeTimeout); err != nil {
		// A read timeout IS the hang signal we are looking for: the
		// back-end is waiting for bytes that aren't coming, so the
		// front-end never produces a response within smugglingProbeTimeout.
		// Cap the reported latency at the timeout so the oracle has a
		// concrete number to compare; on the wire we have observed the
		// hang either way.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return smugglingProbeTimeout, nil
		}
		return 0, err
	}
	return time.Since(start), nil
}

func (c *RequestSmuggling) dial(ctx context.Context, u *url.URL, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	if u.Scheme == "https" {
		// Clone so the http/1.1 probes don't carry the "h2" ALPN entry
		// the H2 path needs; a server that supports h2 will otherwise
		// pick it and break our hand-crafted HTTP/1.1 bytes.
		cfg := tlsCfg.Clone()
		cfg.NextProtos = []string{"http/1.1"}
		return smugglingDialTLS(ctx, addr, cfg)
	}
	return smugglingDialPlain(ctx, addr)
}

// negotiateALPN performs a one-shot TLS handshake and returns the
// negotiated ALPN protocol. Used only to decide whether the H2.CL
// variant is worth attempting against this host; we don't reuse the
// resulting connection because the H2 probe needs to open its own
// session anyway.
func (c *RequestSmuggling) negotiateALPN(ctx context.Context, addr string, tlsCfg *tls.Config) (string, error) {
	conn, err := smugglingDialTLS(ctx, addr, tlsCfg)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if tc, ok := conn.(*tls.Conn); ok {
		return tc.ConnectionState().NegotiatedProtocol, nil
	}
	return "", nil
}

// smugglingProto identifies which wire protocol a variant uses. We
// keep this as a small enum rather than two parallel variant types
// because the per-variant metadata (label, detail) is identical
// regardless of protocol.
type smugglingProto int

const (
	smugglingProtoHTTP1 smugglingProto = iota + 1
	smugglingProtoHTTP2
)

// smugglingVariant describes one desync probe: a label, the wire
// protocol it runs on, a builder for the HTTP/1.1 bytes (used when
// proto == smugglingProtoHTTP1), and a builder for the HTTP/2 frame
// payload (used when proto == smugglingProtoHTTP2). Exactly one
// builder is populated per instance; the other is nil and never
// called.
type smugglingVariant struct {
	label       string
	frontEnd    string // "Content-Length" / "Transfer-Encoding" / "HTTP/2"
	backEnd     string
	proto       smugglingProto
	buildHTTP1  func(host string) string
	buildHTTP2  func(host string) (headers []hpack.HeaderField, data []byte)
	description string
}

func variantCLTE() smugglingVariant {
	return smugglingVariant{
		label:    "CL.TE",
		frontEnd: "Content-Length",
		backEnd:  "Transfer-Encoding: chunked",
		proto:    smugglingProtoHTTP1,
		buildHTTP1: func(host string) string {
			// Body wire bytes: "1\r\nA\r\nX". Front-end CL=4 reads
			// "1\r\nA" and forwards. Back-end TE reads chunk size 1,
			// chunk data "A", expects "\r\n" terminator but the bytes
			// after it have been truncated -> hangs waiting for the
			// next chunk header.
			body := "1\r\nA\r\nX"
			return buildHTTP1RequestRaw(host, http.MethodPost,
				[]string{
					"Content-Length: 4",
					"Transfer-Encoding: chunked",
				}, body)
		},
		description: "front-end uses Content-Length, back-end uses Transfer-Encoding",
	}
}

func variantTECL() smugglingVariant {
	return smugglingVariant{
		label:    "TE.CL",
		frontEnd: "Transfer-Encoding: chunked",
		backEnd:  "Content-Length",
		proto:    smugglingProtoHTTP1,
		buildHTTP1: func(host string) string {
			// Body wire bytes: "0\r\n\r\n" (5 bytes). Front-end TE
			// reads it as a complete zero-chunk message and forwards.
			// Back-end CL=6 expects 6 bytes -> hangs waiting for the
			// missing sixth byte.
			body := "0\r\n\r\n"
			return buildHTTP1RequestRaw(host, http.MethodPost,
				[]string{
					"Content-Length: 6",
					"Transfer-Encoding: chunked",
				}, body)
		},
		description: "front-end uses Transfer-Encoding: chunked, back-end uses Content-Length",
	}
}

func variantH2CL() smugglingVariant {
	return smugglingVariant{
		label:    "H2.CL",
		frontEnd: "HTTP/2 content-length",
		backEnd:  "HTTP/1.1 Content-Length",
		proto:    smugglingProtoHTTP2,
		buildHTTP2: func(host string) ([]hpack.HeaderField, []byte) {
			// H2 request claims content-length: 6 but DATA frame
			// carries 5 bytes. An H2->H1 front-end translates the
			// pseudo-header into a CL line on the down-stream request
			// but only forwards the bytes it actually received -> back-end
			// CL parser hangs.
			data := []byte("AAAAA")
			headers := []hpack.HeaderField{
				{Name: ":method", Value: http.MethodPost},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: host},
				{Name: ":path", Value: "/"},
				{Name: "content-length", Value: "6"},
				{Name: "content-type", Value: "application/octet-stream"},
			}
			return headers, data
		},
		description: "HTTP/2 front-end downgrades to HTTP/1.1 back-end without rewriting content-length",
	}
}

// buildHTTP1RequestRaw assembles a raw HTTP/1.1 request with the given
// extra headers and body. Connection: close keeps the back-end from
// trying to wedge follow-on requests onto the same socket once it
// realizes the framing was wrong, which prunes some non-vulnerable
// stacks from the false-positive set (a back-end that simply drops the
// connection at the framing error answers in <1s rather than hanging).
func buildHTTP1RequestRaw(host, method string, extraHeaders []string, body string) string {
	var b strings.Builder
	b.WriteString(method)
	b.WriteString(" / HTTP/1.1\r\n")
	b.WriteString("Host: ")
	b.WriteString(host)
	b.WriteString("\r\n")
	b.WriteString("User-Agent: hyperz-smuggling-probe\r\n")
	b.WriteString("Accept: */*\r\n")
	b.WriteString("Connection: close\r\n")
	for _, h := range extraHeaders {
		b.WriteString(h)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

// buildBaselineRequest is a minimal well-formed GET / used to learn
// the target's response-time floor before probing. Connection: close
// matches the probe transport so the baseline includes the full TCP
// (and TLS) cost, not the cheap-second-request cost an httpclient
// pool would amortize.
func buildBaselineRequest(host string) string {
	return "GET / HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: hyperz-smuggling-probe\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n" +
		"\r\n"
}

// writeAllDeadline writes b to conn under a wall-clock deadline. A
// stalled write on a probe that the back-end isn't reading would
// otherwise pin the worker indefinitely; the same deadline that bounds
// the read covers the write side too.
func writeAllDeadline(conn net.Conn, b []byte, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	_, err := conn.Write(b)
	return err
}

// readResponseHead reads the HTTP/1.1 status line and headers from
// conn under a deadline, returning whatever bytes were captured. We
// intentionally don't parse beyond the headers: the timing signal is
// the wall-clock cost of getting any response at all, and reading
// the body would dilute it with the body-stream latency.
//
// On a real hang, this returns a net timeout error, which the caller
// interprets as confirmation of the desync and reports as a probe
// latency capped at the timeout.
func readResponseHead(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	r := bufio.NewReader(io.LimitReader(conn, smugglingReadCap))
	// Status line.
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	out := []byte(line)
	// Headers, terminated by an empty line.
	for {
		hl, err := r.ReadString('\n')
		if err != nil {
			return out, err
		}
		out = append(out, hl...)
		trim := strings.TrimRight(hl, "\r\n")
		if trim == "" {
			return out, nil
		}
	}
}

func splitHostPortDefault(u *url.URL) (host, port string) {
	host = u.Hostname()
	port = u.Port()
	if port != "" {
		return host, port
	}
	if u.Scheme == "https" {
		return host, "443"
	}
	return host, "80"
}

// runHTTP2Variant opens a fresh h2 session, sends the smuggling
// HEADERS + DATA frame pair, and times the wall clock until the
// back-end produces a response (or the deadline expires).
//
// We hand-roll the frame writer rather than reusing http2.Transport
// because Transport refuses to emit a request whose declared
// content-length disagrees with the bytes written, which is precisely
// the property we want to test. HPACK encoding is borrowed from
// x/net/http2/hpack so we don't reimplement table state.
func (c *RequestSmuggling) runHTTP2Variant(ctx context.Context, u *url.URL, addr string, tlsCfg *tls.Config, v smugglingVariant) (time.Duration, error) {
	cfg := tlsCfg.Clone()
	cfg.NextProtos = []string{"h2"}
	conn, err := smugglingDialTLS(ctx, addr, cfg)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok || tc.ConnectionState().NegotiatedProtocol != "h2" {
		return 0, errors.New("h2 not negotiated")
	}

	if err := conn.SetDeadline(time.Now().Add(smugglingProbeTimeout)); err != nil {
		return 0, err
	}

	// Connection preface: every HTTP/2 client must send this exact
	// magic string before the first frame so the server knows we're
	// speaking h2 and not something that downgraded over ALPN.
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if _, err := conn.Write([]byte(preface)); err != nil {
		return 0, err
	}
	// Initial SETTINGS frame: empty (accept defaults) so the server's
	// SETTINGS_ACK confirms the session is alive before we send the
	// probe. We don't actually wait for the ACK explicitly - the
	// server's response (or timeout) is the signal we care about.
	if err := writeH2Frame(conn, frameSettings, 0, 0, nil); err != nil {
		return 0, err
	}

	headers, data := v.buildHTTP2(u.Host)
	encoded := encodeH2Headers(headers)

	// HEADERS frame: stream 1, END_HEADERS but NOT END_STREAM (we
	// still have a DATA frame coming).
	const flagEndHeaders = 0x4
	const flagEndStream = 0x1
	const streamID = 1
	start := time.Now()
	if err := writeH2Frame(conn, frameHeaders, flagEndHeaders, streamID, encoded); err != nil {
		return 0, err
	}
	// DATA frame: closes the stream with END_STREAM. The byte count
	// here deliberately disagrees with the content-length pseudo-header
	// so the H2->H1 downgrade leaves the back-end short.
	if err := writeH2Frame(conn, frameData, flagEndStream, streamID, data); err != nil {
		return 0, err
	}

	// Read response frames until we see one for our stream (HEADERS
	// or RST_STREAM) or the deadline expires.
	if err := readH2Response(conn, streamID); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return smugglingProbeTimeout, nil
		}
		return 0, err
	}
	return time.Since(start), nil
}

// HTTP/2 frame types we care about. The spec assigns more, but the
// detection path only writes SETTINGS/HEADERS/DATA and reads
// HEADERS/RST_STREAM/GOAWAY/PING/SETTINGS, so we keep the constants
// scoped rather than dragging in the full http2 client.
const (
	frameData    byte = 0x0
	frameHeaders byte = 0x1
	// frameRSTStream is used in readH2Response only.
	frameRSTStream byte = 0x3
	frameSettings  byte = 0x4
	frameGoaway    byte = 0x7
)

// writeH2Frame writes one HTTP/2 frame to conn. Payload length is
// inferred from len(payload); a payload longer than 2^24-1 panics
// rather than silently truncating, but smuggling probes never come
// close to that ceiling so the check is defensive only.
func writeH2Frame(conn net.Conn, ftype, flags byte, streamID uint32, payload []byte) error {
	if len(payload) > (1<<24)-1 {
		return errors.New("http2 frame payload too large")
	}
	hdr := make([]byte, 9)
	hdr[0] = byte(len(payload) >> 16)
	hdr[1] = byte(len(payload) >> 8)
	hdr[2] = byte(len(payload))
	hdr[3] = ftype
	hdr[4] = flags
	// Stream ID is 31 bits; the top bit is reserved and must be zero.
	binary.BigEndian.PutUint32(hdr[5:9], streamID&0x7fffffff)
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := conn.Write(payload)
	return err
}

// encodeH2Headers compresses h into an HPACK header block. A fresh
// encoder per request is fine for a probe: we send exactly one
// HEADERS frame and never index across requests, so any dynamic-table
// savings would be wasted.
func encodeH2Headers(h []hpack.HeaderField) []byte {
	var buf strings.Builder
	enc := hpack.NewEncoder(&hpackWriter{b: &buf})
	for _, hf := range h {
		_ = enc.WriteField(hf)
	}
	return []byte(buf.String())
}

// hpackWriter adapts strings.Builder to the io.Writer interface that
// hpack.NewEncoder expects. strings.Builder.Write already implements
// it, but the encoder takes an io.Writer concrete value; this shim
// keeps the call site narrow without leaking a *bytes.Buffer.
type hpackWriter struct{ b *strings.Builder }

func (w *hpackWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

// readH2Response reads frames from conn until one targeting streamID
// arrives (HEADERS = the back-end replied; RST_STREAM = the server
// rejected the request, which is the answer we are timing against)
// or the read deadline trips. SETTINGS, PING, and connection-level
// GOAWAY frames are silently consumed so we don't mistake the
// server's preface frames for our response.
func readH2Response(conn net.Conn, streamID uint32) error {
	for {
		ftype, _, sid, payload, err := readH2Frame(conn)
		if err != nil {
			return err
		}
		switch ftype {
		case frameHeaders, frameRSTStream:
			if sid == streamID {
				return nil
			}
		case frameGoaway:
			// Server is closing the connection. Treat as a response:
			// the back-end clearly is not hanging.
			return nil
		default:
			// SETTINGS / PING / WINDOW_UPDATE / etc.: ignore and keep
			// reading. The payload variable is consumed so the framer
			// stays aligned.
			_ = payload
		}
	}
}

// readH2Frame parses one HTTP/2 frame header + payload. Returns the
// raw payload bytes and the frame type/flags/stream ID. A short read
// on the header or payload is propagated to the caller, which
// distinguishes a timeout (the hang signal) from a genuine framing
// error.
func readH2Frame(conn net.Conn) (ftype, flags byte, streamID uint32, payload []byte, err error) {
	var hdr [9]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	length := uint32(hdr[0])<<16 | uint32(hdr[1])<<8 | uint32(hdr[2])
	ftype = hdr[3]
	flags = hdr[4]
	streamID = binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff
	if length == 0 {
		return ftype, flags, streamID, nil, nil
	}
	if length > smugglingReadCap {
		// A pathologically large frame would chew memory for no
		// useful information; discard the payload by reading into a
		// throwaway buffer.
		payload = make([]byte, smugglingReadCap)
		if _, err = io.ReadFull(conn, payload); err != nil {
			return 0, 0, 0, nil, err
		}
		// Drain the remainder.
		remaining := int64(length) - int64(smugglingReadCap)
		if _, err = io.CopyN(io.Discard, conn, remaining); err != nil {
			return 0, 0, 0, nil, err
		}
		return ftype, flags, streamID, payload, nil
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(conn, payload); err != nil {
		return 0, 0, 0, nil, err
	}
	return ftype, flags, streamID, payload, nil
}

// buildFinding assembles the per-host finding once a variant has
// confirmed on both probe attempts. Severity is High: a confirmed
// front/back parser disagreement is reliably exploitable for cache
// poisoning, request hijacking, and security-control bypass, and
// remediation usually requires a coordinated change on the proxy
// stack rather than an application patch.
func (c *RequestSmuggling) buildFinding(u *url.URL, v smugglingVariant, baseline, probe1, probe2 time.Duration) *Finding {
	target := u.Scheme + "://" + u.Host
	detail := fmt.Sprintf(
		"The front-end and back-end disagree on request framing (%s variant: %s). "+
			"A timing-only probe induced a back-end hang on two independent attempts "+
			"(baseline %s, probe-1 %s, probe-2 %s); the threshold for confirmation "+
			"was %s above baseline. An attacker can exploit this disagreement to "+
			"smuggle a request prefix onto another user's connection, enabling "+
			"cache poisoning, header injection, session fixation, and bypass of "+
			"front-end security controls (WAF, auth proxies, ACLs).",
		v.label, v.description,
		baseline.Round(time.Millisecond),
		probe1.Round(time.Millisecond),
		probe2.Round(time.Millisecond),
		smugglingHangThreshold,
	)
	return &Finding{
		Check:    c.Name(),
		Target:   target,
		URL:      target,
		Severity: SeverityHigh,
		Title:    fmt.Sprintf("HTTP request smuggling (%s desynchronization)", v.label),
		Detail:   detail,
		CWE:      "CWE-444",
		OWASP:    "A03:2021 Injection",
		Remediation: "Normalize request framing at the front-end: reject any HTTP/1.1 request that " +
			"carries both Content-Length and Transfer-Encoding, and reject any Transfer-Encoding " +
			"value other than \"chunked\". For HTTP/2 front-ends, validate that content-length matches " +
			"the actual DATA frame size before downgrading to an HTTP/1.1 back-end, or use HTTP/2 end-to-end. " +
			"Configure both front-end and back-end to use identical HTTP parsers where possible, and " +
			"disable HTTP keep-alive on the front-to-back connection if the framing risk cannot be " +
			"eliminated at the parser level.",
		Evidence: &Evidence{
			Method:     http.MethodPost,
			RequestURL: target,
			Snippet: fmt.Sprintf(
				"Variant: %s (front=%s, back=%s)\n"+
					"Baseline: %s\nProbe 1:  %s\nProbe 2:  %s\nThreshold: %s above baseline (or absolute floor)\n",
				v.label, v.frontEnd, v.backEnd,
				baseline.Round(time.Millisecond),
				probe1.Round(time.Millisecond),
				probe2.Round(time.Millisecond),
				smugglingHangThreshold,
			),
		},
		DedupeKey: MakeKey(c.Name(), ScopeHost, target, v.label),
	}
}
