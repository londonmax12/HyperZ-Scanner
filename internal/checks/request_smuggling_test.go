package checks

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestRequestSmugglingName(t *testing.T) {
	c := &RequestSmuggling{}
	if got := c.Name(); got != "request-smuggling" {
		t.Fatalf("Name = %q, want request-smuggling", got)
	}
}

func TestRequestSmugglingLevel(t *testing.T) {
	c := &RequestSmuggling{}
	if got := c.Level(); got != LevelAggressive {
		t.Fatalf("Level = %v, want aggressive", got)
	}
}

func TestRequestSmugglingBudget(t *testing.T) {
	// Confirms the Budgeted interface is honored - DefaultBudget (60s)
	// is too tight for back-to-back probes that can each hang up to
	// the configured probe timeout.
	c := &RequestSmuggling{}
	if got := c.Budget(); got <= DefaultBudget {
		t.Errorf("Budget = %v, want > DefaultBudget (%v)", got, DefaultBudget)
	}
}

// withTestSmugglingTimings dials the production hang threshold, probe
// timeout, and confirmation jitter down to test-friendly values so a
// probe that genuinely hangs takes ~100ms and the confirm gap is ~10ms
// instead of 5s/1.5s. Restores on cleanup.
func withTestSmugglingTimings(t *testing.T) {
	t.Helper()
	origHang := smugglingHangThreshold
	origTimeout := smugglingProbeTimeout
	origConfirm := smugglingConfirmDelay
	smugglingHangThreshold = 100 * time.Millisecond
	smugglingProbeTimeout = 250 * time.Millisecond
	smugglingConfirmDelay = 10 * time.Millisecond
	t.Cleanup(func() {
		smugglingHangThreshold = origHang
		smugglingProbeTimeout = origTimeout
		smugglingConfirmDelay = origConfirm
	})
}

// withTestSmugglingDial points the production raw-socket dialer at the
// given address, restoring the production dialer on cleanup. The check
// only ever calls smugglingDialPlain in tests (we never construct an
// https URL against the mock).
func withTestSmugglingDial(t *testing.T, addr string) {
	t.Helper()
	origPlain := smugglingDialPlain
	smugglingDialPlain = func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	t.Cleanup(func() { smugglingDialPlain = origPlain })
}

// smugglingMockMode controls how the mock front-end responds to probe
// requests. The mock recognises both CL.TE and TE.CL probe shapes by
// their declared headers; everything else (including baseline GETs)
// answers fast with 200 OK.
type smugglingMockMode int

const (
	// mockSafe responds quickly to every request, including the
	// malformed smuggling probes. Used for "no finding" assertions.
	mockSafe smugglingMockMode = iota
	// mockVulnerableCLTE hangs after reading a probe whose headers
	// shape matches CL.TE (both CL and TE: chunked present, CL <= 6).
	// All other requests, including TE.CL probes, answer fast.
	mockVulnerableCLTE
	// mockVulnerableTECL hangs after reading a probe whose headers
	// shape matches TE.CL. All other requests answer fast.
	mockVulnerableTECL
	// mockVulnerableAny hangs on either HTTP/1 probe shape. Used to
	// confirm the check returns after the first variant confirms
	// rather than probing every variant on a known-vulnerable host.
	mockVulnerableAny
)

// startSmugglingMock spins up a TCP listener that speaks raw HTTP/1.1.
// It returns the host:port the listener bound to and a stop function
// the test must call. Each connection is handled on its own goroutine
// and read line-by-line so the mock can decide whether to respond
// based on the request headers it has seen.
func startSmugglingMock(t *testing.T, mode smugglingMockMode) (addr string, probeCount *int32, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var count int32
	var wg sync.WaitGroup
	done := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				handleSmugglingConn(c, mode, &count, done)
			}(conn)
		}
	}()

	stop = func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), &count, stop
}

// handleSmugglingConn reads one HTTP/1.1 request off conn and decides
// how to respond based on the configured mock mode and the request
// headers. A "vulnerable" mode for the matching probe shape blocks
// without responding until done fires; the check's read deadline
// then trips and counts as a confirmed hang.
func handleSmugglingConn(conn net.Conn, mode smugglingMockMode, count *int32, done chan struct{}) {
	r := bufio.NewReader(conn)
	// Status line.
	statusLine, err := r.ReadString('\n')
	if err != nil {
		return
	}
	hasCL := false
	hasTE := false
	cl := 0
	for {
		hl, err := r.ReadString('\n')
		if err != nil {
			return
		}
		trim := strings.TrimRight(hl, "\r\n")
		if trim == "" {
			break
		}
		low := strings.ToLower(trim)
		if strings.HasPrefix(low, "content-length:") {
			hasCL = true
			fmt.Sscanf(strings.TrimSpace(trim[len("Content-Length:"):]), "%d", &cl)
		}
		if strings.HasPrefix(low, "transfer-encoding:") &&
			strings.Contains(low, "chunked") {
			hasTE = true
		}
	}
	atomic.AddInt32(count, 1)

	isProbe := hasCL && hasTE
	// Decide whether this request shape should hang under the
	// configured mode. CL.TE probes use CL=4 (a low value); TE.CL
	// probes use CL=6. We use the CL value as the disambiguator
	// since the headers alone don't tell us which side claims which.
	hang := false
	switch mode {
	case mockVulnerableCLTE:
		hang = isProbe && cl == 4
	case mockVulnerableTECL:
		hang = isProbe && cl == 6
	case mockVulnerableAny:
		hang = isProbe
	}

	if hang {
		// Consume any remaining body bytes so the client's write
		// completes, then block. The check's read deadline fires
		// after smugglingProbeTimeout; we wake up when the test's
		// stop closes done.
		go func() {
			io.Copy(io.Discard, r)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		return
	}

	// Fast 200 response. Crucially we do NOT attempt to drain the
	// body before responding: a malformed probe whose declared
	// Content-Length disagrees with the bytes on the wire would
	// otherwise wedge the mock here, and that hang is exactly the
	// signal the check is testing for. A real "safe" front-end
	// either rejects CL/TE conflicts up front or normalizes them;
	// responding without draining mimics the former.
	_ = statusLine
	_ = hasCL
	_ = hasTE
	_ = cl
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 2\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		"ok"
	_, _ = conn.Write([]byte(resp))
}

func TestRequestSmuggling_CLTE_HangFiresFinding(t *testing.T) {
	withTestSmugglingTimings(t)
	addr, _, stop := startSmugglingMock(t, mockVulnerableCLTE)
	defer stop()
	withTestSmugglingDial(t, addr)

	c := &RequestSmuggling{}
	target := "http://" + addr + "/"
	findings, err := c.Run(context.Background(), nil, nil, page.Page{URL: target})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Check != "request-smuggling" {
		t.Errorf("Check = %q", f.Check)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if !strings.Contains(f.Title, "CL.TE") {
		t.Errorf("Title = %q, want CL.TE in title", f.Title)
	}
	if f.Evidence == nil || !strings.Contains(f.Evidence.Snippet, "CL.TE") {
		t.Errorf("Evidence missing CL.TE marker: %+v", f.Evidence)
	}
}

func TestRequestSmuggling_TECL_HangFiresFinding(t *testing.T) {
	withTestSmugglingTimings(t)
	addr, _, stop := startSmugglingMock(t, mockVulnerableTECL)
	defer stop()
	withTestSmugglingDial(t, addr)

	c := &RequestSmuggling{}
	target := "http://" + addr + "/"
	findings, err := c.Run(context.Background(), nil, nil, page.Page{URL: target})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Title, "TE.CL") {
		t.Errorf("Title = %q, want TE.CL", findings[0].Title)
	}
}

func TestRequestSmuggling_SafeTargetEmitsNothing(t *testing.T) {
	withTestSmugglingTimings(t)
	addr, _, stop := startSmugglingMock(t, mockSafe)
	defer stop()
	withTestSmugglingDial(t, addr)

	c := &RequestSmuggling{}
	target := "http://" + addr + "/"
	findings, err := c.Run(context.Background(), nil, nil, page.Page{URL: target})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: %+v", len(findings), findings)
	}
}

func TestRequestSmuggling_PerHostCaching(t *testing.T) {
	withTestSmugglingTimings(t)
	addr, probeCount, stop := startSmugglingMock(t, mockSafe)
	defer stop()
	withTestSmugglingDial(t, addr)

	c := &RequestSmuggling{}
	pages := []string{
		"http://" + addr + "/",
		"http://" + addr + "/about",
		"http://" + addr + "/contact",
	}
	for _, target := range pages {
		_, err := c.Run(context.Background(), nil, nil, page.Page{URL: target})
		if err != nil {
			t.Fatalf("Run(%s): %v", target, err)
		}
	}
	// The host was evaluated once; subsequent calls hit the cache and
	// dispatch zero new probes. We allow a small ceiling rather than
	// pinning to an exact count because the baseline takes multiple
	// samples and a sample failure can prompt one retry slot.
	if got := atomic.LoadInt32(probeCount); got > 8 {
		t.Errorf("probeCount = %d, want <=8 (cache should suppress re-probe)", got)
	}
}

func TestRequestSmuggling_VulnerableHostCachedFindingRebasesURL(t *testing.T) {
	withTestSmugglingTimings(t)
	addr, _, stop := startSmugglingMock(t, mockVulnerableCLTE)
	defer stop()
	withTestSmugglingDial(t, addr)

	c := &RequestSmuggling{}
	first := "http://" + addr + "/"
	second := "http://" + addr + "/orders/123"

	f1, err := c.Run(context.Background(), nil, nil, page.Page{URL: first})
	if err != nil || len(f1) != 1 {
		t.Fatalf("first run: err=%v findings=%d", err, len(f1))
	}
	f2, err := c.Run(context.Background(), nil, nil, page.Page{URL: second})
	if err != nil || len(f2) != 1 {
		t.Fatalf("second run: err=%v findings=%d", err, len(f2))
	}
	if f2[0].URL != second {
		t.Errorf("cached finding URL = %q, want %q", f2[0].URL, second)
	}
	if f2[0].Target != second {
		t.Errorf("cached finding Target = %q, want %q", f2[0].Target, second)
	}
	// DedupeKey is per-host and shouldn't change just because the
	// cached finding got re-emitted against a different page URL.
	if f1[0].DedupeKey != f2[0].DedupeKey {
		t.Errorf("dedupe drifted across pages: %q vs %q", f1[0].DedupeKey, f2[0].DedupeKey)
	}
}

func TestRequestSmuggling_OutOfScopeSkipped(t *testing.T) {
	withTestSmugglingTimings(t)
	// No dial override: a probe attempt would dial 127.0.0.1:0 and
	// fail. The scope gate should short-circuit before any dial.
	withTestSmugglingDial(t, "127.0.0.1:1")

	sc, err := scope.New(scope.Config{Hosts: []string{"in-scope.example"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	c := &RequestSmuggling{}
	findings, err := c.Run(context.Background(), nil, sc, page.Page{URL: "http://out-of-scope.example/"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 (out of scope)", len(findings))
	}
}

func TestRequestSmuggling_MalformedURLReturnsCleanly(t *testing.T) {
	c := &RequestSmuggling{}
	findings, err := c.Run(context.Background(), nil, nil, page.Page{URL: "::not a url::"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
	// File URLs aren't probable HTTP targets and should fall through.
	findings, err = c.Run(context.Background(), nil, nil, page.Page{URL: "file:///etc/passwd"})
	if err != nil {
		t.Fatalf("Run file: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("file scheme findings = %d, want 0", len(findings))
	}
}

func TestTimingHit_AbsoluteFloorRejectsFastProbe(t *testing.T) {
	// Even a probe that is 10x the baseline should not count if it
	// finished below the absolute hang threshold: a 50ms vs 5ms ratio
	// is jitter on a fast host, not desync.
	c := &RequestSmuggling{}
	if c.timingHit(5*time.Millisecond, 50*time.Millisecond) {
		t.Fatal("timingHit fired below smugglingHangThreshold")
	}
}

func TestTimingHit_FiresWhenBothRelativeAndAbsoluteCross(t *testing.T) {
	c := &RequestSmuggling{}
	// Set test thresholds so the test isn't pinned to production.
	origHang := smugglingHangThreshold
	smugglingHangThreshold = 100 * time.Millisecond
	t.Cleanup(func() { smugglingHangThreshold = origHang })

	if !c.timingHit(5*time.Millisecond, 200*time.Millisecond) {
		t.Fatal("timingHit did not fire on a clear hang signal")
	}
}

func TestBuildHTTP1RequestRaw_FramingShape(t *testing.T) {
	got := buildHTTP1RequestRaw("example.com", "POST",
		[]string{"Content-Length: 4", "Transfer-Encoding: chunked"},
		"1\r\nA\r\nX")
	// Spot-check the framing the back-end will see, since this is
	// what makes or breaks the entire detection. CRLF, mandatory
	// headers in order, headers followed by an empty line, body as-is.
	wantPrefix := "POST / HTTP/1.1\r\nHost: example.com\r\n"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("missing request-line prefix:\n%q", got)
	}
	if !strings.Contains(got, "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX") {
		t.Errorf("malformed CL/TE/body framing:\n%q", got)
	}
}

func TestReadResponseHead_StopsAtBlankLine(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })

	go func() {
		fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Trailing: yes\r\n\r\nhello")
		// Hold the conn open so the test can see we stopped at the
		// blank line rather than consuming the body.
		time.Sleep(50 * time.Millisecond)
	}()

	got, err := readResponseHead(client, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("readResponseHead: %v", err)
	}
	s := string(got)
	if !strings.Contains(s, "HTTP/1.1 200 OK") {
		t.Errorf("missing status line: %q", s)
	}
	if !strings.Contains(s, "X-Trailing: yes") {
		t.Errorf("missing tail header: %q", s)
	}
	if strings.Contains(s, "hello") {
		t.Errorf("readResponseHead consumed body: %q", s)
	}
}

func TestEncodeH2Headers_RoundTripsThroughDecoder(t *testing.T) {
	// Confirm the HPACK encoder we wired produces bytes a vanilla
	// decoder can parse back. Without this, a typo in hpackWriter
	// (e.g. dropping bytes) would silently break the H2.CL probe
	// against every target.
	if got := encodeH2Headers(nil); len(got) != 0 {
		t.Errorf("empty input produced %d bytes, want 0", len(got))
	}
	in := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/"},
		{Name: "content-length", Value: "6"},
	}
	encoded := encodeH2Headers(in)
	if len(encoded) == 0 {
		t.Fatal("encodeH2Headers returned empty bytes for non-empty input")
	}
	// Decode and confirm each field round-tripped.
	dec := hpack.NewDecoder(4096, nil)
	got, err := dec.DecodeFull(encoded)
	if err != nil {
		t.Fatalf("DecodeFull: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("decoded %d fields, want %d", len(got), len(in))
	}
	for i := range in {
		if got[i].Name != in[i].Name || got[i].Value != in[i].Value {
			t.Errorf("field %d: got %q=%q, want %q=%q",
				i, got[i].Name, got[i].Value, in[i].Name, in[i].Value)
		}
	}
}

// selfSignedH2Cert mints a throwaway ECDSA cert good for one hour and
// loopback IPs. The H2 mock listener serves this; the check accepts it
// because evaluateHost's tlsCfg sets InsecureSkipVerify.
func selfSignedH2Cert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hyperz-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// withTestSmugglingDialTLS redirects the production TLS dialer to the
// given mock address while honoring the caller's tls.Config (so the h2
// ALPN entry from runHTTP2Variant still flows through to the handshake).
// Restores on cleanup.
func withTestSmugglingDialTLS(t *testing.T, mockAddr string) {
	t.Helper()
	origTLS := smugglingDialTLS
	smugglingDialTLS = func(ctx context.Context, _ string, cfg *tls.Config) (net.Conn, error) {
		d := &net.Dialer{Timeout: smugglingDialTimeout}
		return tls.DialWithDialer(d, "tcp", mockAddr, cfg)
	}
	t.Cleanup(func() { smugglingDialTLS = origTLS })
}

// startH2Mock spins up a TLS listener that speaks HTTP/2. It reads the
// connection preface and frames until it sees HEADERS+DATA on one
// stream, then either hangs (vulnerable mode) or sends back a fast
// :status 200 HEADERS frame.
func startH2Mock(t *testing.T, vulnerable bool) (addr string, stop func()) {
	t.Helper()
	cert := selfSignedH2Cert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				handleH2MockConn(c, vulnerable, done)
			}(conn)
		}
	}()
	stop = func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), stop
}

// handleH2MockConn implements the server side of the H2 probe: read
// preface, emit our SETTINGS, then read frames until we have HEADERS
// and DATA on one stream. For vulnerable mode we then block; for safe
// mode we emit a :status 200 HEADERS frame so the probe completes fast.
func handleH2MockConn(conn net.Conn, vulnerable bool, done chan struct{}) {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	preface := make([]byte, 24)
	if _, err := io.ReadFull(conn, preface); err != nil {
		return
	}
	if err := writeH2Frame(conn, frameSettings, 0, 0, nil); err != nil {
		return
	}
	var streamID uint32
	seenHeaders, seenData := false, false
	for !(seenHeaders && seenData) {
		ftype, _, sid, _, err := readH2Frame(conn)
		if err != nil {
			return
		}
		switch ftype {
		case frameHeaders:
			if !seenHeaders {
				streamID = sid
				seenHeaders = true
			}
		case frameData:
			if sid == streamID {
				seenData = true
			}
		}
	}
	if vulnerable {
		// Clear the deadline and block: the probe's read deadline will
		// trip first and that timeout is the hang signal we are
		// simulating. The done channel lets the test tear us down.
		_ = conn.SetDeadline(time.Time{})
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		return
	}
	var sb strings.Builder
	enc := hpack.NewEncoder(&hpackWriter{b: &sb})
	_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	payload := []byte(sb.String())
	const flagEndHeaders = 0x4
	const flagEndStream = 0x1
	_ = writeH2Frame(conn, frameHeaders, flagEndHeaders|flagEndStream, streamID, payload)
}

func TestRequestSmuggling_H2CL_VulnerableHangFiresFinding(t *testing.T) {
	withTestSmugglingTimings(t)
	addr, stop := startH2Mock(t, true)
	defer stop()
	withTestSmugglingDialTLS(t, addr)

	c := &RequestSmuggling{}
	u, err := url.Parse("https://" + addr + "/")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	tlsCfg := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}
	d, err := c.runHTTP2Variant(context.Background(), u, addr, tlsCfg, variantH2CL())
	if err != nil {
		t.Fatalf("runHTTP2Variant: %v", err)
	}
	if d < smugglingHangThreshold {
		t.Errorf("h2 vulnerable probe took %v, want >= %v (hang signal)", d, smugglingHangThreshold)
	}
}

func TestRequestSmuggling_H2CL_SafeRespondsFast(t *testing.T) {
	withTestSmugglingTimings(t)
	addr, stop := startH2Mock(t, false)
	defer stop()
	withTestSmugglingDialTLS(t, addr)

	c := &RequestSmuggling{}
	u, err := url.Parse("https://" + addr + "/")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	tlsCfg := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}
	d, err := c.runHTTP2Variant(context.Background(), u, addr, tlsCfg, variantH2CL())
	if err != nil {
		t.Fatalf("runHTTP2Variant: %v", err)
	}
	if d >= smugglingHangThreshold {
		t.Errorf("h2 safe probe took %v, want < %v (fast response)", d, smugglingHangThreshold)
	}
}

func TestRequestSmuggling_PreCancelledContextBailsFast(t *testing.T) {
	withTestSmugglingTimings(t)
	// Use a mock that would hang on every probe shape: if the cancel
	// were ignored, this test would block on smugglingProbeTimeout
	// per variant. Returning fast proves the variant loop and the
	// confirmation gap both honor ctx.
	addr, _, stop := startSmugglingMock(t, mockVulnerableAny)
	defer stop()
	withTestSmugglingDial(t, addr)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := &RequestSmuggling{}
	start := time.Now()
	findings, err := c.Run(ctx, nil, nil, page.Page{URL: "http://" + addr + "/"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0 (cancelled)", len(findings))
	}
	// Pre-cancelled ctx should bail before any probe latency accrues.
	// Generous ceiling because the goroutine still does a tiny amount
	// of setup before checking ctx.
	if elapsed > 200*time.Millisecond {
		t.Errorf("Run with pre-cancelled ctx took %v, want < 200ms", elapsed)
	}
	// And critically: a cancel must not poison the cache. A later
	// fresh-ctx call against the same host should re-evaluate.
	c.mu.Lock()
	_, cached := c.cache["http://"+addr]
	c.mu.Unlock()
	if cached {
		t.Errorf("cache populated after cancellation - subsequent scans would skip this host")
	}
}

// readSmugglingMockProbe is a tiny smoke check that the mock framer
// in this test file actually distinguishes CL.TE from TE.CL based on
// the declared CL value. Catches regressions in the mock when the
// probe shape changes.
func TestSmugglingMockDistinguishesProbeShapes(t *testing.T) {
	cases := []struct {
		name string
		mode smugglingMockMode
		cl   string
		hang bool
	}{
		{"clte-mock-hangs-on-cl4", mockVulnerableCLTE, "Content-Length: 4", true},
		{"clte-mock-ignores-cl6", mockVulnerableCLTE, "Content-Length: 6", false},
		{"tecl-mock-hangs-on-cl6", mockVulnerableTECL, "Content-Length: 6", true},
		{"tecl-mock-ignores-cl4", mockVulnerableTECL, "Content-Length: 4", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, _, stop := startSmugglingMock(t, tc.mode)
			defer stop()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			req := "POST / HTTP/1.1\r\nHost: x\r\n" + tc.cl + "\r\n" +
				"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
			_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
			_, _ = conn.Write([]byte(req))
			buf := make([]byte, 64)
			n, err := conn.Read(buf)
			gotResponse := n > 0 && err == nil
			if tc.hang && gotResponse {
				t.Errorf("expected hang, got response %q", string(buf[:n]))
			}
			if !tc.hang && !gotResponse {
				t.Errorf("expected response, got hang/err: %v", err)
			}
		})
	}
}

