package checks

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

// wsTestServer is a minimal net.Listener-backed handler that completes a
// real RFC 6455 handshake when the request carries an Upgrade: websocket
// header. validateOrigin controls whether a request with a non-empty,
// non-matching Origin is rejected with 403; that distinguishes a
// CSWSH-vulnerable endpoint (false) from a hardened one (true).
type wsTestServer struct {
	listener       net.Listener
	url            string
	hits           atomic.Int32
	validateOrigin bool
	allowedOrigin  string
}

func newWSTestServer(t *testing.T, validateOrigin bool) *wsTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &wsTestServer{
		listener:       ln,
		url:            "ws://" + ln.Addr().String() + "/socket",
		validateOrigin: validateOrigin,
		allowedOrigin:  "https://app.example.com",
	}
	go srv.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

func (s *wsTestServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *wsTestServer) handle(conn net.Conn) {
	defer conn.Close()
	s.hits.Add(1)
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		writeStatus(conn, 400, "Bad Request")
		return
	}
	origin := req.Header.Get("Origin")
	if s.validateOrigin && origin != "" && origin != s.allowedOrigin {
		writeStatus(conn, 403, "Forbidden")
		return
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	h := sha1.New()
	h.Write([]byte(key + wsAcceptMagic))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	_, _ = conn.Write([]byte(resp))
}

func writeStatus(conn net.Conn, code int, text string) {
	body := "{\"error\":\"" + text + "\"}"
	resp := "HTTP/1.1 " + strconv.Itoa(code) + " " + text + "\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Content-Type: application/json\r\n\r\n" + body
	_, _ = conn.Write([]byte(resp))
}

func TestWSAuditName(t *testing.T) {
	if got := (WSAudit{}).Name(); got != "ws-audit" {
		t.Fatalf("Name = %q, want ws-audit", got)
	}
}

func TestWSAuditLevel(t *testing.T) {
	if got := (WSAudit{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

func TestWSAuditSkipsWhenNoEndpointsReferenced(t *testing.T) {
	srv := newWSTestServer(t, false)
	pg := page.FromURL("http://" + srv.listener.Addr().String() + "/")
	pg.Body = []byte(`<html><body>nothing to see</body></html>`)

	findings, err := WSAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings; got %d: %+v", len(findings), findings)
	}
	if got := srv.hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; no ws:// references means no probe", got)
	}
}

func TestWSAuditDetectsCSWSHOnUnvalidatedEndpoint(t *testing.T) {
	srv := newWSTestServer(t, false)
	pg := page.FromURL("http://" + srv.listener.Addr().String() + "/app")
	pg.Body = []byte(`<script>const ws = new WebSocket("` + srv.url + `");</script>`)

	findings, err := WSAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if !strings.Contains(strings.ToLower(f.Title), "foreign origin") {
		t.Errorf("title = %q, want CSWSH wording", f.Title)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.CWE != "CWE-346" {
		t.Errorf("CWE = %q, want CWE-346", f.CWE)
	}
	if f.Evidence == nil || f.Evidence.Status != http.StatusSwitchingProtocols {
		t.Errorf("evidence status = %d, want 101", evidenceStatus(f.Evidence))
	}
}

func TestWSAuditDoesNotFlagWhenOriginValidated(t *testing.T) {
	srv := newWSTestServer(t, true)
	pg := page.FromURL("http://" + srv.listener.Addr().String() + "/app")
	pg.Body = []byte(`<script>new WebSocket("` + srv.url + `");</script>`)

	findings, err := WSAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "foreign origin") {
			t.Errorf("unexpected CSWSH finding when Origin validated: %+v", f)
		}
	}
}

func TestWSAuditFlagsCleartextOnHTTPSPage(t *testing.T) {
	srv := newWSTestServer(t, true) // validate so we don't double-flag with CSWSH
	pg := page.FromURL("https://app.example.com/portal")
	pg.Body = []byte(`<script>new WebSocket("` + srv.url + `");</script>`)

	findings, err := WSAudit{}.Run(context.Background(), nil, nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "cleartext") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no cleartext finding; got %+v", findings)
	}
	if got.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", got.Severity)
	}
	if got.CWE != "CWE-319" {
		t.Errorf("CWE = %q, want CWE-319", got.CWE)
	}
}

func TestWSAuditSkipsThirdPartyHost(t *testing.T) {
	// A ws:// URL pointing at a different host than the page should not
	// be probed; we don't own third-party endpoints and probing them is
	// out-of-scope by default.
	srv := newWSTestServer(t, false)
	pg := page.FromURL("http://app.example.com/")
	pg.Body = []byte(`<script>new WebSocket("` + srv.url + `");</script>`)

	findings, err := WSAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (third-party host filtered); got %+v", findings)
	}
	if got := srv.hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; third-party endpoint must not be probed", got)
	}
}

func TestWSAuditDedupes(t *testing.T) {
	srv := newWSTestServer(t, false)
	pg := page.FromURL("http://" + srv.listener.Addr().String() + "/app")
	// Same endpoint referenced three times in the body must produce
	// one probe and one finding.
	body := `<script>` +
		`new WebSocket("` + srv.url + `");` +
		`var u = "` + srv.url + `";` +
		`fetch("` + srv.url + `");` +
		`</script>`
	pg.Body = []byte(body)

	findings, err := WSAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding after dedupe; got %d: %+v", len(findings), findings)
	}
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("server hit %d times; expected 1 (deduped)", got)
	}
}

func TestWSAuditRejectsCoincidental101(t *testing.T) {
	// A "WebSocket" endpoint that returns 101 but does NOT supply a
	// valid Sec-WebSocket-Accept is not a real WS server; the handshake
	// must not be treated as accepted.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				_, _ = http.ReadRequest(br)
				_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: not-a-real-accept-value\r\n\r\n"))
			}(conn)
		}
	}()

	wsURL := "ws://" + ln.Addr().String() + "/wat"
	pg := page.FromURL("http://" + ln.Addr().String() + "/page")
	pg.Body = []byte(`new WebSocket("` + wsURL + `")`)

	findings, err := WSAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "foreign origin") {
			t.Errorf("unexpected CSWSH finding on coincidental 101: %+v", f)
		}
	}
}

func TestDiscoverWSEndpoints(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "single ws reference",
			body: `<script>new WebSocket("ws://app.example.com/socket");</script>`,
			want: []string{"ws://app.example.com/socket"},
		},
		{
			name: "wss reference",
			body: `<script>const w = "wss://app.example.com/feed?token=x";</script>`,
			want: []string{"wss://app.example.com/feed?token=x"},
		},
		{
			name: "dedupe same url repeated",
			body: `ws://app.example.com/a ws://app.example.com/a`,
			want: []string{"ws://app.example.com/a"},
		},
		{
			name: "retains cross-host reference",
			body: `<script>new WebSocket("ws://other.example.org/socket");</script>`,
			want: []string{"ws://other.example.org/socket"},
		},
		{
			name: "no references",
			body: `<html><body>hi</body></html>`,
			want: nil,
		},
		{
			name: "empty body",
			body: ``,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := discoverWSEndpoints(page.Page{Body: []byte(tc.body)})
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestWSAcceptMatches(t *testing.T) {
	// RFC 6455 §4.1 sample handshake.
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	want := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if !wsAcceptMatches(key, want) {
		t.Errorf("wsAcceptMatches(%q,%q) = false, want true", key, want)
	}
	if wsAcceptMatches(key, "wrong") {
		t.Errorf("wsAcceptMatches accepted a wrong value")
	}
	if wsAcceptMatches(key, "") {
		t.Errorf("wsAcceptMatches accepted empty value")
	}
}

func evidenceStatus(e *Evidence) int {
	if e == nil {
		return -1
	}
	return e.Status
}
