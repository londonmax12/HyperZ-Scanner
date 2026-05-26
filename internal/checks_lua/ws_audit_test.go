package checks_lua

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

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findWSAudit(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "ws-audit" {
			return c
		}
	}
	t.Fatal("ws-audit Lua check not found")
	return nil
}

// wsParityServer is a minimal listener that completes an RFC 6455
// handshake when the request carries Upgrade: websocket. When
// validateOrigin is true, requests with a foreign Origin get 403.
// Duplicates the Go-side helper so the checks_lua parity tests don't
// depend on the internal/checks test binary.
type wsParityServer struct {
	listener       net.Listener
	url            string
	hits           atomic.Int32
	validateOrigin bool
	allowedOrigin  string
}

// wsAcceptMagic is the RFC 6455 GUID concatenated with the client key
// to derive Sec-WebSocket-Accept. The Go-side checks package keeps
// this private; the test mirrors the literal so both sides can
// recompute the accept value independently.
const wsAcceptMagicLua = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func newWSParityServer(t *testing.T, validateOrigin bool) *wsParityServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &wsParityServer{
		listener:       ln,
		url:            "ws://" + ln.Addr().String() + "/socket",
		validateOrigin: validateOrigin,
		allowedOrigin:  "https://app.example.com",
	}
	go srv.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

func (s *wsParityServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *wsParityServer) handle(conn net.Conn) {
	defer conn.Close()
	s.hits.Add(1)
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		wsWriteStatusLua(conn, 400, "Bad Request")
		return
	}
	origin := req.Header.Get("Origin")
	if s.validateOrigin && origin != "" && origin != s.allowedOrigin {
		wsWriteStatusLua(conn, 403, "Forbidden")
		return
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	h := sha1.New()
	h.Write([]byte(key + wsAcceptMagicLua))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	_, _ = conn.Write([]byte(resp))
}

func wsWriteStatusLua(conn net.Conn, code int, text string) {
	body := "{\"error\":\"" + text + "\"}"
	resp := "HTTP/1.1 " + strconv.Itoa(code) + " " + text + "\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Content-Type: application/json\r\n\r\n" + body
	_, _ = conn.Write([]byte(resp))
}

// TestLuaWSAuditNoEndpointsParity asserts neither impl probes nor
// reports anything when the page body has no ws:// / wss:// literals.
func TestLuaWSAuditNoEndpointsParity(t *testing.T) {
	srv := newWSParityServer(t, false)
	pg := page.FromURL("http://" + srv.listener.Addr().String() + "/")
	pg.Body = []byte(`<html><body>nothing to see</body></html>`)

	goFs, err := (checks.WSAudit{}).Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findWSAudit(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != 0 || len(luaFs) != 0 {
		t.Errorf("no-endpoint page must produce 0 findings on both: go=%d lua=%d", len(goFs), len(luaFs))
	}
	if srv.hits.Load() != 0 {
		t.Errorf("server hit %d times; no probes should fire when no ws:// literals", srv.hits.Load())
	}
}

// TestLuaWSAuditCSWSHParity locks in the CSWSH arm: on an unvalidated
// endpoint, both impls must fire one High finding with byte-aligned
// Severity / CWE / DedupeKey.
func TestLuaWSAuditCSWSHParity(t *testing.T) {
	srv := newWSParityServer(t, false)
	pg := page.FromURL("http://" + srv.listener.Addr().String() + "/app")
	pg.Body = []byte(`<script>const ws = new WebSocket("` + srv.url + `");</script>`)

	goFs, err := (checks.WSAudit{}).Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findWSAudit(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}

	goHit := pickByTitleSubstr(goFs, "foreign Origin")
	luaHit := pickByTitleSubstr(luaFs, "foreign Origin")
	if goHit == nil || luaHit == nil {
		t.Fatalf("CSWSH must fire on both impls: go=%+v lua=%+v", goFs, luaFs)
	}
	if goHit.Severity != luaHit.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goHit.Severity, luaHit.Severity)
	}
	if goHit.CWE != luaHit.CWE {
		t.Errorf("CWE drift: go=%q lua=%q", goHit.CWE, luaHit.CWE)
	}
	if goHit.DedupeKey != luaHit.DedupeKey {
		t.Errorf("dedupe drift: go=%q lua=%q", goHit.DedupeKey, luaHit.DedupeKey)
	}
}

// TestLuaWSAuditOriginValidatedQuietParity asserts a hardened endpoint
// (origin allowlist returns 403 on foreign origins) produces no CSWSH
// finding on either impl.
func TestLuaWSAuditOriginValidatedQuietParity(t *testing.T) {
	srv := newWSParityServer(t, true)
	pg := page.FromURL("http://" + srv.listener.Addr().String() + "/app")
	pg.Body = []byte(`<script>new WebSocket("` + srv.url + `");</script>`)

	goFs, err := (checks.WSAudit{}).Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findWSAudit(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if pickByTitleSubstr(goFs, "foreign Origin") != nil {
		t.Errorf("go: CSWSH must not fire under origin allowlist: %+v", goFs)
	}
	if pickByTitleSubstr(luaFs, "foreign Origin") != nil {
		t.Errorf("lua: CSWSH must not fire under origin allowlist: %+v", luaFs)
	}
}

// TestLuaWSAuditCleartextOnHTTPSParity locks in the cleartext arm:
// an https:// page referencing a ws:// endpoint must fire one Medium
// "cleartext" finding on both impls. validateOrigin is true so the
// CSWSH arm does not double-flag.
func TestLuaWSAuditCleartextOnHTTPSParity(t *testing.T) {
	srv := newWSParityServer(t, true)
	pg := page.FromURL("https://app.example.com/portal")
	pg.Body = []byte(`<script>new WebSocket("` + srv.url + `");</script>`)

	goFs, err := (checks.WSAudit{}).Run(context.Background(), nil, nil, pg)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findWSAudit(t)
	luaFs, err := luaC.Run(context.Background(), nil, nil, pg)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}

	goHit := pickByTitleSubstr(goFs, "cleartext")
	luaHit := pickByTitleSubstr(luaFs, "cleartext")
	if goHit == nil || luaHit == nil {
		t.Fatalf("cleartext must fire on both impls: go=%+v lua=%+v", goFs, luaFs)
	}
	if goHit.Severity != luaHit.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goHit.Severity, luaHit.Severity)
	}
	if goHit.CWE != luaHit.CWE {
		t.Errorf("CWE drift: go=%q lua=%q", goHit.CWE, luaHit.CWE)
	}
	if goHit.DedupeKey != luaHit.DedupeKey {
		t.Errorf("dedupe drift: go=%q lua=%q", goHit.DedupeKey, luaHit.DedupeKey)
	}
}

// TestLuaWSAuditCrossHostFilterParity asserts both impls skip the
// CSWSH probe when the ws:// endpoint is on a different host than
// the page. The server must not be hit; both impls must produce no
// CSWSH finding.
func TestLuaWSAuditCrossHostFilterParity(t *testing.T) {
	srv := newWSParityServer(t, false)
	pg := page.FromURL("http://app.example.com/")
	pg.Body = []byte(`<script>new WebSocket("` + srv.url + `");</script>`)

	goFs, err := (checks.WSAudit{}).Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findWSAudit(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if pickByTitleSubstr(goFs, "foreign Origin") != nil {
		t.Errorf("go: CSWSH must skip third-party hosts: %+v", goFs)
	}
	if pickByTitleSubstr(luaFs, "foreign Origin") != nil {
		t.Errorf("lua: CSWSH must skip third-party hosts: %+v", luaFs)
	}
	if srv.hits.Load() != 0 {
		t.Errorf("server hit %d times; third-party endpoint must not be probed", srv.hits.Load())
	}
}

// TestLuaWSAuditDedupesParity asserts both impls collapse multiple
// references to the same endpoint into a single probe + finding.
func TestLuaWSAuditDedupesParity(t *testing.T) {
	srv := newWSParityServer(t, false)
	pg := page.FromURL("http://" + srv.listener.Addr().String() + "/app")
	body := `<script>` +
		`new WebSocket("` + srv.url + `");` +
		`var u = "` + srv.url + `";` +
		`fetch("` + srv.url + `");` +
		`</script>`
	pg.Body = []byte(body)

	// One pass for Go; one for Lua. Counting hits separately because
	// the bridge handshake goes through a fresh dial each call.
	preGo := srv.hits.Load()
	goFs, err := (checks.WSAudit{}).Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	postGo := srv.hits.Load()
	if got := postGo - preGo; got != 1 {
		t.Errorf("go: server hit %d times after dedupe; want 1", got)
	}

	preLua := srv.hits.Load()
	luaC := findWSAudit(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	postLua := srv.hits.Load()
	if got := postLua - preLua; got != 1 {
		t.Errorf("lua: server hit %d times after dedupe; want 1", got)
	}

	if len(goFs) != 1 {
		t.Errorf("go: expected 1 finding after dedupe; got %d", len(goFs))
	}
	if len(luaFs) != 1 {
		t.Errorf("lua: expected 1 finding after dedupe; got %d", len(luaFs))
	}
	if len(goFs) == 1 && len(luaFs) == 1 && goFs[0].DedupeKey != luaFs[0].DedupeKey {
		t.Errorf("dedupe key drift: go=%q lua=%q", goFs[0].DedupeKey, luaFs[0].DedupeKey)
	}
}
