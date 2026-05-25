package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// WSAudit probes WebSocket endpoints discovered on a crawled page for
// Cross-Site WebSocket Hijacking (CSWSH) and cleartext-on-HTTPS exposure.
//
// Discovery is cheap: scan the already-fetched body for ws:// / wss://
// URL literals (script src, anchor href, JS string constants, inline JSON
// config). Each discovered endpoint that the scope allows is then probed
// with a real RFC 6455 handshake carrying a foreign Origin header. If the
// server replies with 101 Switching Protocols and a valid
// Sec-WebSocket-Accept derived from our Sec-WebSocket-Key, the handshake
// succeeded - which means Origin is not being validated and any
// attacker-controlled page can open the same socket from a victim's
// browser. With cookie-based session auth that is read+write access to
// the live channel; even without auth, message traffic and rate limits
// can be enumerated.
//
// The check fires HTTP/1.1 upgrade requests directly over a TCP (or TLS)
// connection because the http.Client transport will not let us inspect a
// 101 response cleanly. The handshake bypasses the configured rate
// limiter and budget - the cost is bounded by the small number of
// endpoints discoverable on any one page, but operators should know that
// a /loop scan against the same page will issue 1-3 handshakes per pass.
//
// Active (LevelDefault) check. Sends one Origin-spoofed handshake per
// unique endpoint; never sends data frames after the handshake.
type WSAudit struct{}

func (WSAudit) Name() string { return "ws-audit" }

func (WSAudit) Level() Level { return LevelDefault }

const (
	// wsBodyCap bounds how much of the page body we scan for ws:// URL
	// literals. Endpoint references almost always appear in the head /
	// early script tags; capping prevents pathological pages from
	// turning a passive scan into a long regex run.
	wsBodyCap = 2 << 20
	// wsHandshakeTimeout caps the handshake's TCP + TLS + first-byte
	// budget. A WebSocket endpoint that does not respond within this
	// window is treated as unreachable rather than vulnerable; the
	// alternative (blocking indefinitely on a long-poll-style upgrade)
	// would let a single bad host stall the worker slot.
	wsHandshakeTimeout = 8 * time.Second
	// wsOrigin is the foreign Origin presented during the handshake.
	// Any clearly-foreign hostname works; example.com is used because
	// it's reserved by IANA and will never collide with a real allowlist.
	wsOrigin = "https://hyperz-attacker.example"
	// wsAcceptMagic is the RFC 6455 GUID concatenated with the client
	// Sec-WebSocket-Key to derive the server's Sec-WebSocket-Accept.
	// Used both for crafting the probe and for verifying the server's
	// response is a real WebSocket accept (not just a coincidental 101).
	wsAcceptMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	// wsMaxEndpointsPerPage caps how many distinct endpoints we probe
	// from one page. Single-page apps sometimes inline dozens of
	// environment-specific URLs in a config blob; we'd rather sample
	// than fan out.
	wsMaxEndpointsPerPage = 5
)

// wsURLRE matches ws:// or wss:// URL literals in HTML / JS bodies.
// Stops at the usual string terminators so a quoted URL doesn't bleed
// into the next attribute or expression. Anchored case-insensitively
// because servers and devs use both lowercase and uppercase schemes.
var wsURLRE = regexp.MustCompile(`(?i)wss?://[^\s'"<>)\\` + "`" + `]+`)

func (c WSAudit) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	pageURL, err := url.Parse(p.URL)
	if err != nil || pageURL.Host == "" {
		return nil, nil
	}
	if !sc.Allows(pageURL) {
		return nil, nil
	}

	endpoints := discoverWSEndpoints(p)
	if len(endpoints) == 0 {
		return nil, nil
	}

	var findings []Finding
	probed := 0
	for _, ep := range endpoints {
		epURL, err := url.Parse(ep)
		if err != nil || epURL.Host == "" {
			continue
		}

		// Cleartext-on-HTTPS: a ws:// endpoint referenced from an
		// https:// page is mixed content for the WebSocket channel.
		// Browsers block this load entirely, but the configuration
		// leak is worth flagging - it tells an attacker the channel
		// exists and what URL to attack at the http:// fallback.
		// This fires regardless of host because a cross-host cleartext
		// reference is just as much of a privacy and integrity leak
		// for the user as a same-host one.
		if strings.EqualFold(epURL.Scheme, "ws") && strings.EqualFold(pageURL.Scheme, "https") {
			findings = append(findings, Finding{
				Check:    c.Name(),
				Target:   p.URL,
				URL:      p.URL,
				Severity: SeverityMedium,
				Title:    fmt.Sprintf("HTTPS page references cleartext WebSocket %s", ep),
				Detail: "An https:// page advertises a ws:// WebSocket endpoint. Modern browsers block the connection " +
					"as mixed active content, but the reference itself reveals the channel to anyone reading the page " +
					"source. Anyone who can sit on the network path between the client and that endpoint can read or " +
					"tamper with every frame in both directions because the channel is unencrypted.",
				CWE:   "CWE-319",
				OWASP: "A02:2021 Cryptographic Failures",
				Remediation: "Serve the WebSocket over wss:// (TLS) and update every page reference. If the WebSocket " +
					"server is behind a load balancer or reverse proxy, terminate TLS there and forward the upgraded " +
					"connection as plaintext on the trusted internal segment.",
				Evidence: &Evidence{
					Method:     http.MethodGet,
					RequestURL: ep,
					Snippet:    "Page " + p.URL + " references " + ep,
				},
				DedupeKey: MakeKey(c.Name(), ScopeHost, p.URL, "cleartext:"+ep),
			})
		}

		// Same-host filter for the actual CSWSH probe. We don't own
		// third-party endpoints and probing them is out-of-scope by
		// default; the cleartext finding above is the only thing we
		// emit for a cross-host reference. Scope is also re-checked
		// here so a same-host endpoint outside the operator's scope
		// (e.g. port-restricted) is not probed.
		if !strings.EqualFold(epURL.Hostname(), pageURL.Hostname()) {
			continue
		}
		if !sc.Allows(epURL) {
			continue
		}
		if probed >= wsMaxEndpointsPerPage {
			continue
		}
		probed++
		accepted, snippet, status, err := wsHandshake(ctx, ep, wsOrigin)
		if err != nil {
			Report(ctx, fmt.Errorf("ws-audit handshake %s: %w", ep, err))
			continue
		}
		if !accepted {
			continue
		}
		findings = append(findings, Finding{
			Check:    c.Name(),
			Target:   p.URL,
			URL:      ep,
			Severity: SeverityHigh,
			Title:    "WebSocket handshake accepted from foreign Origin",
			Detail: "The endpoint completed an RFC 6455 handshake when the request carried Origin: " + wsOrigin +
				". WebSocket connections are NOT subject to the same-origin policy at the browser level; the only " +
				"thing standing between a victim's authenticated session and an attacker-controlled page is server-side " +
				"Origin validation. With validation absent, any web page the victim visits can open a socket to this " +
				"endpoint, replay the victim's session cookies, and read or send messages on the channel. This is the " +
				"WebSocket analogue of cross-site request forgery (Cross-Site WebSocket Hijacking / CSWSH).",
			CWE:   "CWE-346",
			OWASP: "A01:2021 Broken Access Control",
			Remediation: "Validate the request's Origin header against an allowlist of trusted origins during the " +
				"WebSocket handshake (HTTP 403 on mismatch). For session-bound channels, additionally require a " +
				"non-cookie credential (signed token in a sub-protocol or in the first message); cookies alone are " +
				"vulnerable to replay from any origin the user happens to visit.",
			Evidence: &Evidence{
				Method:     http.MethodGet,
				RequestURL: ep,
				Status:     status,
				Snippet:    snippet,
			},
			DedupeKey: MakeKey(c.Name(), ScopePage, ep, "cswsh"),
		})
	}
	return findings, nil
}

// discoverWSEndpoints extracts ws:// / wss:// URL literals from the
// already-fetched page body and returns a stable-ordered, deduped slice
// of absolute endpoint URLs. Relative URLs and protocol-relative URLs
// don't apply: ws:// references are always absolute by spec. Non-body
// pages (nil body, binary content types) silently yield no endpoints.
//
// The caller filters by host before probing; cross-host references are
// retained so the cleartext-on-HTTPS finding can still fire on them.
func discoverWSEndpoints(p page.Page) []string {
	if len(p.Body) == 0 {
		return nil
	}
	scan := p.Body
	if len(scan) > wsBodyCap {
		scan = scan[:wsBodyCap]
	}
	seen := map[string]struct{}{}
	for _, m := range wsURLRE.FindAll(scan, -1) {
		raw := string(m)
		// HTML attribute terminators that the regex's character class
		// would not have stopped on (a JSON " inside HTML "..." for
		// instance). Trim conservative trailing punctuation that almost
		// never appears in a URL path.
		raw = strings.TrimRight(raw, ".,;:!?")
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		if u.Scheme != "ws" && u.Scheme != "wss" {
			continue
		}
		key := u.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// wsHandshake opens a TCP (or TLS) connection to the WebSocket
// endpoint, sends an RFC 6455 client handshake with the supplied
// Origin, and reports whether the server accepted the upgrade. accepted
// is true only when the server returned 101 Switching Protocols and the
// Sec-WebSocket-Accept header derives correctly from our key - both
// conditions are required to distinguish a real WebSocket server from a
// generic proxy that returns 101 for any upgrade.
//
// The connection is closed before returning; no data frames are sent.
// snippet is a compact rendering of the response status line and a few
// signal headers, suitable for embedding in Evidence.Snippet.
func wsHandshake(ctx context.Context, target, origin string) (bool, string, int, error) {
	u, err := url.Parse(target)
	if err != nil {
		return false, "", 0, fmt.Errorf("parse %q: %w", target, err)
	}
	// dialAddr must always carry an explicit port (TCP dial needs one),
	// but the Host header must mirror what a browser would send -
	// browsers strip the default port for ws://80 and wss://443, and
	// some virtual-host routers 400 on a Host that includes one.
	dialAddr := u.Host
	if u.Port() == "" {
		if strings.EqualFold(u.Scheme, "wss") {
			dialAddr = u.Hostname() + ":443"
		} else {
			dialAddr = u.Hostname() + ":80"
		}
	}

	deadline := time.Now().Add(wsHandshakeTimeout)
	dialer := &net.Dialer{Timeout: wsHandshakeTimeout}
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	var conn net.Conn
	if strings.EqualFold(u.Scheme, "wss") {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: u.Hostname()}}
		conn, err = tlsDialer.DialContext(dialCtx, "tcp", dialAddr)
	} else {
		conn, err = dialer.DialContext(dialCtx, "tcp", dialAddr)
	}
	if err != nil {
		return false, "", 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	key, err := newWSKey()
	if err != nil {
		return false, "", 0, fmt.Errorf("generate ws key: %w", err)
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	var req bytes.Buffer
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&req, "Host: %s\r\n", u.Host)
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", key)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&req, "Origin: %s\r\n", origin)
	req.WriteString("User-Agent: hyperz/ws-audit\r\n")
	req.WriteString("\r\n")

	if _, err := conn.Write(req.Bytes()); err != nil {
		return false, "", 0, err
	}

	httpReq, _ := http.NewRequest(http.MethodGet, target, nil)
	resp, err := http.ReadResponse(bufio.NewReader(conn), httpReq)
	if err != nil {
		return false, "", 0, err
	}
	defer resp.Body.Close()

	accepted := resp.StatusCode == http.StatusSwitchingProtocols &&
		wsAcceptMatches(key, resp.Header.Get("Sec-WebSocket-Accept"))

	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %s\n", resp.Status)
	for _, k := range []string{
		"Upgrade",
		"Connection",
		"Sec-WebSocket-Accept",
		"Sec-WebSocket-Protocol",
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials",
	} {
		if v := resp.Header.Get(k); v != "" {
			fmt.Fprintf(&sb, "%s: %s\n", k, v)
		}
	}
	return accepted, sb.String(), resp.StatusCode, nil
}

// newWSKey returns a fresh base64-encoded 16-byte client key for use as
// Sec-WebSocket-Key. Per RFC 6455 the key is opaque to the server; we
// generate a unique one per handshake so a stale Sec-WebSocket-Accept
// from a cached response can't false-positive verifyAccept.
func newWSKey() (string, error) {
	var k [16]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// wsAcceptMatches reports whether accept is the correct RFC 6455
// derivation of key. The server computes base64(sha1(key + magic)) and
// returns it in Sec-WebSocket-Accept; only a real WebSocket server (or
// one that has been told the magic GUID) produces this value, which
// rules out proxies that return 101 Switching Protocols for arbitrary
// upgrade requests.
func wsAcceptMatches(key, accept string) bool {
	if accept == "" {
		return false
	}
	h := sha1.New()
	h.Write([]byte(key + wsAcceptMagic))
	want := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return strings.EqualFold(strings.TrimSpace(accept), want)
}
