package lua_engine

import (
	"bufio"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// Low-level raw-socket helpers shared by checks that bypass the
// standard httpclient transport (request-smuggling, race-condition).
// These were originally private to request_smuggling.go; they were
// promoted to the package surface so per-family check subpackages
// (internal/lua_engine/checks/...) can reach them without an import
// cycle through root.
//
// The body-read cap is a local const here so neither subpackage needs
// to thread its own value; 8 KiB is comfortably above any sane front-
// end's error response, which is the only shape the timing-oracle
// callers ever look at.

const responseHeadReadCap = 8 << 10

// SplitHostPortDefault returns u.Hostname() and u.Port(), defaulting
// the port to 443 for https and 80 for http when the URL omitted one.
// Used by callers that need to JoinHostPort for a raw TCP dial.
func SplitHostPortDefault(u *url.URL) (host, port string) {
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

// WriteAllDeadline writes b to conn under a wall-clock deadline. A
// stalled write on a probe that the back-end isn't reading would
// otherwise pin the worker indefinitely; the same deadline that bounds
// the read covers the write side too.
func WriteAllDeadline(conn net.Conn, b []byte, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	_, err := conn.Write(b)
	return err
}

// ReadResponseHead reads the HTTP/1.1 status line and headers from
// conn under a deadline, returning whatever bytes were captured. We
// intentionally don't parse beyond the headers: the timing signal is
// the wall-clock cost of getting any response at all, and reading
// the body would dilute it with the body-stream latency.
//
// On a real hang, this returns a net timeout error, which the caller
// interprets as confirmation of the desync and reports as a probe
// latency capped at the timeout.
func ReadResponseHead(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	r := bufio.NewReader(io.LimitReader(conn, responseHeadReadCap))
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
