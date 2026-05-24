// Package oob provides the out-of-band callback backbone for blind checks.
//
// Active checks turn into blind detectors when they can observe a
// target-initiated callback to a hyperz-controlled endpoint. Blind SSRF,
// blind XXE, and blind SSTI all share the same shape: embed a unique
// canary URL in a probe payload, then ask "did anything contact that
// URL during the scan." This package owns the canary lifecycle and the
// listener those callbacks land on.
//
// Concurrency: every method on Server is safe for concurrent use. Checks
// call Register from many goroutines during the active phase; the
// built-in listener writes hits from its own accept loop.
package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

// Hit is one observed callback to the listener. SourceAddr is the
// remote IP:port the connection arrived from; Path is the request-line
// path as the listener saw it (relative, including the canary token
// segment). Headers is a clone of the request headers so the report
// can show the target's User-Agent / fetch-library fingerprint.
//
// Body is intentionally NOT captured. The detection signal is "the
// canary URL was contacted", not "what bytes the target sent" - a
// curl-shaped fetch and a Python requests call both produce the same
// finding, and the body adds storage cost without raising confidence.
type Hit struct {
	Token      string      `json:"token"`
	Protocol   string      `json:"protocol"`
	SourceAddr string      `json:"source_addr"`
	Timestamp  time.Time   `json:"timestamp"`
	Method     string      `json:"method,omitempty"`
	Path       string      `json:"path,omitempty"`
	Headers    http.Header `json:"headers,omitempty"`
}

// Canary is the addressable identity a probe embeds in its payload. Token
// is the short opaque string the listener correlates incoming hits to;
// HTTPURL is the full URL a probe should plant ("http://callback-host:port/<token>").
//
// Tokens are minted with crypto/rand so a target cannot guess one and
// generate a fake hit. Per-scan registrations stay in memory only -
// nothing about a Canary survives across scans.
type Canary struct {
	Token   string
	HTTPURL string
}

// Registration is the metadata block a check supplies when minting a
// canary. The server stores it verbatim and returns it during Drain so
// the check can build a finding from the same fields it knew at probe
// time (target URL, sink, payload name) without re-deriving them.
//
// Extra is opaque to the server - keys and values are check-specific.
// Check names live in the Check field so the server can index by them.
type Registration struct {
	Canary Canary
	Check  string
	Extra  map[string]string
}

// Server is the OOB callback backbone. Implementations may be in-process
// (Builtin) or remote (a hypothetical interactsh-style HTTP poller); the
// scan command picks one at startup and threads it into check contexts.
//
// Lifecycle: Start once before the scan begins, Stop once after the
// scan and the drain phase complete. Register / Registrations / Hits
// are safe between Start and Stop.
type Server interface {
	// Register mints a fresh canary and indexes it under check. Extra
	// is stored verbatim for the matching Registration to retrieve at
	// Drain time. Safe for concurrent callers.
	Register(check string, extra map[string]string) Canary
	// Registrations returns every registration the named check made,
	// in mint order. Empty slice when the check never registered.
	Registrations(check string) []Registration
	// Hits returns every hit observed for token, in arrival order. Empty
	// slice when no hit landed.
	Hits(token string) []Hit
	// Start begins serving callbacks. Returns once the listener is bound
	// and ready to accept requests, or an error if binding fails.
	Start(ctx context.Context) error
	// Stop releases listener resources. Safe to call multiple times.
	Stop(ctx context.Context) error
	// CallbackHost returns the host:port targets see in canary URLs.
	// Used by the scan command for the "OOB ready at ..." startup log.
	CallbackHost() string
}

// canaryTokenLen is the number of random bytes a token carries. 16 bytes
// (128 bits) makes a target's chance of guessing a live token
// vanishingly small even across a scan with millions of canaries.
const canaryTokenLen = 16

// MintToken returns a fresh opaque token. Reads from crypto/rand; a
// failure means the platform CSPRNG is broken and there is no useful
// fallback, so this panics rather than silently emitting predictable
// tokens that a target could enumerate.
func MintToken() string {
	var b [canaryTokenLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("oob: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
