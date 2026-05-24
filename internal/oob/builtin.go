package oob

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Builtin is the in-process OOB listener. It binds an HTTP server on the
// operator-supplied address and records every request that arrives.
// Tokens are extracted from the first path segment; requests that don't
// start with a known token are still recorded (under a synthetic
// "unattributed" key) so the operator can see scanner traffic the
// target may have lost the token from along the way (e.g. a redirect
// chain that dropped query bits).
//
// HTTPS is intentionally not supported in MVP: TLS termination requires
// a cert chain the operator usually doesn't have for the public
// callback host, and the detection signal (a connection was made) does
// not depend on transport security. Targets that refuse to call plain
// HTTP endpoints will simply not hit the listener, which is a clean
// false-negative rather than a misleading false-positive.
//
// DNS is also out of scope for MVP. The blind-check payloads ride HTTP
// fetches end-to-end, and binding port 53 on most hosts needs root
// privileges - a deployment hurdle that would dwarf the additional
// coverage DNS-only callbacks add over HTTP ones.
type Builtin struct {
	listen string // bind address, e.g. ":7777"
	host   string // callback host:port targets see, e.g. "scanner.example.com:7777"

	mu      sync.RWMutex
	regs    map[string]Registration   // token -> registration
	byCheck map[string][]string       // check -> tokens (mint order)
	hits    map[string][]Hit          // token -> hits

	srv     *http.Server
	ln      net.Listener
	started bool
	stopped bool
}

// LocalAddr returns the listener's resolved TCP address after Start.
// Returns the empty string before Start or after Stop. Useful when the
// caller bound ":0" and needs to learn the OS-assigned port.
func (b *Builtin) LocalAddr() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.ln == nil {
		return ""
	}
	return b.ln.Addr().String()
}

// NewBuiltin returns a Builtin configured to bind at listen and advertise
// the supplied callback host in canary URLs. listen is a Go net/http
// address ("host:port" or ":port"); host is "host" or "host:port" -
// the latter overrides the scheme-implied default port when targets
// reach the listener through a proxy or non-standard port.
//
// The server is not started until Start is called.
func NewBuiltin(listen, host string) *Builtin {
	return &Builtin{
		listen:  listen,
		host:    host,
		regs:    map[string]Registration{},
		byCheck: map[string][]string{},
		hits:    map[string][]Hit{},
	}
}

// CallbackHost returns the host:port the listener was configured to
// advertise. Returned verbatim - the caller is responsible for any
// scheme prefix.
func (b *Builtin) CallbackHost() string { return b.host }

// Register mints a fresh canary, indexes it under check, and stores the
// supplied extra metadata. The returned Canary's HTTPURL embeds the
// callback host so a probe can copy it directly into a payload.
//
// Safe for concurrent callers. Extra is copied so subsequent mutation
// by the caller cannot reach back into the server's index.
func (b *Builtin) Register(check string, extra map[string]string) Canary {
	token := MintToken()
	canary := Canary{
		Token:   token,
		HTTPURL: "http://" + b.host + "/" + token,
	}
	cp := make(map[string]string, len(extra))
	for k, v := range extra {
		cp[k] = v
	}
	reg := Registration{Canary: canary, Check: check, Extra: cp}
	b.mu.Lock()
	b.regs[token] = reg
	b.byCheck[check] = append(b.byCheck[check], token)
	b.mu.Unlock()
	return canary
}

// Registrations returns the registrations the named check made, in mint
// order. The returned slice is a copy - callers can iterate without
// holding the server lock.
func (b *Builtin) Registrations(check string) []Registration {
	b.mu.RLock()
	defer b.mu.RUnlock()
	tokens := b.byCheck[check]
	if len(tokens) == 0 {
		return nil
	}
	out := make([]Registration, 0, len(tokens))
	for _, t := range tokens {
		if reg, ok := b.regs[t]; ok {
			out = append(out, reg)
		}
	}
	return out
}

// Hits returns the hits observed for token, in arrival order. The
// returned slice is a copy.
func (b *Builtin) Hits(token string) []Hit {
	b.mu.RLock()
	defer b.mu.RUnlock()
	src := b.hits[token]
	if len(src) == 0 {
		return nil
	}
	out := make([]Hit, len(src))
	copy(out, src)
	return out
}

// Start binds the HTTP listener and serves callbacks until Stop is
// called. The HTTP server runs on its own goroutine; Start returns
// once the socket is bound (so callers can log "ready" without
// racing the first probe). ctx is currently unused but kept in the
// signature so a future implementation can honor caller cancellation
// during a slow startup probe.
func (b *Builtin) Start(_ context.Context) error {
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return errors.New("oob: builtin already started")
	}
	if b.stopped {
		b.mu.Unlock()
		return errors.New("oob: builtin already stopped, cannot restart")
	}
	b.started = true
	b.mu.Unlock()

	// Bind eagerly so the caller learns immediately if the port is
	// unavailable. The accept loop runs in the background; we don't
	// want a target's first probe to race a still-binding listener.
	ln, err := net.Listen("tcp", b.listen)
	if err != nil {
		b.mu.Lock()
		b.started = false
		b.mu.Unlock()
		return fmt.Errorf("oob: listen %s: %w", b.listen, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", b.handle)
	b.mu.Lock()
	b.ln = ln
	b.srv = &http.Server{
		Handler: mux,
		// Tight timeouts. The listener never serves a real client; every
		// request is either a hit (small) or noise (still small). A long
		// timeout just lets a slow attacker tie up sockets.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	srv := b.srv
	b.mu.Unlock()
	go func() {
		// http.ErrServerClosed is the clean-stop signal; any other error
		// is interesting (port closed under us, etc.) but the server
		// teardown path doesn't propagate it. Operators can re-run with
		// a different --oob-listen if the first attempt fails noisily.
		_ = srv.Serve(ln)
	}()
	return nil
}

// Stop shuts the listener down. Safe to call after a failed Start (it
// becomes a no-op) and safe to call more than once.
func (b *Builtin) Stop(ctx context.Context) error {
	b.mu.Lock()
	if b.stopped || b.srv == nil {
		b.stopped = true
		b.mu.Unlock()
		return nil
	}
	b.stopped = true
	srv := b.srv
	b.mu.Unlock()
	return srv.Shutdown(ctx)
}

// handle records every incoming request as a Hit. The token is the
// first non-empty path segment; if no segment is present (a bare GET /
// from a port scanner, say) the hit is recorded against the empty
// token so it doesn't get lost - the operator can grep it out of
// debug logs later if needed.
func (b *Builtin) handle(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r.URL.Path)
	hit := Hit{
		Token:      token,
		Protocol:   "http",
		SourceAddr: r.RemoteAddr,
		Timestamp:  time.Now().UTC(),
		Method:     r.Method,
		Path:       r.URL.RequestURI(),
		Headers:    r.Header.Clone(),
	}
	b.mu.Lock()
	b.hits[token] = append(b.hits[token], hit)
	b.mu.Unlock()
	// Reply with a tiny 200 so the calling library doesn't retry. We
	// don't echo the token: a target that gets back its own canary
	// might log it in a way that leaks the scanner's address.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// extractToken returns the first non-empty path segment from path. A
// leading or trailing slash is tolerated; multiple slashes between
// segments collapse cleanly because strings.Split treats them as empty
// segments which we filter out.
func extractToken(path string) string {
	for _, seg := range strings.Split(path, "/") {
		if seg != "" {
			return seg
		}
	}
	return ""
}
