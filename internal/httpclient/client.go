package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	http         *http.Client
	httpNoFollow *http.Client // shares transport/jar/timeout with http; CheckRedirect short-circuits the chain
	userAgent    string
	limiter      *HostLimiter
	budget       *Budget
	maxRetries   int
	maxRetryWait time.Duration
	basicAuth    *BasicAuth
	bearerToken  string
	extraHeaders http.Header
	middlewares  []RequestMiddleware
	nowFn        func() time.Time // overridable for tests parsing HTTP-date Retry-After
	sleepFn      func(context.Context, time.Duration) error
}

// BasicAuth holds HTTP Basic credentials applied to every outgoing request
// that doesn't already carry an Authorization header.
type BasicAuth struct {
	Username string
	Password string
}

type Config struct {
	Timeout             time.Duration
	UserAgent           string
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
	Limiter             *HostLimiter
	// Budget, when non-nil, enforces a scan-wide request count cap and/or a
	// global RPS ceiling layered on top of the per-host Limiter. Returns
	// ErrBudgetExhausted from Do once the count cap is reached. Built via
	// NewBudget; pass nil (the default) for no scan-wide enforcement.
	Budget *Budget
	// Proxy selects the proxy URL for each request. Ignored when Transport
	// is set; otherwise nil means http.ProxyFromEnvironment.
	Proxy func(*http.Request) (*url.URL, error)
	// Transport, if set, replaces the default http.Transport entirely
	// used by the smart proxy pool so it can both pick proxies and observe
	// per-request outcomes. When non-nil, Proxy / MaxIdleConnsPerHost /
	// MaxConnsPerHost are ignored.
	Transport http.RoundTripper
	// MaxRetries is the number of *additional* attempts Do makes after a
	// 429 / 503 response on an idempotent request. 0 (the default) disables
	// retry, preserving the original single-shot behavior.
	MaxRetries int
	// MaxRetryWait caps how long a Retry-After header can ask us to sleep
	// for a single retry. Zero means "use a sensible default" (30s).
	MaxRetryWait time.Duration
	// Jar, when non-nil, stores and replays cookies across requests via the
	// underlying http.Client. Callers can pre-seed it (e.g. session cookies)
	// before passing it in.
	Jar http.CookieJar
	// BasicAuth, when non-nil, applies HTTP Basic credentials to every
	// outgoing request that doesn't already carry an Authorization header.
	BasicAuth *BasicAuth
	// BearerToken, when non-empty, sets `Authorization: Bearer <token>` on
	// every request that doesn't already carry an Authorization header.
	// Ignored when BasicAuth is also set.
	BearerToken string
	// ExtraHeaders are applied to every outgoing request. Caller-set headers
	// on a specific request win; otherwise these are added in. Useful for
	// custom auth tokens (e.g. X-API-Key) or canary identifiers.
	ExtraHeaders http.Header
	// Middlewares run, in order, just before each outbound request. They can
	// mutate the request or short-circuit the call with an error. See
	// RequestMiddleware for the contract; SessionSentinel and CSRFTokenSource
	// are the in-tree implementations.
	Middlewares []RequestMiddleware
	// TLSClientConfig, when set, is cloned onto the default http.Transport
	// New constructs (the cfg.Transport == nil path). Used by the CLI's
	// --ca-file flag to install a custom CA bundle so HTTPS targets with
	// self-signed certs verify cleanly without falling back to
	// InsecureSkipVerify. Ignored when cfg.Transport is non-nil because the
	// caller-supplied transport owns its own TLS settings (e.g. the proxy
	// pool's NewTransport).
	TLSClientConfig *tls.Config
}

func New(cfg Config) *Client {
	transport := cfg.Transport
	if transport == nil {
		if cfg.MaxIdleConnsPerHost == 0 {
			cfg.MaxIdleConnsPerHost = 32
		}
		if cfg.MaxConnsPerHost == 0 {
			cfg.MaxConnsPerHost = 64
		}
		proxy := cfg.Proxy
		if proxy == nil {
			proxy = http.ProxyFromEnvironment
		}
		t := &http.Transport{
			Proxy: proxy,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          256,
			MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
			MaxConnsPerHost:       cfg.MaxConnsPerHost,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		if cfg.TLSClientConfig != nil {
			t.TLSClientConfig = cfg.TLSClientConfig.Clone()
		}
		transport = t
	}
	maxWait := cfg.MaxRetryWait
	if maxWait <= 0 {
		maxWait = 30 * time.Second
	}
	return &Client{
		http: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
			Jar:       cfg.Jar,
		},
		httpNoFollow: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
			Jar:       cfg.Jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		userAgent:    cfg.UserAgent,
		limiter:      cfg.Limiter,
		budget:       cfg.Budget,
		maxRetries:   cfg.MaxRetries,
		maxRetryWait: maxWait,
		basicAuth:    cfg.BasicAuth,
		bearerToken:  cfg.BearerToken,
		extraHeaders: cfg.ExtraHeaders.Clone(),
		middlewares:  append([]RequestMiddleware(nil), cfg.Middlewares...),
		nowFn:        time.Now,
		sleepFn:      sleepCtx,
	}
}

// Jar returns the cookie jar wired into the underlying http.Client (may be
// nil). Exposed so the CLI can pre-seed cookies after constructing the client.
func (c *Client) Jar() http.CookieJar { return c.http.Jar }

// ProbeClient returns an *http.Client suitable for a RequestMiddleware's own
// internal requests (e.g. SessionSentinel's liveness ping, CSRFTokenSource's
// source-page fetch). It shares cfg.Jar (so probes carry the same cookies the
// scan does), cfg.Transport (so probes route through the same proxy pool),
// and cfg.Timeout, but does NOT run the middleware chain - that's the whole
// point: calls made through this client cannot recurse back into the
// middleware that owns them.
//
// When cfg.Transport is nil, http.DefaultTransport is used. Pass the same
// Config you're about to hand to New so the probe client matches the scan
// client exactly.
func ProbeClient(cfg Config) *http.Client {
	transport := cfg.Transport
	if transport == nil {
		if cfg.TLSClientConfig != nil {
			// Clone DefaultTransport so the custom TLS config doesn't leak
			// into other callers that share http.DefaultTransport.
			base := http.DefaultTransport.(*http.Transport).Clone()
			base.TLSClientConfig = cfg.TLSClientConfig.Clone()
			transport = base
		} else {
			transport = http.DefaultTransport
		}
	}
	return &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		Jar:       cfg.Jar,
	}
}

// Do issues req, applying the host limiter and default User-Agent. The
// caller-provided ctx takes precedence over any context already attached to
// req. Callers may set their own User-Agent header to override the default.
//
// When MaxRetries > 0 and the request is idempotent (GET/HEAD/OPTIONS), a
// 429 or 503 response triggers a retry after sleeping for the Retry-After
// header value (capped by MaxRetryWait) or an exponential backoff fallback.
// Each such response also penalizes the host limiter so subsequent requests
// to that host slow down.
//
// Transport errors (dial, TLS, RST, read timeout) on an idempotent request
// also retry, using the same exponential backoff. Transport failures don't
// penalize the host limiter, since they say nothing about target pushback.
// ctx cancellation short-circuits the loop.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return c.doWith(ctx, req, c.http)
}

// DoNoFollow is like Do but returns the first response verbatim instead of
// chasing 3xx Location headers. Active checks that need to inspect a
// redirect target - open redirect, SSRF guards, auth-bypass probes - want
// the original response, not the destination it points at.
//
// All other behavior (UA, extra headers, auth, host rate limiter,
// retry-on-429/503) is identical to Do.
func (c *Client) DoNoFollow(ctx context.Context, req *http.Request) (*http.Response, error) {
	return c.doWith(ctx, req, c.httpNoFollow)
}

func (c *Client) doWith(ctx context.Context, req *http.Request, h *http.Client) (*http.Response, error) {
	req = req.WithContext(ctx)
	if c.userAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	for k, vs := range c.extraHeaders {
		if req.Header.Get(k) != "" {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("Authorization") == "" {
		switch {
		case c.basicAuth != nil:
			req.SetBasicAuth(c.basicAuth.Username, c.basicAuth.Password)
		case c.bearerToken != "":
			req.Header.Set("Authorization", "Bearer "+c.bearerToken)
		}
	}
	// Middlewares fire after the static header/auth shims so they can read the
	// outgoing state but before the retry loop so the mutation isn't repeated
	// per attempt. A middleware that needs per-attempt behaviour (e.g. CSRF
	// re-fetch on 403) can stash state on itself and re-run inside Before by
	// inspecting req; for now, every in-tree middleware is happy with one pass.
	for _, mw := range c.middlewares {
		if err := mw.Before(req); err != nil {
			return nil, err
		}
	}

	attempts := 1 + c.maxRetries
	if !canRetry(req) {
		attempts = 1
	}

	var resp *http.Response
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		// Budget runs ahead of the host limiter: an exhausted count cap
		// short-circuits without burning a host slot, and the global RPS
		// shapes flow before per-host pacing. Retries count against the
		// budget too - that's the whole point of a noise ceiling.
		if werr := c.budget.Wait(ctx); werr != nil {
			return nil, werr
		}
		if c.limiter != nil && req.URL != nil {
			if werr := c.limiter.Wait(ctx, req.URL.Host); werr != nil {
				return nil, werr
			}
		}
		resp, err = h.Do(req)
		if err != nil {
			// Transport error (dial, TLS, RST, read timeout, etc.). On
			// an idempotent request, give it another shot with backoff -
			// a transient network blip, or with a proxy pool a single
			// bad proxy, shouldn't sink the whole request. The proxy
			// pool scores each attempt independently, so retrying is
			// what lets it route around a degraded proxy.
			//
			// Bail immediately if ctx is canceled (the error is
			// non-recoverable) or we're out of attempts. Don't penalize
			// the limiter: transport errors aren't target pushback.
			if ctx.Err() != nil || attempt == attempts-1 {
				return nil, err
			}
			wait := c.retryWait(nil, attempt)
			if serr := c.sleepFn(ctx, wait); serr != nil {
				return nil, err
			}
			if req.Body != nil {
				if req.GetBody == nil {
					return nil, err
				}
				body, gerr := req.GetBody()
				if gerr != nil {
					return nil, err
				}
				req.Body = body
			}
			continue
		}
		if !shouldRetryStatus(resp.StatusCode) {
			return resp, nil
		}
		// Target pushed back. Decay the limiter regardless of whether we
		// have retries left, so the next caller to this host slows down.
		if c.limiter != nil && req.URL != nil {
			c.limiter.Penalize(req.URL.Host)
		}
		if attempt == attempts-1 {
			return resp, nil
		}
		wait := c.retryWait(resp, attempt)
		drainAndClose(resp.Body)
		if err := c.sleepFn(ctx, wait); err != nil {
			return nil, err
		}
		if req.Body != nil {
			if req.GetBody == nil {
				return resp, nil
			}
			body, gerr := req.GetBody()
			if gerr != nil {
				return resp, nil
			}
			req.Body = body
		}
	}
	return resp, nil
}

func (c *Client) Get(ctx context.Context, rawurl string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req)
}

func canRetry(req *http.Request) bool {
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func shouldRetryStatus(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable
}

// retryWait derives the per-attempt sleep from Retry-After, capped by
// maxRetryWait. When no Retry-After is present - or resp is nil, as on a
// transport error - falls back to a bounded exponential backoff
// (1s, 2s, 4s, ...).
func (c *Client) retryWait(resp *http.Response, attempt int) time.Duration {
	if resp != nil {
		if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), c.nowFn()); ok {
			if d < 0 {
				d = 0
			}
			if d > c.maxRetryWait {
				d = c.maxRetryWait
			}
			return d
		}
	}
	backoff := time.Second << attempt
	if backoff > c.maxRetryWait {
		backoff = c.maxRetryWait
	}
	return backoff
}

// parseRetryAfter accepts either delta-seconds or an HTTP-date per RFC 7231
// §7.1.3. Returns (0, false) if the header is empty or malformed.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return t.Sub(now), true
	}
	return 0, false
}

// sleepCtx waits d or until ctx is canceled, whichever comes first. A
// zero/negative duration returns immediately.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ReadBody reads up to max bytes from resp.Body. The caller still owns
// closing resp.Body. A nil resp or resp.Body returns (nil, nil).
func ReadBody(resp *http.Response, max int64) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

// ReadBodyCapped is like ReadBody but additionally reports whether the
// response body would have exceeded max. It reads one extra byte past max
// to disambiguate "fits exactly" from "was cut off"; on truncation the
// returned slice is trimmed back to max. Useful when recording bodies into
// Evidence so reports can flag a snippet as a partial capture.
func ReadBodyCapped(resp *http.Response, max int64) ([]byte, bool, error) {
	if resp == nil || resp.Body == nil {
		return nil, false, nil
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > max {
		return buf[:max], true, nil
	}
	return buf, false, nil
}

// SnapshotRequestBody buffers req.Body and reinstalls req.Body / req.GetBody
// so the request remains sendable, returning the captured bytes. The
// truncated flag fires when the body exceeded max; the snapshot is then
// trimmed to max but req.Body still carries the full payload so the actual
// request goes out intact.
//
// Use this from active checks that want to record the exact payload they
// sent into Evidence (the body is consumed by the time Do returns, so the
// snapshot has to be taken before sending). Safe on a nil request or nil
// body - returns (nil, false, nil) in both cases.
func SnapshotRequestBody(req *http.Request, max int64) ([]byte, bool, error) {
	if req == nil || req.Body == nil {
		return nil, false, nil
	}
	full, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, false, err
	}
	req.Body = io.NopCloser(bytes.NewReader(full))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(full)), nil
	}
	req.ContentLength = int64(len(full))
	if int64(len(full)) > max {
		return full[:max], true, nil
	}
	return full, false, nil
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
