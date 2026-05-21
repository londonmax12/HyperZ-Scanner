package httpclient

import (
	"context"
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
	userAgent    string
	limiter      *HostLimiter
	maxRetries   int
	maxRetryWait time.Duration
	basicAuth    *BasicAuth
	bearerToken  string
	extraHeaders http.Header
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
		transport = &http.Transport{
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
		userAgent:    cfg.UserAgent,
		limiter:      cfg.Limiter,
		maxRetries:   cfg.MaxRetries,
		maxRetryWait: maxWait,
		basicAuth:    cfg.BasicAuth,
		bearerToken:  cfg.BearerToken,
		extraHeaders: cfg.ExtraHeaders.Clone(),
		nowFn:        time.Now,
		sleepFn:      sleepCtx,
	}
}

// Jar returns the cookie jar wired into the underlying http.Client (may be
// nil). Exposed so the CLI can pre-seed cookies after constructing the client.
func (c *Client) Jar() http.CookieJar { return c.http.Jar }

// Do issues req, applying the host limiter and default User-Agent. The
// caller-provided ctx takes precedence over any context already attached to
// req. Callers may set their own User-Agent header to override the default.
//
// When MaxRetries > 0 and the request is idempotent (GET/HEAD/OPTIONS), a
// 429 or 503 response triggers a retry after sleeping for the Retry-After
// header value (capped by MaxRetryWait) or an exponential backoff fallback.
// Each such response also penalizes the host limiter so subsequent requests
// to that host slow down.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
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

	attempts := 1 + c.maxRetries
	if !canRetry(req) {
		attempts = 1
	}

	var resp *http.Response
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if c.limiter != nil && req.URL != nil {
			if werr := c.limiter.Wait(ctx, req.URL.Host); werr != nil {
				return nil, werr
			}
		}
		resp, err = c.http.Do(req)
		if err != nil {
			// Network/transport error: proxy pool already scored this;
			// don't retry here (avoid double-counting against the proxy).
			return nil, err
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
// maxRetryWait. When no Retry-After is present, falls back to a bounded
// exponential backoff (1s, 2s, 4s, ...).
func (c *Client) retryWait(resp *http.Response, attempt int) time.Duration {
	if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), c.nowFn()); ok {
		if d < 0 {
			d = 0
		}
		if d > c.maxRetryWait {
			d = c.maxRetryWait
		}
		return d
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

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
