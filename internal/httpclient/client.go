package httpclient

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	http      *http.Client
	userAgent string
	limiter   *HostLimiter
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
	// Transport, if set, replaces the default http.Transport entirely —
	// used by the smart proxy pool so it can both pick proxies and observe
	// per-request outcomes. When non-nil, Proxy / MaxIdleConnsPerHost /
	// MaxConnsPerHost are ignored.
	Transport http.RoundTripper
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
	return &Client{
		http:      &http.Client{Timeout: cfg.Timeout, Transport: transport},
		userAgent: cfg.UserAgent,
		limiter:   cfg.Limiter,
	}
}

// Do issues req, applying the host limiter and default User-Agent. The
// caller-provided ctx takes precedence over any context already attached to
// req. Callers may set their own User-Agent header to override the default.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c.limiter != nil && req.URL != nil {
		if err := c.limiter.Wait(ctx, req.URL.Host); err != nil {
			return nil, err
		}
	}
	req = req.WithContext(ctx)
	if c.userAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	return c.http.Do(req)
}

func (c *Client) Get(ctx context.Context, rawurl string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req)
}
