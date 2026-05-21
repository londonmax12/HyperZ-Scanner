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
	// Proxy selects the proxy URL for each request. Nil means use
	// http.ProxyFromEnvironment; return (nil, nil) from the func to bypass
	// the proxy for a given request.
	Proxy func(*http.Request) (*url.URL, error)
}

func New(cfg Config) *Client {
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
	transport := &http.Transport{
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
	return &Client{
		http:      &http.Client{Timeout: cfg.Timeout, Transport: transport},
		userAgent: cfg.UserAgent,
		limiter:   cfg.Limiter,
	}
}

func (c *Client) Get(ctx context.Context, rawurl string) (*http.Response, error) {
	if c.limiter != nil {
		host, err := hostOf(rawurl)
		if err != nil {
			return nil, err
		}
		if err := c.limiter.Wait(ctx, host); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	return c.http.Do(req)
}

func hostOf(rawurl string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}
