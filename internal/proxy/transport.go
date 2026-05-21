package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// TransportConfig mirrors the relevant fields of http.Transport defaults used
// by the scan client, so the proxy transport can be built standalone.
type TransportConfig struct {
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
}

// NewTransport returns an http.RoundTripper that, for each request, selects a
// proxy from the pool, routes the request through it, and records the outcome
// back into the pool. Selection happens here (not in http.Transport.Proxy)
// because we need to know which proxy was used to attribute the outcome.
func NewTransport(pool *SmartPool, cfg TransportConfig) http.RoundTripper {
	if cfg.MaxIdleConnsPerHost == 0 {
		cfg.MaxIdleConnsPerHost = 32
	}
	if cfg.MaxConnsPerHost == 0 {
		cfg.MaxConnsPerHost = 64
	}
	inner := &http.Transport{
		Proxy: proxyFromContext,
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
	return &poolTransport{pool: pool, inner: inner}
}

type poolTransport struct {
	pool  *SmartPool
	inner *http.Transport
}

type ctxKey struct{}

var proxyKey ctxKey

func proxyFromContext(req *http.Request) (*url.URL, error) {
	if e, ok := req.Context().Value(proxyKey).(*proxyEntry); ok && e != nil {
		return e.url, nil
	}
	return nil, nil
}

func (t *poolTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	entry := t.pool.next()
	if entry != nil {
		ctx := context.WithValue(req.Context(), proxyKey, entry)
		req = req.WithContext(ctx)
	}
	resp, err := t.inner.RoundTrip(req)
	if entry != nil {
		t.pool.Record(entry, classify(resp, err))
	}
	return resp, err
}

// classify maps a (response, error) pair to an Outcome. User cancellation
// isn't the proxy's fault, so we don't ding the score for it; deadline
// exceeded does count, since a too-slow proxy is a low-quality proxy.
func classify(resp *http.Response, err error) Outcome {
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return OutcomeSuccess
		}
		return OutcomeError
	}
	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests:
		return OutcomeBlock
	case http.StatusProxyAuthRequired,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return OutcomeError
	default:
		return OutcomeSuccess
	}
}
