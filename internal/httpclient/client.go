package httpclient

import (
	"context"
	"net/http"
	"time"
)

type Client struct {
	http      *http.Client
	userAgent string
}

func New(timeout time.Duration, userAgent string) *Client {
	return &Client{
		http:      &http.Client{Timeout: timeout},
		userAgent: userAgent,
	}
}

func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	return c.http.Do(req)
}
