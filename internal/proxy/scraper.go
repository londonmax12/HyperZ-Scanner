package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/londonball/hyperz/internal/httpclient"
)

// DefaultSources is a small built-in list of public proxy aggregators. They
// can rot - users can override or extend via -proxy-source.
var DefaultSources = []string{
	"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
	"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000",
	"https://www.proxy-list.download/api/v1/get?type=http",
}

const (
	defaultScrapeTimeout    = 15 * time.Second
	defaultScrapeMaxBytes   = 4 << 20 // 4 MiB per source
	defaultScrapeUserAgent  = "hyperz-proxy-scraper/0.1"
)

type ScrapeConfig struct {
	Sources   []string
	Timeout   time.Duration
	UserAgent string
	MaxBytes  int64
	// OnError, if set, is called for each source that failed; scraping
	// continues with the remaining sources rather than aborting.
	OnError func(source string, err error)
}

// Scrape fetches each source concurrently, extracts host:port entries from
// each response body, and returns deduped proxy URLs (scheme defaults to
// http). Per-source failures are reported via OnError but do not abort the
// scrape - partial results are returned.
func Scrape(ctx context.Context, cfg ScrapeConfig) ([]*url.URL, error) {
	if len(cfg.Sources) == 0 {
		return nil, nil
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultScrapeTimeout
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultScrapeUserAgent
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultScrapeMaxBytes
	}

	// Use a dedicated client with env proxy so the scraper still works
	// behind a corporate proxy. Independent of the scan client to avoid
	// polluting its rate-limit and stats.
	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	type result struct {
		hostports []string
		err       error
		source    string
	}
	results := make(chan result, len(cfg.Sources))

	var wg sync.WaitGroup
	for _, src := range cfg.Sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			hps, err := fetchProxies(ctx, client, src, cfg.UserAgent, cfg.MaxBytes)
			results <- result{hostports: hps, err: err, source: src}
		}(src)
	}
	go func() { wg.Wait(); close(results) }()

	seen := map[string]struct{}{}
	var out []*url.URL
	for r := range results {
		if r.err != nil {
			if cfg.OnError != nil {
				cfg.OnError(r.source, r.err)
			}
			continue
		}
		for _, hp := range r.hostports {
			key := "http://" + hp
			if _, ok := seen[key]; ok {
				continue
			}
			u, err := url.Parse(key)
			if err != nil || u.Host == "" {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, u)
		}
	}
	return out, nil
}

func fetchProxies(ctx context.Context, client *http.Client, source, ua string, maxBytes int64) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := httpclient.ReadBody(resp, maxBytes)
	if err != nil {
		return nil, err
	}
	return extractHostPorts(string(body)), nil
}
