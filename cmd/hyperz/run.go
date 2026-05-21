package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"sync/atomic"

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/crawler"
	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/proxy"
	"github.com/londonball/hyperz/internal/report"
	"github.com/londonball/hyperz/internal/scanner"
)

const (
	exitOK       = 0
	exitFailure  = 1
	exitUsage    = 2
	exitCanceled = 130
)

func run(ctx context.Context, cfg *config) int {
	rep, err := report.New(cfg.format)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsage
	}

	out, closeOut, err := openOutput(cfg.outputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitFailure
	}
	defer closeOut()

	proxies, err := loadProxies(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy error:", err)
		return exitFailure
	}
	clientCfg := httpclient.Config{
		Timeout:   cfg.timeout,
		UserAgent: cfg.userAgent,
		Limiter:   httpclient.NewHostLimiter(cfg.rps, cfg.burst),
	}
	var pool *proxy.SmartPool
	if len(proxies) > 0 {
		pool = proxy.NewSmartPool(proxies)
		clientCfg.Transport = proxy.NewTransport(pool, proxy.TransportConfig{})
		fmt.Fprintf(os.Stderr, "[proxy] pool ready: %d proxies (epsilon-greedy on success rate)\n", pool.Len())
	}
	client := httpclient.New(clientCfg)

	all := []checks.Check{
		checks.SecurityHeaders{},
	}
	enabled := checks.Filter(all, cfg.mode)
	fmt.Fprintf(os.Stderr, "[scan] mode=%s, %d/%d check(s) enabled\n",
		cfg.mode, len(enabled), len(all))

	var checkErrors atomic.Int64
	s := scanner.New(client,
		enabled,
		scanner.WithConcurrency(cfg.concurrency),
		scanner.WithErrorHandler(func(target, check string, err error) {
			checkErrors.Add(1)
			fmt.Fprintf(os.Stderr, "[error] %s/%s: %v\n", check, target, err)
		}),
	)

	targets := make(chan string, cfg.concurrency)
	findings := make(chan checks.Finding, 64)

	feedErr := make(chan error, 1)
	if cfg.crawl {
		seeds, err := collectSeeds(cfg.urls, cfg.urlsFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "input error:", err)
			return exitFailure
		}
		cr := crawler.New(client, crawler.Config{
			Workers:  cfg.crawlWorkers,
			MaxDepth: cfg.crawlDepth,
			MaxPages: cfg.crawlPages,
			SameHost: cfg.crawlSameHost,
		}, crawler.WithErrorHandler(func(target string, err error) {
			fmt.Fprintf(os.Stderr, "[crawl] %s: %v\n", target, err)
		}))
		go func() { feedErr <- cr.Crawl(ctx, seeds, targets) }()
	} else {
		go func() {
			defer close(targets)
			feedErr <- feed(ctx, targets, cfg.urls, cfg.urlsFile)
		}()
	}

	scanErr := make(chan error, 1)
	go func() { scanErr <- s.ScanAll(ctx, targets, findings) }()

	exit := exitOK
	if err := rep.Write(ctx, out, findings); err != nil {
		fmt.Fprintln(os.Stderr, "report failed:", err)
		exit = exitFailure
	}
	if err := <-scanErr; err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "scan error:", err)
		exit = exitFailure
	}
	if err := <-feedErr; err != nil {
		fmt.Fprintln(os.Stderr, "input error:", err)
		exit = exitFailure
	}
	if n := checkErrors.Load(); n > 0 {
		fmt.Fprintf(os.Stderr, "%d check error(s) occurred\n", n)
		if exit == exitOK {
			exit = exitFailure
		}
	}
	if ctx.Err() != nil && exit == exitOK {
		exit = exitCanceled
	}
	if pool != nil {
		printProxyStats(os.Stderr, pool, cfg.proxyStatsTopN)
	}
	return exit
}

// loadProxies combines inline + file + scraped sources into a single deduped
// list. Inline/file errors are fatal (user-supplied input); scrape errors are
// per-source and reported but non-fatal so a single dead source doesn't
// disable proxying entirely.
func loadProxies(ctx context.Context, cfg *config) ([]*url.URL, error) {
	manual, err := proxy.Load(cfg.proxies, cfg.proxiesFile)
	if err != nil {
		return nil, err
	}
	scrape := cfg.scrapeProxies || len(cfg.proxySources) > 0
	if !scrape {
		return manual, nil
	}
	sources := append([]string{}, proxy.DefaultSources...)
	sources = append(sources, cfg.proxySources...)
	fmt.Fprintf(os.Stderr, "[proxy] scraping %d source(s)...\n", len(sources))
	scraped, err := proxy.Scrape(ctx, proxy.ScrapeConfig{
		Sources:   sources,
		UserAgent: cfg.userAgent,
		OnError: func(src string, err error) {
			fmt.Fprintf(os.Stderr, "[proxy] source %s: %v\n", src, err)
		},
	})
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "[proxy] scraped %d proxies\n", len(scraped))

	// Dedupe across manual + scraped (manual entries take precedence so a
	// non-http scheme the user specified isn't overwritten by a bare scrape).
	seen := map[string]struct{}{}
	out := make([]*url.URL, 0, len(manual)+len(scraped))
	for _, u := range manual {
		if _, ok := seen[u.String()]; ok {
			continue
		}
		seen[u.String()] = struct{}{}
		out = append(out, u)
	}
	for _, u := range scraped {
		if _, ok := seen[u.String()]; ok {
			continue
		}
		seen[u.String()] = struct{}{}
		out = append(out, u)
	}
	return out, nil
}

func printProxyStats(w io.Writer, pool *proxy.SmartPool, topN int) {
	stats := pool.Stats()
	used := 0
	for _, s := range stats {
		if s.Requests > 0 {
			used++
		}
	}
	if used == 0 {
		return
	}
	fmt.Fprintf(w, "[proxy] used %d/%d; overall block rate %.1f%%\n",
		used, pool.Len(), pool.OverallBlockRate()*100)
	if topN <= 0 {
		return
	}
	limit := topN
	if limit > used {
		limit = used
	}
	for i := 0; i < limit; i++ {
		s := stats[i]
		fmt.Fprintf(w, "[proxy] %s req=%d ok=%d block=%d err=%d ok-rate=%.0f%% block-rate=%.0f%%\n",
			s.URL, s.Requests, s.Successes, s.Blocks, s.Errors,
			s.SuccessRate()*100, s.BlockRate()*100)
	}
}
