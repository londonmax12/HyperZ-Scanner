package main

import (
	"context"
	"fmt"
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

	proxies, err := proxy.Load(cfg.proxies, cfg.proxiesFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy error:", err)
		return exitFailure
	}
	clientCfg := httpclient.Config{
		Timeout:   cfg.timeout,
		UserAgent: cfg.userAgent,
		Limiter:   httpclient.NewHostLimiter(cfg.rps, cfg.burst),
	}
	if len(proxies) > 0 {
		pool := proxy.NewPool(proxies)
		clientCfg.Proxy = pool.ProxyFunc()
		fmt.Fprintf(os.Stderr, "[proxy] loaded %d proxies (round-robin)\n", pool.Len())
	}
	client := httpclient.New(clientCfg)

	var checkErrors atomic.Int64
	s := scanner.New(client,
		[]checks.Check{
			checks.SecurityHeaders{},
		},
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
	return exit
}
