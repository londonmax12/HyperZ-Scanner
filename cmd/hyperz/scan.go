package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/crawler"
	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/proxy"
	"github.com/londonball/hyperz/internal/report"
	"github.com/londonball/hyperz/internal/scanner"
)

type scanConfig struct {
	urls        []string
	urlsFile    string
	timeout     time.Duration
	userAgent   string
	format      string
	mode        string
	concurrency int
	rps         float64
	burst       int
	outputPath  string

	crawl         bool
	crawlDepth    int
	crawlPages    int
	crawlWorkers  int
	crawlSameHost bool

	proxies        []string
	proxiesFile    string
	scrapeProxies  bool
	proxySources   []string
	proxyStatsTopN int
}

func newScanCmd() *cobra.Command {
	var cfg scanConfig

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan one or more URLs for vulnerabilities",
		Long: `Scan one or more URLs for security findings.

Targets come from --url (repeatable) and/or --urls-file (one per line; '-'
reads stdin). With --crawl, each seed URL is recursively crawled and every
discovered page becomes a scan target.

Modes:
  passive (default) — observation-only; safe to run anywhere you may look.
  active            — adds intrusive probes (XSS, SQLi, traversal, ...);
                      only run against systems you are authorized to test.`,
		Example: `  hyperz scan --url https://example.com
  hyperz scan --url https://example.com --format json -o report.json
  hyperz scan --url https://example.com --mode active
  hyperz scan --urls-file targets.txt --proxies-file proxies.txt
  hyperz scan --urls-file targets.txt --scrape-proxies
  hyperz scan --url https://example.com --crawl --max-depth 3`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Allow bare positional URLs as a convenience: `hyperz scan https://a https://b`.
			cfg.urls = append(cfg.urls, args...)
			if len(cfg.urls) == 0 && cfg.urlsFile == "" {
				return fmt.Errorf("provide --url and/or --urls-file (or a URL as a positional arg)")
			}
			parsedMode, err := checks.ParseMode(cfg.mode)
			if err != nil {
				return err
			}
			code := runScan(cmd.Context(), &cfg, parsedMode)
			if code == exitCanceled {
				return fmt.Errorf("canceled")
			}
			if code != exitOK {
				return fmt.Errorf("scan failed")
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringSliceVar(&cfg.urls, "url", nil, "target URL to scan (repeatable)")
	f.StringVar(&cfg.urlsFile, "urls-file", "", "file with one URL per line (use '-' for stdin)")
	f.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "per-request timeout")
	f.StringVar(&cfg.userAgent, "user-agent", "hyperz/0.1", "User-Agent header to send")
	f.StringVar(&cfg.format, "format", "text",
		"output format ("+strings.Join(report.Formats(), "|")+")")
	f.StringVar(&cfg.mode, "mode", string(checks.ModePassive),
		"scan mode: passive (safe, observation-only) | active (also runs intrusive probes)")
	f.IntVar(&cfg.concurrency, "concurrency", 8, "number of targets scanned in parallel")
	f.Float64Var(&cfg.rps, "rate", 5, "max requests per second per host")
	f.IntVar(&cfg.burst, "burst", 5, "per-host rate limiter burst")
	f.StringVarP(&cfg.outputPath, "output", "o", "-", "output path ('-' for stdout)")

	f.BoolVar(&cfg.crawl, "crawl", false, "discover scan targets by crawling from each seed URL")
	f.IntVar(&cfg.crawlDepth, "max-depth", 2, "max crawl depth (0 = only seeds, no link extraction)")
	f.IntVar(&cfg.crawlPages, "max-pages", 100, "max unique pages to enqueue while crawling (0 = unlimited)")
	f.IntVar(&cfg.crawlWorkers, "crawl-workers", 8, "number of parallel crawl fetchers")
	f.BoolVar(&cfg.crawlSameHost, "crawl-same-host", true, "only follow links on seed hosts")

	f.StringSliceVar(&cfg.proxies, "proxy", nil,
		"proxy URL to route requests through, e.g. http://host:port or socks5://host:port (repeatable)")
	f.StringVar(&cfg.proxiesFile, "proxies-file", "", "file with one proxy per line")
	f.BoolVar(&cfg.scrapeProxies, "scrape-proxies", false,
		"fetch proxies from built-in public sources at startup")
	f.StringSliceVar(&cfg.proxySources, "proxy-source", nil,
		"URL of an additional proxy list to scrape (repeatable; implies --scrape-proxies)")
	f.IntVar(&cfg.proxyStatsTopN, "proxy-stats-top", 10,
		"rows of per-proxy stats to print at scan end (0 to hide)")

	return cmd
}

func runScan(ctx context.Context, cfg *scanConfig, mode checks.Mode) int {
	rep, err := report.New(cfg.format)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitFailure
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

	all := registry()
	enabled := checks.Filter(all, mode)
	fmt.Fprintf(os.Stderr, "[scan] mode=%s, %d/%d check(s) enabled\n",
		mode, len(enabled), len(all))

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
func loadProxies(ctx context.Context, cfg *scanConfig) ([]*url.URL, error) {
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
