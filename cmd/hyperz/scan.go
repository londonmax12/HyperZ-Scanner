package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/crawler"
	"github.com/londonball/hyperz/internal/fingerprint"
	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/proxy"
	"github.com/londonball/hyperz/internal/report"
	"github.com/londonball/hyperz/internal/scanner"
	"github.com/londonball/hyperz/internal/scope"
)

type scanConfig struct {
	urls        []string
	urlsFile    string
	timeout     time.Duration
	userAgent   string
	format      string
	mode        string
	concurrency  int
	rps          float64
	burst        int
	maxRetries   int
	maxRetryWait time.Duration
	outputPath   string

	logLevel  string
	logFormat string

	crawl        bool
	crawlPages   int
	crawlWorkers int

	noFingerprint bool

	scopeHosts       []string
	scopeAnyHost     bool
	scopePorts       string
	scopePathInclude []string
	scopePathExclude []string
	scopeMaxDepth    int

	proxies        []string
	proxiesFile    string
	scrapeProxies  bool
	proxySources   []string
	proxyStatsTopN int

	cookies     []string
	cookiesFile string
	authBasic   string
	authBearer  string
	headers     []string
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
  hyperz scan --url https://example.com --mode aggressive
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
			level, err := checks.ParseLevel(cfg.mode)
			if err != nil {
				return err
			}
			code := runScan(cmd.Context(), &cfg, level)
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
	f.StringVar(&cfg.mode, "mode", checks.LevelPassive.String(),
		"scan level: passive (safe, observation-only) | default (low-risk crafted probes) | aggressive (heavy fuzzing). "+
			"Higher levels include everything below; checks above the requested level are skipped.")
	f.IntVar(&cfg.concurrency, "concurrency", 8, "number of targets scanned in parallel")
	f.Float64Var(&cfg.rps, "rate", 5, "max requests per second per host")
	f.IntVar(&cfg.burst, "burst", 5, "per-host rate limiter burst")
	f.IntVar(&cfg.maxRetries, "max-retries", 2,
		"retry idempotent requests this many times on 429/503 (0 disables)")
	f.DurationVar(&cfg.maxRetryWait, "max-retry-wait", 30*time.Second,
		"cap on a single Retry-After sleep")
	f.StringVarP(&cfg.outputPath, "output", "o", "-", "output path ('-' for stdout)")
	f.StringVar(&cfg.logLevel, "log-level", "info",
		"log verbosity: debug | info | warn | error (debug surfaces per-target skip events)")
	f.StringVar(&cfg.logFormat, "log-format", "text",
		"log output format: text (key=value) | json (one record per line, pipe to jq)")

	f.BoolVar(&cfg.crawl, "crawl", false, "discover scan targets by crawling from each seed URL")
	f.IntVar(&cfg.crawlPages, "max-pages", 100, "max unique pages to enqueue while crawling (0 = unlimited)")
	f.IntVar(&cfg.crawlWorkers, "crawl-workers", 8, "number of parallel crawl fetchers")

	f.BoolVar(&cfg.noFingerprint, "no-fingerprint", false,
		"disable stack detection; runs every check against every target")

	f.StringSliceVar(&cfg.scopeHosts, "scope-host", nil,
		"hostname allowed in scope (repeatable; defaults to the seed hosts when empty)")
	f.BoolVar(&cfg.scopeAnyHost, "scope-any-host", false,
		"disable host filtering (let the crawler follow links to any host)")
	f.StringVar(&cfg.scopePorts, "scope-ports", "",
		"port or port range allowed in scope, e.g. 443 or 8000-8999 (empty = any)")
	f.StringSliceVar(&cfg.scopePathInclude, "scope-path-include", nil,
		"regex a URL path must match to be in scope (repeatable; ANY match passes)")
	f.StringSliceVar(&cfg.scopePathExclude, "scope-path-exclude", nil,
		"regex a URL path must NOT match (repeatable; ANY match excludes)")
	f.IntVar(&cfg.scopeMaxDepth, "scope-max-depth", 2,
		"max crawl depth from any seed (0 = seeds only; -1 = unlimited)")

	f.StringSliceVar(&cfg.proxies, "proxy", nil,
		"proxy URL to route requests through, e.g. http://host:port or socks5://host:port (repeatable)")
	f.StringVar(&cfg.proxiesFile, "proxies-file", "", "file with one proxy per line")
	f.BoolVar(&cfg.scrapeProxies, "scrape-proxies", false,
		"fetch proxies from built-in public sources at startup")
	f.StringSliceVar(&cfg.proxySources, "proxy-source", nil,
		"URL of an additional proxy list to scrape (repeatable; implies --scrape-proxies)")
	f.IntVar(&cfg.proxyStatsTopN, "proxy-stats-top", 10,
		"rows of per-proxy stats to print at scan end (0 to hide)")

	f.StringSliceVar(&cfg.cookies, "cookie", nil,
		"cookie to send with every request; 'name=value' or 'name=value; name2=value2' (repeatable)")
	f.StringVar(&cfg.cookiesFile, "cookies-file", "",
		"file with cookies (Netscape format from curl/browsers, or 'name=value' per line)")
	f.StringVar(&cfg.authBasic, "auth-basic", "",
		"HTTP Basic credentials as user:pass; applied to every request lacking Authorization")
	f.StringVar(&cfg.authBearer, "auth-bearer", "",
		"Bearer token; sent as 'Authorization: Bearer <token>' when no Authorization is set")
	f.StringSliceVar(&cfg.headers, "header", nil,
		"extra header 'Name: Value' sent on every request (repeatable; e.g. an API key)")

	return cmd
}

func runScan(ctx context.Context, cfg *scanConfig, level checks.Level) int {
	log, err := newLogger(cfg.logLevel, cfg.logFormat, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitFailure
	}

	rep, err := report.New(cfg.format)
	if err != nil {
		log.Error("report init failed", "err", err)
		return exitFailure
	}

	out, closeOut, err := openOutput(cfg.outputPath)
	if err != nil {
		log.Error("open output failed", "path", cfg.outputPath, "err", err)
		return exitFailure
	}
	defer closeOut()

	proxies, err := loadProxies(ctx, log, cfg)
	if err != nil {
		log.Error("proxy load failed", "err", err)
		return exitFailure
	}

	seeds, err := collectSeeds(cfg.urls, cfg.urlsFile)
	if err != nil {
		log.Error("input load failed", "err", err)
		return exitFailure
	}

	clientCfg := httpclient.Config{
		Timeout:      cfg.timeout,
		UserAgent:    cfg.userAgent,
		Limiter:      httpclient.NewHostLimiter(cfg.rps, cfg.burst),
		MaxRetries:   cfg.maxRetries,
		MaxRetryWait: cfg.maxRetryWait,
	}
	if err := applyAuthConfig(&clientCfg, cfg, seeds, log); err != nil {
		log.Error("auth config failed", "err", err)
		return exitFailure
	}
	var pool *proxy.SmartPool
	if len(proxies) > 0 {
		pool = proxy.NewSmartPool(proxies)
		clientCfg.Transport = proxy.NewTransport(pool, proxy.TransportConfig{})
		log.Info("proxy pool ready", "proxies", pool.Len(), "strategy", "epsilon-greedy")
	}
	client := httpclient.New(clientCfg)

	sc, err := buildScope(cfg, seeds)
	if err != nil {
		log.Error("scope build failed", "err", err)
		return exitFailure
	}
	if hosts := sc.Hosts(); len(hosts) > 0 {
		log.Info("scope configured", "hosts", strings.Join(hosts, ","), "depth", sc.MaxDepth())
	} else {
		log.Info("scope configured", "hosts", "*", "depth", sc.MaxDepth())
	}

	all := registry()
	enabled := checks.Filter(all, level)
	log.Info("scan starting", "scan_level", level.String(), "enabled", len(enabled), "total", len(all))

	scannerOpts := []scanner.Option{
		scanner.WithConcurrency(cfg.concurrency),
		scanner.WithScope(sc),
		scanner.WithSkipHandler(func(target, check, reason string) {
			log.Debug("check skipped", "check", check, "target", target, "reason", reason)
		}),
	}
	// stacks is shared with the report writer. OnDetect fires inside the
	// fingerprint cache's sync.Once, so we only need the mutex to guard the
	// concurrent map writes; reads happen after the findings channel closes.
	var stacksMu sync.Mutex
	stacks := map[string]*fingerprint.Stack{}
	if !cfg.noFingerprint {
		det := fingerprint.New(client,
			fingerprint.WithOnDetect(func(host string, stack *fingerprint.Stack) {
				stacksMu.Lock()
				stacks[host] = stack
				stacksMu.Unlock()
				log.Info("fingerprint detected",
					"host", host,
					"stack", stack.Summary(),
					"confidence", stack.Confidence)
			}),
		)
		scannerOpts = append(scannerOpts, scanner.WithFingerprint(det))
	} else {
		log.Info("fingerprint disabled", "reason", "--no-fingerprint")
	}

	var checkErrors atomic.Int64
	scannerOpts = append(scannerOpts, scanner.WithErrorHandler(func(target, check string, err error) {
		checkErrors.Add(1)
		log.Warn("check error", "check", check, "target", target, "err", err)
	}))
	s := scanner.New(client, enabled, scannerOpts...)

	targets := make(chan string, cfg.concurrency)
	findings := make(chan checks.Finding, 64)

	feedErr := make(chan error, 1)
	if cfg.crawl {
		cr := crawler.New(client, crawler.Config{
			Workers:  cfg.crawlWorkers,
			MaxPages: cfg.crawlPages,
			Scope:    sc,
		}, crawler.WithErrorHandler(func(target string, err error) {
			log.Warn("crawl error", "target", target, "err", err)
		}))
		go func() { feedErr <- cr.Crawl(ctx, seeds, targets) }()
	} else {
		go func() {
			defer close(targets)
			feedErr <- feedSeeds(ctx, targets, seeds)
		}()
	}

	scanErr := make(chan error, 1)
	go func() { scanErr <- s.ScanAll(ctx, targets, findings) }()

	// Dedupe before reporting so site-wide issues (e.g. missing security
	// headers) don't fire once per crawled page. Checks opt in by setting
	// Finding.DedupeKey; findings without a key pass through unchanged.
	deduped := report.Dedupe(findings)

	exit := exitOK
	if err := rep.Write(ctx, out, deduped, report.Metadata{Stacks: stacks}); err != nil {
		log.Error("report write failed", "err", err)
		exit = exitFailure
	}
	if err := <-scanErr; err != nil && ctx.Err() == nil {
		log.Error("scan failed", "err", err)
		exit = exitFailure
	}
	if err := <-feedErr; err != nil {
		log.Error("input feed failed", "err", err)
		exit = exitFailure
	}
	if n := checkErrors.Load(); n > 0 {
		log.Warn("check errors occurred", "count", n)
		if exit == exitOK {
			exit = exitFailure
		}
	}
	if ctx.Err() != nil && exit == exitOK {
		exit = exitCanceled
	}
	if pool != nil {
		logProxyStats(log, pool, cfg.proxyStatsTopN)
	}
	return exit
}

// buildScope assembles the scan scope from CLI flags. When --scope-host is
// empty (and --scope-any-host is not set), the seed hosts are added as the
// allowlist so default behavior matches the old "same-host" crawler default.
func buildScope(cfg *scanConfig, seeds []string) (*scope.Scope, error) {
	sc, err := scope.New(scope.Config{
		Hosts:       cfg.scopeHosts,
		Ports:       cfg.scopePorts,
		PathInclude: cfg.scopePathInclude,
		PathExclude: cfg.scopePathExclude,
		MaxDepth:    cfg.scopeMaxDepth,
	})
	if err != nil {
		return nil, err
	}
	if cfg.scopeAnyHost {
		// User opted out of host filtering entirely. Honor --scope-host if
		// they also provided it (treat as a soft restriction); otherwise the
		// scope's host set stays empty (any host allowed).
		return sc, nil
	}
	if len(cfg.scopeHosts) == 0 {
		for _, s := range seeds {
			u, err := url.Parse(s)
			if err != nil {
				continue
			}
			sc.AllowHost(u.Hostname())
		}
	}
	return sc, nil
}

// loadProxies combines inline + file + scraped sources into a single deduped
// list. Inline/file errors are fatal (user-supplied input); scrape errors are
// per-source and reported but non-fatal so a single dead source doesn't
// disable proxying entirely.
func loadProxies(ctx context.Context, log *slog.Logger, cfg *scanConfig) ([]*url.URL, error) {
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
	log.Info("proxy scraping", "sources", len(sources))
	scraped, err := proxy.Scrape(ctx, proxy.ScrapeConfig{
		Sources:   sources,
		UserAgent: cfg.userAgent,
		OnError: func(src string, err error) {
			log.Warn("proxy source failed", "source", src, "err", err)
		},
	})
	if err != nil {
		return nil, err
	}
	log.Info("proxy scraped", "proxies", len(scraped))

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

func logProxyStats(log *slog.Logger, pool *proxy.SmartPool, topN int) {
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
	log.Info("proxy pool summary",
		"used", used,
		"total", pool.Len(),
		"block_rate", pool.OverallBlockRate())
	if topN <= 0 {
		return
	}
	limit := topN
	if limit > used {
		limit = used
	}
	for i := 0; i < limit; i++ {
		s := stats[i]
		log.Info("proxy stat",
			"url", s.URL.String(),
			"req", s.Requests,
			"ok", s.Successes,
			"block", s.Blocks,
			"err", s.Errors,
			"ok_rate", s.SuccessRate(),
			"block_rate", s.BlockRate())
	}
}
