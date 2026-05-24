package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/crawler"
	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/proxy"
	"github.com/londonmax12/hyperz/internal/report"
	"github.com/londonmax12/hyperz/internal/scanner"
	"github.com/londonmax12/hyperz/internal/scope"
)

type scanConfig struct {
	urls             []string
	urlsFile         string
	timeout          time.Duration
	userAgent        string
	format           string
	mode             string
	concurrency      int
	checkConcurrency int
	rps              float64
	burst            int
	maxRequests      int64
	globalRPS        float64
	globalBurst      int
	maxRetries       int
	maxRetryWait     time.Duration
	outputPath       string

	logLevel  string
	logFormat string

	crawl        bool
	crawlPages   int
	crawlWorkers int
	apiDiscovery bool
	pollute      bool

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

	sessionCheckURL     string
	sessionCheckPattern string
	sessionCheckEvery   int

	csrfTokenSource string
	csrfInject      string
	csrfHeaderName  string
	csrfParam       string

	baselinePath   string
	baselineFormat string
	failOn         string
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
  passive (default) - observation-only; safe to run anywhere you may look.
  default           - adds low-risk crafted probes (XSS, SQLi, traversal,
                      ...); only run against systems you are authorized to
                      test.
  aggressive        - adds noisy or heavy fuzzing on top of default; likely
                      to trip rate limits or WAFs.`,
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
			switch code {
			case exitOK:
				return nil
			case exitCanceled:
				// cobra strips RunE errors and main.go exits 2; override the
				// exit code in main.go's deferred path is awkward, so call
				// os.Exit directly to preserve 130 for shells that look at it.
				os.Exit(exitCanceled)
				return nil
			case exitFindings:
				os.Exit(exitFindings)
				return nil
			default:
				return fmt.Errorf("scan failed")
			}
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
	f.IntVar(&cfg.checkConcurrency, "check-concurrency", 16,
		"max checks running in parallel per target (0 = unlimited)")
	f.Float64Var(&cfg.rps, "rate", 5, "max requests per second per host")
	f.IntVar(&cfg.burst, "burst", 5, "per-host rate limiter burst")
	f.Int64Var(&cfg.maxRequests, "max-requests", 0,
		"scan-wide cap on total HTTP requests; once hit, in-flight findings are flushed "+
			"and further requests fail fast as scan-request-budget-exhausted (0 = unlimited)")
	f.Float64Var(&cfg.globalRPS, "rate-global", 0,
		"scan-wide RPS ceiling layered on top of --rate so fan-out across many hosts "+
			"can't slip past a global noise budget (0 = unlimited)")
	f.IntVar(&cfg.globalBurst, "burst-global", 1,
		"burst for --rate-global; default 1 keeps the global pace strict")
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
	f.BoolVar(&cfg.apiDiscovery, "api-discovery", true,
		"probe well-known OpenAPI/Swagger paths on each seed origin and enqueue every documented endpoint (requires --crawl)")
	f.BoolVar(&cfg.pollute, "pollute", false,
		"opt in to state-mutating discovery and checks: walks select-driven navigation forms "+
			"(POSTs every <option> through and queues the redirect target) and enables the "+
			"proto-pollution check, which leaves a (best-effort cleaned-up) modification on a "+
			"Node target. Off by default; turn on only against systems you may safely mutate.")

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

	f.StringVar(&cfg.sessionCheckURL, "session-check-url", "",
		"URL to GET periodically to verify the session is still authenticated; "+
			"the scan halts with session-lost when the probe fails")
	f.StringVar(&cfg.sessionCheckPattern, "session-check-pattern", "",
		"regex the --session-check-url response body must match for the session "+
			"to be considered alive (empty = only require HTTP 200)")
	f.IntVar(&cfg.sessionCheckEvery, "session-check-every", 50,
		"fire the session liveness probe every N requests (>=1)")

	f.StringVar(&cfg.csrfTokenSource, "csrf-token-source", "",
		"URL to GET once and parse for a CSRF token; the token is then "+
			"auto-attached to every POST/PUT/PATCH/DELETE the scanner sends")
	f.StringVar(&cfg.csrfInject, "csrf-inject", "auto",
		"where to attach the CSRF token: auto (form for hidden inputs, header "+
			"for <meta>) | form | header")
	f.StringVar(&cfg.csrfHeaderName, "csrf-header-name", httpclient.DefaultCSRFHeader,
		"request header name used when --csrf-inject=header")
	f.StringVar(&cfg.csrfParam, "csrf-param", "",
		"override the form-field name parsed from --csrf-token-source "+
			"(rare; use when the displayed form name and the field the server expects differ)")

	f.StringVar(&cfg.baselinePath, "baseline", "",
		"previous scan report to diff against; findings are annotated new|persisting|resolved. "+
			"Format autodetected from extension/content; only json|jsonl|csv|sarif round-trip cleanly enough to use")
	f.StringVar(&cfg.baselineFormat, "baseline-format", "",
		"override baseline format detection (json|jsonl|csv|sarif)")
	f.StringVar(&cfg.failOn, "fail-on", "medium",
		"exit 1 when any finding's severity is at or above this level "+
			"(info|low|medium|high|critical|none). With --baseline, only NEW findings count toward the threshold")

	return cmd
}

func runScan(ctx context.Context, cfg *scanConfig, level checks.Level) int {
	log, err := newLogger(cfg.logLevel, cfg.logFormat, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitScanError
	}

	failOnRank, gateEnabled, err := parseFailOn(cfg.failOn)
	if err != nil {
		log.Error("invalid --fail-on", "err", err)
		return exitScanError
	}

	var baseline *report.Baseline
	if cfg.baselinePath != "" {
		baseline, err = report.LoadBaseline(cfg.baselinePath, cfg.baselineFormat)
		if err != nil {
			log.Error("baseline load failed", "path", cfg.baselinePath, "err", err)
			return exitScanError
		}
		log.Info("baseline loaded",
			"path", cfg.baselinePath,
			"format", baseline.Format,
			"keyed", len(baseline.Keys),
			"unkeyed", len(baseline.NoKey))
		if len(baseline.NoKey) > 0 {
			log.Warn("baseline entries without dedupe_key are excluded from diff",
				"count", len(baseline.NoKey))
		}
	}

	rep, err := report.New(cfg.format)
	if err != nil {
		log.Error("report init failed", "err", err)
		return exitScanError
	}

	out, closeOut, err := openOutput(cfg.outputPath)
	if err != nil {
		log.Error("open output failed", "path", cfg.outputPath, "err", err)
		return exitScanError
	}
	defer closeOut()

	proxies, err := loadProxies(ctx, log, cfg)
	if err != nil {
		log.Error("proxy load failed", "err", err)
		return exitScanError
	}

	seeds, err := collectSeeds(cfg.urls, cfg.urlsFile)
	if err != nil {
		log.Error("input load failed", "err", err)
		return exitScanError
	}

	budget := httpclient.NewBudget(cfg.maxRequests, cfg.globalRPS, cfg.globalBurst)
	if budget != nil {
		log.Info("scan-wide budget enabled",
			"max_requests", cfg.maxRequests,
			"global_rps", cfg.globalRPS,
			"global_burst", cfg.globalBurst)
	}
	clientCfg := httpclient.Config{
		Timeout:      cfg.timeout,
		UserAgent:    cfg.userAgent,
		Limiter:      httpclient.NewHostLimiter(cfg.rps, cfg.burst),
		Budget:       budget,
		MaxRetries:   cfg.maxRetries,
		MaxRetryWait: cfg.maxRetryWait,
	}
	if err := applyAuthConfig(&clientCfg, cfg, seeds, log); err != nil {
		log.Error("auth config failed", "err", err)
		return exitScanError
	}
	var pool *proxy.SmartPool
	if len(proxies) > 0 {
		pool = proxy.NewSmartPool(proxies)
		clientCfg.Transport = proxy.NewTransport(pool, proxy.TransportConfig{})
		log.Info("proxy pool ready", "proxies", pool.Len(), "strategy", "epsilon-greedy")
	}
	// Session sentinel + CSRF middleware build after the proxy pool is in
	// place so their internal probes route through the same transport (and
	// therefore the same exit IPs) as the rest of the scan.
	if err := applyActiveSessionConfig(&clientCfg, cfg, log); err != nil {
		log.Error("session/csrf config failed", "err", err)
		return exitScanError
	}
	client := httpclient.New(clientCfg)

	sc, err := buildScope(cfg, seeds)
	if err != nil {
		log.Error("scope build failed", "err", err)
		return exitScanError
	}
	if hosts := sc.Hosts(); len(hosts) > 0 {
		log.Info("scope configured", "hosts", strings.Join(hosts, ","), "depth", sc.MaxDepth())
	} else {
		log.Info("scope configured", "hosts", "*", "depth", sc.MaxDepth())
	}

	all := registry(cfg.pollute)
	enabled := checks.Filter(all, level)
	log.Info("scan starting",
		"scan_level", level.String(),
		"enabled", len(enabled),
		"total", len(all),
		"pollute", cfg.pollute)

	scannerOpts := []scanner.Option{
		scanner.WithConcurrency(cfg.concurrency),
		scanner.WithCheckConcurrency(cfg.checkConcurrency),
		scanner.WithScope(sc),
		scanner.WithLevel(level),
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
			fingerprint.WithFallbackProbes(fingerprintFallbackProbes(level)...),
		)
		scannerOpts = append(scannerOpts, scanner.WithFingerprint(det))
	} else {
		log.Info("fingerprint disabled", "reason", "--no-fingerprint")
	}

	var checkErrors atomic.Int64
	scannerOpts = append(scannerOpts, scanner.WithErrorHandler(func(target, check string, err error) {
		// Budget exhaustion is a planned ceiling, not a malfunction. Surface
		// it in the report (via meta.Budget) rather than as a noisy per-check
		// failure, and don't bump the exit code: the scan ended cleanly at
		// the cap the operator set.
		if errors.Is(err, httpclient.ErrBudgetExhausted) {
			return
		}
		checkErrors.Add(1)
		log.Warn("check error", "check", check, "target", target, "err", err)
	}))
	s := scanner.New(client, enabled, scannerOpts...)

	pages := make(chan page.Page, cfg.concurrency)
	findings := make(chan checks.Finding, 64)

	feedErr := make(chan error, 1)
	if cfg.crawl {
		cr := crawler.New(client, crawler.Config{
			Workers:      cfg.crawlWorkers,
			MaxPages:     cfg.crawlPages,
			Scope:        sc,
			APIDiscovery: cfg.apiDiscovery,
			Pollute:      cfg.pollute,
		}, crawler.WithErrorHandler(func(target string, err error) {
			log.Warn("crawl error", "target", target, "err", err)
		}))
		go func() { feedErr <- cr.Crawl(ctx, seeds, pages) }()
	} else {
		go func() {
			defer close(pages)
			feedErr <- feedSeeds(ctx, pages, seeds, sc, func(seed, reason string) {
				log.Warn("seed skipped", "url", seed, "reason", reason)
			})
		}()
	}

	scanErr := make(chan error, 1)
	go func() { scanErr <- s.ScanAll(ctx, pages, findings) }()

	// Dedupe before reporting so site-wide issues (e.g. missing security
	// headers) don't fire once per crawled page. Checks opt in by setting
	// Finding.DedupeKey; findings without a key pass through unchanged.
	deduped := report.Dedupe(findings)

	// Diff overlay runs after Dedupe so resolved/persisting decisions are
	// taken on the same fingerprint a future scan would emit. counts is
	// shared with the reporter via Metadata.Diff and safe to read once the
	// reporter returns (the overlay only writes while the reporter is
	// draining).
	var diffCounts *report.DiffCounts
	reportCh := deduped
	if baseline != nil {
		diffCounts = &report.DiffCounts{}
		reportCh = report.Diff(deduped, baseline, diffCounts)
	}

	// Track the worst severity that *would* trigger the --fail-on gate so
	// the exit code can be set once the reporter drains. With --baseline,
	// only `new` findings count (the whole point of a baseline is to ignore
	// known issues). Without a baseline, every emitted finding counts.
	worstSev := -1
	gated := report.Tap(reportCh, func(f checks.Finding) {
		if !gateEnabled {
			return
		}
		if baseline != nil && f.DiffStatus != report.DiffStatusNew {
			return
		}
		if r := checks.SeverityRank(f.Severity); r > worstSev {
			worstSev = r
		}
	})

	exit := exitOK
	if err := rep.Write(ctx, out, gated, report.Metadata{
		Stacks: stacks,
		Budget: budget,
		Diff:   diffCounts,
	}); err != nil {
		log.Error("report write failed", "err", err)
		exit = exitScanError
	}
	if err := <-scanErr; err != nil && ctx.Err() == nil {
		log.Error("scan failed", "err", err)
		exit = exitScanError
	}
	if err := <-feedErr; err != nil {
		log.Error("input feed failed", "err", err)
		exit = exitScanError
	}
	if n := checkErrors.Load(); n > 0 {
		log.Warn("check errors occurred", "count", n)
		if exit == exitOK {
			exit = exitScanError
		}
	}
	if ctx.Err() != nil && exit == exitOK {
		exit = exitCanceled
	}
	// Threshold gate runs only when the scan otherwise completed cleanly.
	// A tool error (exitScanError) or cancel (exitCanceled) already
	// dominates - we don't want to mask a broken scan as "just findings".
	if exit == exitOK && gateEnabled && worstSev >= failOnRank {
		log.Info("findings at or above --fail-on threshold",
			"fail_on", cfg.failOn, "exit_code", exitFindings)
		exit = exitFindings
	}
	if diffCounts != nil {
		log.Info("diff vs baseline summary",
			"new", diffCounts.New,
			"persisting", diffCounts.Persisting,
			"resolved", diffCounts.Resolved)
	}
	if pool != nil {
		logProxyStats(log, pool, cfg.proxyStatsTopN)
	}
	if budget != nil {
		s := budget.Snapshot()
		if s.Exhausted {
			log.Warn("scan request budget exhausted",
				"requests", s.Requests, "max", s.Max, "exhausted_at", s.ExhaustedAt.UTC())
		} else if s.Max > 0 || s.GlobalRPS > 0 {
			log.Info("scan request budget summary",
				"requests", s.Requests, "max", s.Max, "global_rps", s.GlobalRPS)
		}
	}
	return exit
}

// parseFailOn turns the --fail-on flag value into a severity rank (per
// checks.SeverityRank). "none" disables the gate; any other value must be a
// canonical severity name. Returns enabled=false when the gate is off so
// callers can short-circuit the worst-severity tracking.
func parseFailOn(s string) (rank int, enabled bool, err error) {
	if strings.EqualFold(s, "none") {
		return 0, false, nil
	}
	sev, err := checks.ParseSeverity(s)
	if err != nil {
		return 0, false, err
	}
	return checks.SeverityRank(sev), true, nil
}

// fingerprintFallbackProbes returns the host-relative paths the detector
// should walk when the seed response leaves CMS and Framework empty (the
// SPA case where the document <head> carries no signal). robots.txt and
// sitemap.xml are conventional client-discoverable resources, so they run
// at every level; the CMS login URLs look like recon to defenders and are
// gated to LevelDefault+.
func fingerprintFallbackProbes(level checks.Level) []string {
	probes := []string{"/robots.txt", "/sitemap.xml"}
	if level >= checks.LevelDefault {
		probes = append(probes,
			"/wp-login.php",
			"/administrator/",
			"/user/login",
		)
	}
	return probes
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
