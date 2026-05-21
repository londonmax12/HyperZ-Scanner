package main

import (
	"errors"
	"flag"
	"strings"
	"time"

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/report"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type config struct {
	urls        []string
	urlsFile    string
	timeout     time.Duration
	userAgent   string
	format      string
	mode        checks.Mode
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

func parseFlags() (*config, error) {
	var urls stringList
	var proxies stringList
	var proxySources stringList
	flag.Var(&urls, "url", "target URL to scan (repeatable)")
	flag.Var(&proxies, "proxy", "proxy URL to route requests through, e.g. http://host:port or socks5://host:port (repeatable)")
	flag.Var(&proxySources, "proxy-source", "URL of an additional proxy list to scrape (repeatable; implies -scrape-proxies)")
	proxiesFile := flag.String("proxies-file", "", "file with one proxy per line")
	scrapeProxies := flag.Bool("scrape-proxies", false, "fetch proxies from built-in public sources at startup")
	proxyStatsTopN := flag.Int("proxy-stats-top", 10, "rows of per-proxy stats to print at scan end (0 to hide)")
	urlsFile := flag.String("urls-file", "", "file with one URL per line (use '-' for stdin)")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	userAgent := flag.String("user-agent", "hyperz/0.1", "User-Agent header to send")
	format := flag.String("format", "text",
		"output format: "+strings.Join(report.Formats(), "|"))
	mode := flag.String("mode", string(checks.ModePassive),
		"scan mode: passive (safe, observation-only) | active (also runs intrusive probes)")
	concurrency := flag.Int("concurrency", 8, "number of targets scanned in parallel")
	rps := flag.Float64("rate", 5, "max requests per second per host")
	burst := flag.Int("burst", 5, "per-host rate limiter burst")
	output := flag.String("o", "-", "output path ('-' for stdout)")
	crawl := flag.Bool("crawl", false, "discover scan targets by crawling from each seed URL")
	crawlDepth := flag.Int("max-depth", 2, "max crawl depth (0 = only seeds, no link extraction)")
	crawlPages := flag.Int("max-pages", 100, "max unique pages to enqueue while crawling (0 = unlimited)")
	crawlWorkers := flag.Int("crawl-workers", 8, "number of parallel crawl fetchers")
	crawlSameHost := flag.Bool("crawl-same-host", true, "only follow links on seed hosts")
	flag.Parse()

	if len(urls) == 0 && *urlsFile == "" {
		return nil, errors.New("provide -url and/or -urls-file")
	}
	parsedMode, err := checks.ParseMode(*mode)
	if err != nil {
		return nil, err
	}
	return &config{
		urls:          urls,
		urlsFile:      *urlsFile,
		timeout:       *timeout,
		userAgent:     *userAgent,
		format:        *format,
		mode:          parsedMode,
		concurrency:   *concurrency,
		rps:           *rps,
		burst:         *burst,
		outputPath:    *output,
		crawl:         *crawl,
		crawlDepth:    *crawlDepth,
		crawlPages:    *crawlPages,
		crawlWorkers:  *crawlWorkers,
		crawlSameHost: *crawlSameHost,
		proxies:        proxies,
		proxiesFile:    *proxiesFile,
		scrapeProxies:  *scrapeProxies,
		proxySources:   proxySources,
		proxyStatsTopN: *proxyStatsTopN,
	}, nil
}
