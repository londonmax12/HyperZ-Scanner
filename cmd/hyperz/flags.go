package main

import (
	"errors"
	"flag"
	"strings"
	"time"

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
	concurrency int
	rps         float64
	burst       int
	outputPath  string

	crawl         bool
	crawlDepth    int
	crawlPages    int
	crawlWorkers  int
	crawlSameHost bool

	proxies     []string
	proxiesFile string
}

func parseFlags() (*config, error) {
	var urls stringList
	var proxies stringList
	flag.Var(&urls, "url", "target URL to scan (repeatable)")
	flag.Var(&proxies, "proxy", "proxy URL to route requests through, e.g. http://host:port or socks5://host:port (repeatable)")
	proxiesFile := flag.String("proxies-file", "", "file with one proxy per line (round-robin across requests)")
	urlsFile := flag.String("urls-file", "", "file with one URL per line (use '-' for stdin)")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	userAgent := flag.String("user-agent", "hyperz/0.1", "User-Agent header to send")
	format := flag.String("format", "text",
		"output format: "+strings.Join(report.Formats(), "|"))
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
	return &config{
		urls:          urls,
		urlsFile:      *urlsFile,
		timeout:       *timeout,
		userAgent:     *userAgent,
		format:        *format,
		concurrency:   *concurrency,
		rps:           *rps,
		burst:         *burst,
		outputPath:    *output,
		crawl:         *crawl,
		crawlDepth:    *crawlDepth,
		crawlPages:    *crawlPages,
		crawlWorkers:  *crawlWorkers,
		crawlSameHost: *crawlSameHost,
		proxies:       proxies,
		proxiesFile:   *proxiesFile,
	}, nil
}
