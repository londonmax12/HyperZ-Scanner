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
}

func parseFlags() (*config, error) {
	var urls stringList
	flag.Var(&urls, "url", "target URL to scan (repeatable)")
	urlsFile := flag.String("urls-file", "", "file with one URL per line (use '-' for stdin)")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	userAgent := flag.String("user-agent", "hyperz/0.1", "User-Agent header to send")
	format := flag.String("format", "text",
		"output format: "+strings.Join(report.Formats(), "|"))
	concurrency := flag.Int("concurrency", 8, "number of targets scanned in parallel")
	rps := flag.Float64("rate", 5, "max requests per second per host")
	burst := flag.Int("burst", 5, "per-host rate limiter burst")
	output := flag.String("o", "-", "output path ('-' for stdout)")
	flag.Parse()

	if len(urls) == 0 && *urlsFile == "" {
		return nil, errors.New("provide -url and/or -urls-file")
	}
	return &config{
		urls:        urls,
		urlsFile:    *urlsFile,
		timeout:     *timeout,
		userAgent:   *userAgent,
		format:      *format,
		concurrency: *concurrency,
		rps:         *rps,
		burst:       *burst,
		outputPath:  *output,
	}, nil
}
