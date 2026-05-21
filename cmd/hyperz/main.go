package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/report"
	"github.com/londonball/hyperz/internal/scanner"
)

func main() {
	var (
		target    = flag.String("url", "", "target URL to scan (required)")
		timeout   = flag.Duration("timeout", 10*time.Second, "per-request timeout")
		userAgent = flag.String("user-agent", "hyperz/0.1", "User-Agent header to send")
		format    = flag.String("format", "text", "output format: text|json")
	)
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: -url is required")
		flag.Usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client := httpclient.New(*timeout, *userAgent)
	s := scanner.New(client, []checks.Check{
		checks.SecurityHeaders{},
	})

	findings, err := s.Scan(ctx, *target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}

	if err := report.Write(os.Stdout, *format, findings); err != nil {
		fmt.Fprintf(os.Stderr, "report failed: %v\n", err)
		os.Exit(1)
	}
}
