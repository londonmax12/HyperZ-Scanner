package main

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/httpclient"
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

	client := httpclient.New(httpclient.Config{
		Timeout:   cfg.timeout,
		UserAgent: cfg.userAgent,
		Limiter:   httpclient.NewHostLimiter(cfg.rps, cfg.burst),
	})

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
	go func() {
		defer close(targets)
		feedErr <- feed(ctx, targets, cfg.urls, cfg.urlsFile)
	}()

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
