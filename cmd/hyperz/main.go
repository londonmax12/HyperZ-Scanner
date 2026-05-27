// Package main is the hyperz CLI entry point. The actual command tree
// and scan orchestration live under internal/cli so the integration
// test harness can invoke Run in-process without fork/exec'ing the
// hyperz binary; see internal/cli/run.go for the rationale.
package main

import (
	"os"

	"github.com/londonmax12/hyperz/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
