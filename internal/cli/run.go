package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
)

// exitErr lets RunE handlers signal a specific process exit code
// without calling os.Exit. Run recognises this error and returns the
// embedded code; any other error maps to exitScanError. Without this
// trampoline, RunE handlers that called os.Exit directly would kill
// in-process callers like the integration test harness, which
// invokes Run instead of fork/exec'ing the hyperz binary.
type exitErr struct {
	code  int
	cause error
}

func (e *exitErr) Error() string {
	if e.cause == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.cause.Error()
}

func (e *exitErr) Unwrap() error { return e.cause }

// Run executes the hyperz CLI with the given argv-style args and
// returns the process exit code. cmd/hyperz/main.go calls this with
// os.Args[1:]; the integration test harness calls it directly so
// the scan runs in-process and no fork/exec of hyperz.exe happens.
// Avoiding fork/exec matters on Windows where Smart App Control
// flags the unsigned scanner binary as having "Malicious binary
// reputation" and refuses to start it - the same code path runs
// fine when it lives inside an already-running test process.
//
// Run owns the signal handler so a SIGINT mid-scan still produces
// an orderly cancel + exitCanceled regardless of caller.
func Run(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cmd := newRootCmd()
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	var ee *exitErr
	if errors.As(err, &ee) {
		return ee.code
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return exitScanError
}
