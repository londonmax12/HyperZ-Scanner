package cli

import (
	"github.com/spf13/cobra"
)

// Exit codes are intentionally split between "we found something" (1) and
// "the tool itself failed" (2) so CI gates can tell signal from breakage.
//   - exitOK:        scan completed and no findings cleared the --fail-on
//                    threshold (or --fail-on=none was set).
//   - exitFindings:  scan completed cleanly but at least one finding (the
//                    "new" set when running with --baseline, otherwise the
//                    whole result list) is >= --fail-on severity.
//   - exitScanError: scan or tool error (bad input, proxy load failure,
//                    report write error, check error). Not findings.
//   - exitCanceled:  SIGINT/SIGTERM.
const (
	exitOK         = 0
	exitFindings   = 1
	exitScanError = 2
	exitCanceled   = 130
)

// version is overridable at build time via:
//
//	-ldflags "-X github.com/londonmax12/hyperz/internal/cli.version=..."
var version = "dev"

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hyperz",
		Short: "A web vulnerability scanner",
		Long: `hyperz is a web vulnerability scanner written in Go.

Only scan systems you have explicit authorization to test.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	cmd.SetVersionTemplate("hyperz {{.Version}}\n")

	cmd.AddCommand(
		newScanCmd(),
		newVersionCmd(),
		newFormatsCmd(),
		newChecksCmd(),
	)
	return cmd
}
