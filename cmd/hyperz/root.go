package main

import (
	"github.com/spf13/cobra"
)

const (
	exitOK       = 0
	exitFailure  = 1
	exitCanceled = 130
)

// version is overridable at build time via -ldflags "-X main.version=...".
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
