package main

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the hyperz version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "hyperz %s\n", version)
			fmt.Fprintf(out, "  go:      %s\n", runtime.Version())
			fmt.Fprintf(out, "  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
			if info, ok := debug.ReadBuildInfo(); ok {
				var rev, modified string
				for _, s := range info.Settings {
					switch s.Key {
					case "vcs.revision":
						rev = s.Value
					case "vcs.modified":
						modified = s.Value
					}
				}
				if rev != "" {
					suffix := ""
					if modified == "true" {
						suffix = " (dirty)"
					}
					fmt.Fprintf(out, "  commit:  %s%s\n", rev, suffix)
				}
			}
			return nil
		},
	}
}
