package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/londonball/hyperz/internal/checks"
)

// registry lists every check that ships with hyperz. Add new checks here so
// they appear in `hyperz checks list` and run during `hyperz scan`.
func registry() []checks.Check {
	return []checks.Check{
		checks.SecurityHeaders{},
	}
}

func newChecksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checks",
		Short: "Inspect the built-in check catalog",
	}
	cmd.AddCommand(newChecksListCmd())
	return cmd
}

func newChecksListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all checks and the level each one runs at",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tLEVEL")
			for _, c := range registry() {
				fmt.Fprintf(tw, "%s\t%s\n", c.Name(), c.Level())
			}
			return tw.Flush()
		},
	}
}
