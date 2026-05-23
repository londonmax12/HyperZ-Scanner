package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/londonmax12/hyperz/internal/report"
)

func newFormatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "formats",
		Short: "List supported output formats",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			for _, f := range report.Formats() {
				fmt.Fprintln(out, f)
			}
			return nil
		},
	}
}
