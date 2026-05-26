package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// registry returns every check shipped with hyperz. Detection logic
// lives in pure Lua under internal/checks/*.lua; this binary embeds
// the catalog and instantiates each rule through internal/lua_engine.
//
// pollute gates the disruptive subset (state-mutating or noisy
// probes that declared `pollute = true` in their module table). When
// the operator passes --pollute at scan time we load those too;
// otherwise the default scan stays read-only.
func registry(pollute bool) []core.Check {
	return lua_engine.All(pollute)
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
			// pollute=true so the catalog shows the full set, including
			// state-mutating checks; the operator chooses what to enable
			// at scan time via --pollute.
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tLEVEL")
			for _, c := range registry(true) {
				fmt.Fprintf(tw, "%s\t%s\n", c.Name(), c.Level())
			}
			return tw.Flush()
		},
	}
}
