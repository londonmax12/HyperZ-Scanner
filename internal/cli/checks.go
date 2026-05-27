package cli

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
//
// settings is the operator-supplied per-check config bag map from
// the YAML config file. Each matched check has its bag attached
// before the catalog is returned; bags keyed by unknown check names
// surface via the returned unknownSettings slice so the caller can
// warn instead of failing the scan.
func registry(pollute bool, settings map[string]map[string]any) (checks []core.Check, unknownSettings []string) {
	return lua_engine.All(pollute, settings)
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
			// at scan time via --pollute. The list view does not surface
			// per-check settings, so the settings map is nil here.
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tLEVEL")
			catalog, _ := registry(true, nil)
			for _, c := range catalog {
				fmt.Fprintf(tw, "%s\t%s\n", c.Name(), c.Level())
			}
			return tw.Flush()
		},
	}
}
