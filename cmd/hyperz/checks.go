package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/londonmax12/hyperz/internal/checks"
)

// registry lists every check that ships with hyperz. Add new checks here so
// they appear in `hyperz checks list` and run during `hyperz scan`.
//
// pollute gates state-mutating and disruptive checks. ProtoPollution leaves
// a (best-effort cleaned-up) modification on a Node target's Object.prototype,
// StoredXSS plants XSS payloads that PERSIST until the operator removes them
// (the whole point of the check is the canary surviving the storage boundary,
// so there is no cleanup pass), RequestSmuggling sends deliberately malformed
// CL/TE/H2 requests over a raw socket - timing-only so no smuggled suffix
// lands on the next user's connection, but the traffic is loud and some
// front-ends will log or block the source IP - and JWTVulns brute-forces
// HMAC secrets offline and sends forged alg=none / kid-injection tokens
// against the application. All load only when the operator has explicitly
// accepted that with --pollute. Other checks here are read-only or only
// mutate the request itself.
func registry(pollute bool) []checks.Check {
	out := []checks.Check{
		checks.SecurityHeaders{},
		checks.CookieAttributes{},
		checks.CacheControlSensitive{},
		checks.CSPWeak{},
		checks.CSPBypass{},
		checks.HSTSWeak{},
		checks.CrossOriginIsolation{},
		checks.FormAutocomplete{},
		checks.FormActionInsecure{},
		checks.CORSConfig{},
		checks.CORSReflection{},
		checks.ServerLeak{},
		checks.SecretsInBody{},
		&checks.OAuthDiscovery{},
		checks.TLSAudit{},
		checks.MixedContent{},
		checks.OpenRedirect{},
		checks.HostHeaderInjection{},
		checks.CachePoisoning{},
		checks.CRLFInjection{},
		checks.SSRF{},
		checks.ReflectedXSS{},
		checks.DOMXSS{},
		checks.SQLiError{},
		checks.SQLiBoolean{},
		checks.SQLiTime{},
		checks.NoSQLi{},
		checks.LDAPi{},
		checks.PathTraversal{},
		checks.CmdInjection{},
		checks.CmdInjectionBlind{},
		checks.InsecureDeserialization{},
		checks.XXE{},
		checks.GraphQLAudit{},
		&checks.OpenAPIAudit{},
		checks.WSAudit{},
		checks.JSLibsKnownVuln{},
		checks.SRIMissing{},
		checks.SourceMapExposure{},
		checks.TargetBlankNoopener{},
		&checks.ContentDiscovery{},
		&checks.IDOR{},
		&checks.SubdomainTakeover{},
	}
	if pollute {
		out = append(out, checks.ProtoPollution{})
		out = append(out, &checks.StoredXSS{})
		out = append(out, &checks.RequestSmuggling{})
		out = append(out, &checks.JWTVulns{})
		out = append(out, &checks.RaceCondition{})
	}
	return out
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
