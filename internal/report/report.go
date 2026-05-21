package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/londonball/hyperz/internal/checks"
)

func Write(w io.Writer, format string, findings []checks.Finding) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	case "text", "":
		if len(findings) == 0 {
			_, err := fmt.Fprintln(w, "no findings")
			return err
		}
		for _, f := range findings {
			if _, err := fmt.Fprintf(w, "[%s] %s — %s\n", f.Severity, f.Check, f.Title); err != nil {
				return err
			}
			if f.Detail != "" {
				if _, err := fmt.Fprintf(w, "    %s\n", f.Detail); err != nil {
					return err
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q", format)
	}
}
