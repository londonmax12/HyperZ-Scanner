package checks

import (
	"context"
	"fmt"

	"github.com/londonball/hyperz/internal/httpclient"
)

type SecurityHeaders struct{}

func (SecurityHeaders) Name() string { return "security-headers" }

func (SecurityHeaders) Mode() Mode { return ModePassive }

func (c SecurityHeaders) Run(ctx context.Context, client *httpclient.Client, target string) ([]Finding, error) {
	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	expected := map[string]Severity{
		"Content-Security-Policy":   SeverityMedium,
		"Strict-Transport-Security": SeverityMedium,
		"X-Content-Type-Options":    SeverityLow,
		"X-Frame-Options":           SeverityLow,
		"Referrer-Policy":           SeverityLow,
	}

	var findings []Finding
	for header, sev := range expected {
		if resp.Header.Get(header) == "" {
			findings = append(findings, Finding{
				Check:    c.Name(),
				Target:   target,
				Severity: sev,
				Title:    "missing security header: " + header,
				Detail:   fmt.Sprintf("response from %s did not include %s", target, header),
			})
		}
	}
	return findings, nil
}
