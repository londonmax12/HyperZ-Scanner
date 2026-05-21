package scanner

import (
	"context"
	"fmt"

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/httpclient"
)

type Scanner struct {
	client *httpclient.Client
	checks []checks.Check
}

func New(client *httpclient.Client, c []checks.Check) *Scanner {
	return &Scanner{client: client, checks: c}
}

func (s *Scanner) Scan(ctx context.Context, target string) ([]checks.Finding, error) {
	var all []checks.Finding
	for _, c := range s.checks {
		if ctx.Err() != nil {
			return all, ctx.Err()
		}
		found, err := c.Run(ctx, s.client, target)
		if err != nil {
			return all, fmt.Errorf("check %s: %w", c.Name(), err)
		}
		all = append(all, found...)
	}
	return all, nil
}
