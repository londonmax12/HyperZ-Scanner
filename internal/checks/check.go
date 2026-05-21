package checks

import (
	"context"

	"github.com/londonball/hyperz/internal/httpclient"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Finding struct {
	Check    string   `json:"check"`
	Target   string   `json:"target"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
}

type Check interface {
	Name() string
	Run(ctx context.Context, client *httpclient.Client, target string) ([]Finding, error)
}
