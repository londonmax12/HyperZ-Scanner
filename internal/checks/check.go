package checks

import (
	"context"
	"fmt"

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

// Mode classifies a check by how invasive it is.
//
// Passive checks only inspect responses to normal-looking requests; they
// don't send payloads designed to trigger vulnerabilities. They're safe to
// run against any target you're allowed to look at.
//
// Active checks send crafted probes (XSS, SQLi, traversal, etc.) and may
// be logged as attacks. Run them only against systems you have explicit
// authorization to test.
type Mode string

const (
	ModePassive Mode = "passive"
	ModeActive  Mode = "active"
)

func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModePassive:
		return ModePassive, nil
	case ModeActive:
		return ModeActive, nil
	default:
		return "", fmt.Errorf("invalid mode %q (want %q or %q)", s, ModePassive, ModeActive)
	}
}

type Finding struct {
	Check    string   `json:"check"`
	Target   string   `json:"target"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
}

type Check interface {
	Name() string
	Mode() Mode
	Run(ctx context.Context, client *httpclient.Client, target string) ([]Finding, error)
}

// Filter returns the subset of checks that should run for the given mode.
// Passive mode keeps only passive checks. Active mode keeps everything;
// running active probes without first making the passive observations
// would discard cheap, useful findings, so an active scan is a superset.
func Filter(all []Check, mode Mode) []Check {
	if mode == ModeActive {
		return all
	}
	out := make([]Check, 0, len(all))
	for _, c := range all {
		if c.Mode() == ModePassive {
			out = append(out, c)
		}
	}
	return out
}
