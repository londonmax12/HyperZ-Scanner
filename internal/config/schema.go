// Package config defines the on-disk schema for hyperz's optional
// YAML configuration file and the rules for merging a named profile
// overlay onto the base configuration.
//
// The file is opt-in: operators may continue passing every value via
// CLI flags. When --config is supplied, the precedence chain is:
//
//	built-in defaults  <  file: base values  <  file: --profile overlay  <  CLI flags
//
// Each layer overrides the prior only for fields it explicitly sets.
// "Explicit" is tracked via pointer / nil-slice sentinels so a profile
// that does not mention `rate` leaves the base rate intact rather than
// slamming it to 0.
package config

import (
	"fmt"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// File is the top-level on-disk shape parsed from a YAML config.
//
// Base values live at the file root via the inline embed so a config
// without profiles reads naturally as a flat document. Profiles is a
// name-keyed map of overlays: `--profile <name>` selects one to merge
// over Base before flags are applied.
type File struct {
	Config   `yaml:",inline"`
	Profiles map[string]Config `yaml:"profiles,omitempty"`
}

// Config carries every knob the scanner exposes today, mirroring the
// CLI flag surface field-for-field. Every scalar is a pointer so an
// absent key in YAML stays distinguishable from a key that explicitly
// set the zero value; merge logic relies on that distinction to know
// whether a profile is overriding the base.
//
// Slices and maps use nil to mean "unset". A profile that wants to
// clear a slice from the base must specify an empty slice in YAML
// (`headers: []`) rather than omitting the key.
type Config struct {
	Timeout          *Duration `yaml:"timeout,omitempty"`
	UserAgent        *string   `yaml:"user_agent,omitempty"`
	Format           *string   `yaml:"format,omitempty"`
	Mode             *string   `yaml:"mode,omitempty"`
	Concurrency      *int      `yaml:"concurrency,omitempty"`
	CheckConcurrency *int      `yaml:"check_concurrency,omitempty"`
	Rate             *float64  `yaml:"rate,omitempty"`
	Burst            *int      `yaml:"burst,omitempty"`
	MaxRequests      *int64    `yaml:"max_requests,omitempty"`
	GlobalRate       *float64  `yaml:"global_rate,omitempty"`
	GlobalBurst      *int      `yaml:"global_burst,omitempty"`
	MaxRetries       *int      `yaml:"max_retries,omitempty"`
	MaxRetryWait     *Duration `yaml:"max_retry_wait,omitempty"`
	Output           *string   `yaml:"output,omitempty"`

	LogLevel  *string `yaml:"log_level,omitempty"`
	LogFormat *string `yaml:"log_format,omitempty"`

	Crawl    *CrawlConfig    `yaml:"crawl,omitempty"`
	Scope    *ScopeConfig    `yaml:"scope,omitempty"`
	Auth     *AuthConfig     `yaml:"auth,omitempty"`
	OOB      *OOBConfig      `yaml:"oob,omitempty"`
	JS       *JSConfig       `yaml:"js,omitempty"`
	Proxies  *ProxiesConfig  `yaml:"proxies,omitempty"`
	Session  *SessionConfig  `yaml:"session,omitempty"`
	CSRF     *CSRFConfig     `yaml:"csrf,omitempty"`
	Baseline *BaselineConfig `yaml:"baseline,omitempty"`

	FailOn        *string `yaml:"fail_on,omitempty"`
	CAFile        *string `yaml:"ca_file,omitempty"`
	NoFingerprint *bool   `yaml:"no_fingerprint,omitempty"`

	URL      []string `yaml:"url,omitempty"`
	URLsFile *string  `yaml:"urls_file,omitempty"`

	Checks *ChecksConfig `yaml:"checks,omitempty"`
}

// CrawlConfig groups crawl-related toggles. Pulled out of the top
// level so a profile can say `crawl: { workers: 4 }` without having
// to repeat every other crawl flag.
type CrawlConfig struct {
	Enabled      *bool `yaml:"enabled,omitempty"`
	MaxPages     *int  `yaml:"max_pages,omitempty"`
	Workers      *int  `yaml:"workers,omitempty"`
	APIDiscovery *bool `yaml:"api_discovery,omitempty"`
}

// ScopeConfig mirrors the --scope-* flag family.
type ScopeConfig struct {
	Hosts       []string `yaml:"hosts,omitempty"`
	AnyHost     *bool    `yaml:"any_host,omitempty"`
	Ports       *string  `yaml:"ports,omitempty"`
	PathInclude []string `yaml:"path_include,omitempty"`
	PathExclude []string `yaml:"path_exclude,omitempty"`
	MaxDepth    *int     `yaml:"max_depth,omitempty"`
}

// AuthConfig groups auth headers, cookies, and bearer tokens. Headers
// and Cookies follow the same one-string-per-entry shape the CLI
// flags use ("Name: Value" and "name=value" respectively); the loader
// does not parse them here so the existing httpclient helpers can
// stay the single source of truth.
type AuthConfig struct {
	Basic       *string  `yaml:"basic,omitempty"`
	Bearer      *string  `yaml:"bearer,omitempty"`
	Headers     []string `yaml:"headers,omitempty"`
	Cookies     []string `yaml:"cookies,omitempty"`
	CookiesFile *string  `yaml:"cookies_file,omitempty"`
}

// OOBConfig groups the out-of-band listener knobs.
type OOBConfig struct {
	Enabled *bool     `yaml:"enabled,omitempty"`
	Listen  *string   `yaml:"listen,omitempty"`
	Host    *string   `yaml:"host,omitempty"`
	Wait    *Duration `yaml:"wait,omitempty"`
}

// JSConfig groups headless-browser knobs.
type JSConfig struct {
	Enabled    *bool `yaml:"enabled,omitempty"`
	Concurrent *int  `yaml:"concurrent,omitempty"`
}

// ProxiesConfig groups proxy sourcing and stats knobs.
type ProxiesConfig struct {
	URLs     []string `yaml:"urls,omitempty"`
	File     *string  `yaml:"file,omitempty"`
	Scrape   *bool    `yaml:"scrape,omitempty"`
	Sources  []string `yaml:"sources,omitempty"`
	StatsTop *int     `yaml:"stats_top,omitempty"`
}

// SessionConfig groups session-liveness probe knobs.
type SessionConfig struct {
	CheckURL *string `yaml:"check_url,omitempty"`
	Pattern  *string `yaml:"pattern,omitempty"`
	Every    *int    `yaml:"every,omitempty"`
}

// CSRFConfig groups CSRF auto-injection knobs.
type CSRFConfig struct {
	TokenSource *string `yaml:"token_source,omitempty"`
	Inject      *string `yaml:"inject,omitempty"`
	Header      *string `yaml:"header,omitempty"`
	Param       *string `yaml:"param,omitempty"`
}

// BaselineConfig groups baseline-diff knobs.
type BaselineConfig struct {
	Path   *string `yaml:"path,omitempty"`
	Format *string `yaml:"format,omitempty"`
}

// ChecksConfig is the catalog-control block: which checks to run and
// per-check settings to surface to the Lua runtime.
//
// Enable/Disable use glob patterns matched against check names via
// path.Match. Empty Enable means "every check the level allows";
// Disable always subtracts from the post-Enable set.
//
// Settings carries arbitrary per-check key/value bags. Each check's
// bag is exposed inside its Lua module as `ctx.config` - the bridge
// does not interpret the values, so the schema a check accepts is
// owned by the check's .lua file. Settings keyed by a check name that
// is not in the catalog at load time is reported as a warning, not
// an error, so a profile written for a newer build still loads on an
// older one (the unknown bag is simply ignored).
type ChecksConfig struct {
	Enable   []string                          `yaml:"enable,omitempty"`
	Disable  []string                          `yaml:"disable,omitempty"`
	Pollute  *bool                             `yaml:"pollute,omitempty"`
	Settings map[string]map[string]interface{} `yaml:"settings,omitempty"`
}

// Duration is a time.Duration that round-trips through YAML as a
// Go-style duration string (e.g. "10s", "5m"). The default yaml.v3
// decoder treats Duration as an int64 nanosecond count, which is
// hostile to humans editing configs by hand; this wrapper accepts
// either a string (parsed via time.ParseDuration) or a number (read
// as seconds for ergonomics: `timeout: 10` means 10s).
type Duration time.Duration

// UnmarshalYAML accepts both `10s` (string) and `10` (number = seconds).
// The two forms cover the common cases without forcing the operator
// to remember a specific representation. yaml.Node carries the raw
// scalar so we can disambiguate "10" (parse as seconds) from "10s"
// (parse via time.ParseDuration).
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar (string or number)")
	}
	if node.Tag == "!!int" || node.Tag == "!!float" {
		f, err := strconv.ParseFloat(node.Value, 64)
		if err != nil {
			return fmt.Errorf("invalid duration number %q: %w", node.Value, err)
		}
		*d = Duration(time.Duration(f * float64(time.Second)))
		return nil
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	*d = Duration(parsed)
	return nil
}

// Std returns the underlying time.Duration. Callers should guard on
// d != nil first - a nil *Duration means the field was not set in
// YAML and the caller's default should win.
func (d *Duration) Std() time.Duration {
	if d == nil {
		return 0
	}
	return time.Duration(*d)
}
