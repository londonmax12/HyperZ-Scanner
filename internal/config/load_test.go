package config

import (
	"strings"
	"testing"
	"time"
)

func TestParseBaseFields(t *testing.T) {
	raw := []byte(`
timeout: 30s
mode: aggressive
concurrency: 16
rate: 2.5
checks:
  disable:
    - request-smuggling
  settings:
    reflected-xss:
      body_cap_bytes: 65536
`)
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, err := f.Resolve("")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cfg.Timeout == nil || cfg.Timeout.Std() != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", cfg.Timeout)
	}
	if cfg.Mode == nil || *cfg.Mode != "aggressive" {
		t.Errorf("mode = %v, want aggressive", cfg.Mode)
	}
	if cfg.Concurrency == nil || *cfg.Concurrency != 16 {
		t.Errorf("concurrency = %v, want 16", cfg.Concurrency)
	}
	if cfg.Rate == nil || *cfg.Rate != 2.5 {
		t.Errorf("rate = %v, want 2.5", cfg.Rate)
	}
	if cfg.Checks == nil {
		t.Fatal("checks block missing")
	}
	if got := cfg.Checks.Disable; len(got) != 1 || got[0] != "request-smuggling" {
		t.Errorf("checks.disable = %v", got)
	}
	bag, ok := cfg.Checks.Settings["reflected-xss"]
	if !ok {
		t.Fatal("reflected-xss settings missing")
	}
	if v, ok := bag["body_cap_bytes"].(int); !ok || v != 65536 {
		t.Errorf("body_cap_bytes = %v (%T), want int 65536", bag["body_cap_bytes"], bag["body_cap_bytes"])
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	raw := []byte(`
timeout: 10s
nonsense_key: true
`)
	if _, err := Parse(raw); err == nil {
		t.Fatal("expected unknown-field error, got nil")
	} else if !strings.Contains(err.Error(), "nonsense_key") {
		t.Errorf("error did not mention unknown field: %v", err)
	}
}

func TestParseDurationNumeric(t *testing.T) {
	raw := []byte(`timeout: 15`)
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, _ := f.Resolve("")
	if cfg.Timeout == nil || cfg.Timeout.Std() != 15*time.Second {
		t.Errorf("timeout numeric = %v, want 15s", cfg.Timeout)
	}
}

func TestResolveProfileOverlaysBase(t *testing.T) {
	raw := []byte(`
timeout: 10s
mode: passive
rate: 5
checks:
  settings:
    reflected-xss:
      body_cap_bytes: 65536
      timeout_ms: 5000

profiles:
  staging:
    mode: default
    rate: 1
    checks:
      disable:
        - request-smuggling
      settings:
        reflected-xss:
          timeout_ms: 1000
`)
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, err := f.Resolve("staging")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Base wins for fields the profile did not override.
	if cfg.Timeout == nil || cfg.Timeout.Std() != 10*time.Second {
		t.Errorf("timeout = %v, want 10s (from base)", cfg.Timeout)
	}
	// Profile wins for fields it touched.
	if cfg.Mode == nil || *cfg.Mode != "default" {
		t.Errorf("mode = %v, want default (from profile)", cfg.Mode)
	}
	if cfg.Rate == nil || *cfg.Rate != 1 {
		t.Errorf("rate = %v, want 1 (from profile)", cfg.Rate)
	}
	if got := cfg.Checks.Disable; len(got) != 1 || got[0] != "request-smuggling" {
		t.Errorf("checks.disable = %v", got)
	}
	// Settings merges per-key: profile's timeout_ms wins, base's
	// body_cap_bytes survives.
	bag := cfg.Checks.Settings["reflected-xss"]
	if v, _ := bag["body_cap_bytes"].(int); v != 65536 {
		t.Errorf("body_cap_bytes = %v, want 65536 preserved from base", bag["body_cap_bytes"])
	}
	if v, _ := bag["timeout_ms"].(int); v != 1000 {
		t.Errorf("timeout_ms = %v, want 1000 from profile", bag["timeout_ms"])
	}
}

func TestResolveUnknownProfile(t *testing.T) {
	raw := []byte(`
mode: passive
profiles:
  staging:
    mode: aggressive
`)
	f, _ := Parse(raw)
	_, err := f.Resolve("prod")
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	if !strings.Contains(err.Error(), "prod") || !strings.Contains(err.Error(), "staging") {
		t.Errorf("error should name the missing profile and available list, got: %v", err)
	}
}

func TestResolveEmptyProfileReturnsBase(t *testing.T) {
	raw := []byte(`
mode: passive
profiles:
  staging:
    mode: aggressive
`)
	f, _ := Parse(raw)
	cfg, err := f.Resolve("")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cfg.Mode == nil || *cfg.Mode != "passive" {
		t.Errorf("mode = %v, want passive (base)", cfg.Mode)
	}
}

func TestProfileNamesSorted(t *testing.T) {
	raw := []byte(`
profiles:
  staging: {}
  prod: {}
  ci: {}
`)
	f, _ := Parse(raw)
	got := f.ProfileNames()
	want := []string{"ci", "prod", "staging"}
	if len(got) != len(want) {
		t.Fatalf("ProfileNames len = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("ProfileNames[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestEmptyConfigParsesToZero(t *testing.T) {
	f, err := Parse(nil)
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	cfg, err := f.Resolve("")
	if err != nil {
		t.Fatalf("resolve empty: %v", err)
	}
	if cfg.Timeout != nil {
		t.Errorf("empty config should leave timeout nil, got %v", cfg.Timeout)
	}
}
