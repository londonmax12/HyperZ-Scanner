package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTempConfig stages cfg in a temp dir and returns its path. The
// dir is cleaned up via t.Cleanup, so individual tests don't need to
// remember to remove it.
func writeTempConfig(t *testing.T, cfg string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hyperz.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestApplyConfigDefaultsFillsUntouchedFields(t *testing.T) {
	path := writeTempConfig(t, `
timeout: 30s
mode: default
rate: 2.5
crawl:
  enabled: true
  max_pages: 250
checks:
  disable:
    - request-smuggling
  settings:
    reflected-xss:
      body_cap_bytes: 32768
`)

	// applyConfigDefaults reads the configPath off the supplied
	// scanConfig and consults cobra's pflag.Changed on `cmd` to
	// decide whether file values may overwrite struct fields. The
	// production wiring goes through cobra Execute; for the test we
	// construct the same shape by hand: a parsed *cobra.Command and a
	// scanConfig pre-populated with what cobra would have written via
	// flag defaults.
	scfg := scanConfig{
		configPath: path,
		timeout:    10 * time.Second,
		mode:       "passive",
		rps:        5,
		crawlPages: 100,
	}
	cmd := newScanCmd()
	if err := cmd.Flags().Parse([]string{"--config", path}); err != nil {
		t.Fatalf("flag parse: %v", err)
	}
	if err := applyConfigDefaults(cmd, &scfg); err != nil {
		t.Fatalf("applyConfigDefaults: %v", err)
	}

	if scfg.timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", scfg.timeout)
	}
	if scfg.mode != "default" {
		t.Errorf("mode = %q, want default", scfg.mode)
	}
	if scfg.rps != 2.5 {
		t.Errorf("rps = %v, want 2.5", scfg.rps)
	}
	if !scfg.crawl {
		t.Errorf("crawl = false, want true (from config)")
	}
	if scfg.crawlPages != 250 {
		t.Errorf("crawlPages = %d, want 250", scfg.crawlPages)
	}
	if got := scfg.checksDisable; len(got) != 1 || got[0] != "request-smuggling" {
		t.Errorf("checksDisable = %v, want [request-smuggling]", got)
	}
	if scfg.checkSettings == nil {
		t.Fatal("checkSettings = nil, want loaded bag")
	}
	bag, ok := scfg.checkSettings["reflected-xss"]
	if !ok {
		t.Fatal("reflected-xss missing from checkSettings")
	}
	if v, _ := bag["body_cap_bytes"].(int); v != 32768 {
		t.Errorf("body_cap_bytes = %v, want 32768", bag["body_cap_bytes"])
	}
}

func TestApplyConfigDefaultsCLIWinsOverConfig(t *testing.T) {
	path := writeTempConfig(t, `
timeout: 30s
mode: default
`)
	cmd := newScanCmd()
	// --timeout on the CLI must beat the file's value.
	if err := cmd.Flags().Parse([]string{
		"--config", path,
		"--timeout", "5s",
		"--mode", "aggressive",
	}); err != nil {
		t.Fatalf("flag parse: %v", err)
	}
	scfg := scanConfig{
		configPath: path,
		timeout:    5 * time.Second,
		mode:       "aggressive",
		rps:        5,
	}
	if err := applyConfigDefaults(cmd, &scfg); err != nil {
		t.Fatalf("applyConfigDefaults: %v", err)
	}
	if scfg.timeout != 5*time.Second {
		t.Errorf("timeout = %v, want CLI value 5s", scfg.timeout)
	}
	if scfg.mode != "aggressive" {
		t.Errorf("mode = %q, want CLI value aggressive", scfg.mode)
	}
}

func TestApplyConfigDefaultsProfileOverlay(t *testing.T) {
	path := writeTempConfig(t, `
mode: passive
rate: 5
profiles:
  staging:
    mode: default
    rate: 1
    checks:
      disable: ["*-blind"]
`)
	cmd := newScanCmd()
	if err := cmd.Flags().Parse([]string{"--config", path, "--profile", "staging"}); err != nil {
		t.Fatalf("flag parse: %v", err)
	}
	scfg := scanConfig{configPath: path, profile: "staging", mode: "passive", rps: 5}
	if err := applyConfigDefaults(cmd, &scfg); err != nil {
		t.Fatalf("applyConfigDefaults: %v", err)
	}
	if scfg.mode != "default" {
		t.Errorf("mode = %q, want default (profile)", scfg.mode)
	}
	if scfg.rps != 1 {
		t.Errorf("rps = %v, want 1 (profile)", scfg.rps)
	}
	if got := scfg.checksDisable; len(got) != 1 || got[0] != "*-blind" {
		t.Errorf("checksDisable = %v, want [*-blind]", got)
	}
}

func TestApplyConfigDefaultsBadProfile(t *testing.T) {
	path := writeTempConfig(t, `
mode: passive
profiles:
  staging: {}
`)
	cmd := newScanCmd()
	if err := cmd.Flags().Parse([]string{"--config", path, "--profile", "nope"}); err != nil {
		t.Fatalf("flag parse: %v", err)
	}
	scfg := scanConfig{configPath: path, profile: "nope"}
	if err := applyConfigDefaults(cmd, &scfg); err == nil {
		t.Fatal("expected error for unknown profile, got nil")
	}
}

func TestApplyConfigDefaultsNoConfigFileNoop(t *testing.T) {
	cmd := newScanCmd()
	if err := cmd.Flags().Parse([]string{"--url", "https://example.com"}); err != nil {
		t.Fatalf("flag parse: %v", err)
	}
	before := scanConfig{
		timeout: 10 * time.Second,
		mode:    "passive",
		rps:     5,
	}
	if err := applyConfigDefaults(cmd, &before); err != nil {
		t.Fatalf("applyConfigDefaults: %v", err)
	}
	if before.timeout != 10*time.Second || before.mode != "passive" || before.rps != 5 {
		t.Errorf("no-config path mutated cfg: %+v", before)
	}
}
