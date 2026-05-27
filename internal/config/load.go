package config

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads path and decodes it into a *File. Unknown keys are
// rejected so a typo in the YAML fails fast instead of silently
// disabling whatever the operator intended.
//
// Returns the parsed File and the absolute path the loader resolved
// (useful for log lines / future include directives). path may be a
// relative path; the caller is responsible for any os.Chdir-ing.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse decodes raw as a YAML config file. Split from Load so tests
// can exercise the decoder against in-memory buffers without staging
// fixture files.
func Parse(raw []byte) (*File, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)

	var f File
	if err := dec.Decode(&f); err != nil {
		if err == io.EOF {
			return &f, nil
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if extra := dec.Decode(&File{}); extra == nil {
		return nil, fmt.Errorf("parse config: multiple YAML documents are not supported")
	} else if extra != io.EOF {
		return nil, fmt.Errorf("parse config: trailing content: %w", extra)
	}
	return &f, nil
}

// Resolve returns the effective Config for the named profile, merged
// on top of the file's base values.
//
// An empty profile name returns the base config unchanged. An unknown
// profile name returns an error listing the available profiles, so a
// typo in --profile surfaces immediately instead of silently scanning
// with default settings.
func (f *File) Resolve(profile string) (*Config, error) {
	base := f.Config
	if profile == "" {
		return &base, nil
	}
	overlay, ok := f.Profiles[profile]
	if !ok {
		names := make([]string, 0, len(f.Profiles))
		for name := range f.Profiles {
			names = append(names, name)
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("profile %q not defined (this config has no profiles)", profile)
		}
		return nil, fmt.Errorf("profile %q not defined (available: %v)", profile, names)
	}
	merged := base
	merged.merge(&overlay)
	return &merged, nil
}

// ProfileNames returns the sorted list of profile names defined in f.
// Returned in deterministic order so `hyperz config profiles` output
// is stable across runs.
func (f *File) ProfileNames() []string {
	if len(f.Profiles) == 0 {
		return nil
	}
	out := make([]string, 0, len(f.Profiles))
	for name := range f.Profiles {
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

// sortStrings is a small wrapper kept here so the load layer does not
// pull in `sort` for one call site. Tiny insertion sort suffices for
// the handful of profile names a config realistically defines.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
