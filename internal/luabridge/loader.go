package luabridge

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/londonmax12/hyperz/internal/checks"
)

// LoadDir loads every .lua file under root in fsys and returns the
// resulting LuaChecks. Files are loaded in alphabetical order so
// the catalog the scanner sees is deterministic across runs (which
// matters for the hyperz checks list output and for any
// dedupe-by-name logic downstream).
//
// Files that fail to parse or whose module table is malformed
// return a non-nil error annotated with the filename; one bad rule
// aborts the load rather than silently skipping. We would rather a
// scan startup fail loudly than silently drop a check the operator
// expected to be running.
//
// The root path defaults to "." (every .lua file in fsys). Nested
// directories are walked, but the resulting registry is flat -
// directory structure is for organization, not namespacing.
func LoadDir(fsys fs.FS, root string) ([]*LuaCheck, error) {
	if root == "" {
		root = "."
	}
	var files []string
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".lua") {
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("luabridge: walk: %w", err)
	}
	sort.Strings(files)

	out := make([]*LuaCheck, 0, len(files))
	for _, f := range files {
		src, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, fmt.Errorf("luabridge: read %s: %w", f, err)
		}
		c, err := Load(path.Base(f), src)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// AsChecks unwraps a LuaCheck slice into the checks.Check interface
// slice the catalog registry expects. Two-phase modules (those whose
// metadata declared `phase = "two-phase"`) are wrapped in luaTwoPhase
// so type assertion to checks.TwoPhaseCheck succeeds only for the
// opted-in subset; single-phase modules pass through bare. This gates
// scanner phase-2 fanout to the checks that actually need it, since
// the scanner re-fetches the visited URL set the moment any
// TwoPhaseCheck is registered.
func AsChecks(in []*LuaCheck) []checks.Check {
	out := make([]checks.Check, 0, len(in))
	for _, c := range in {
		if c.isTwoPhase {
			out = append(out, &luaTwoPhase{LuaCheck: c})
		} else {
			out = append(out, c)
		}
	}
	return out
}
