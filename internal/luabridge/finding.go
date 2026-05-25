package luabridge

import (
	"fmt"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/checks"
)

// marshalFindings converts a Lua array table of finding tables into
// the typed checks.Finding slice the scanner consumes. Each entry
// inherits the LuaCheck's metadata (name, cwe, owasp, remediation,
// default scope) so individual findings only have to declare what
// differs - severity, title, detail, evidence, dedupe parts, and
// per-finding overrides.
//
// The marshal is deliberately strict on the fields that affect
// downstream behavior (severity, dedupe key construction) and
// lenient on text fields (titles, details) which we coerce to
// strings rather than reject. A typo in severity should fail the
// check loudly; a missing title only loses information.
func (c *LuaCheck) marshalFindings(t *lua.LTable, env *runEnv) ([]checks.Finding, error) {
	n := t.Len()
	if n <= 0 {
		return nil, nil
	}
	out := make([]checks.Finding, 0, n)
	for i := 1; i <= n; i++ {
		entry, ok := t.RawGetInt(i).(*lua.LTable)
		if !ok {
			return nil, fmt.Errorf("%s: findings[%d] is %s, not a table",
				c.name, i, t.RawGetInt(i).Type())
		}
		f, err := c.marshalOne(entry, env)
		if err != nil {
			return nil, fmt.Errorf("%s: findings[%d]: %w", c.name, i, err)
		}
		out = append(out, f)
	}
	return out, nil
}

func (c *LuaCheck) marshalOne(t *lua.LTable, env *runEnv) (checks.Finding, error) {
	sev := checks.Severity(lvalString(t.RawGetString("severity")))
	if sev == "" {
		return checks.Finding{}, fmt.Errorf("missing required field `severity`")
	}
	if checks.SeverityRank(sev) < 0 {
		return checks.Finding{}, fmt.Errorf("invalid severity %q", sev)
	}

	target := lvalString(t.RawGetString("target"))
	if target == "" {
		target = env.page.URL
	}
	urlStr := lvalString(t.RawGetString("url"))
	if urlStr == "" {
		urlStr = env.page.URL
	}

	cwe := lvalString(t.RawGetString("cwe"))
	if cwe == "" {
		cwe = c.cwe
	}
	owasp := lvalString(t.RawGetString("owasp"))
	if owasp == "" {
		owasp = c.owasp
	}
	remediation := lvalString(t.RawGetString("remediation"))
	if remediation == "" {
		remediation = c.remediation
	}

	dedupeKey := lvalString(t.RawGetString("dedupe_key"))
	if dedupeKey == "" {
		// dedupe_parts is the ergonomic path: a check supplies just
		// the variable parts and inherits the scope from its module
		// metadata. The explicit dedupe_key escape hatch is for the
		// rare check that needs to override scope per-finding.
		parts := stringList(t, "dedupe_parts")
		scopeStr := lvalString(t.RawGetString("dedupe_scope"))
		sc := c.defaultScope
		if scopeStr != "" {
			parsed, err := parseScope(scopeStr)
			if err != nil {
				return checks.Finding{}, err
			}
			sc = parsed
		}
		dedupeKey = checks.MakeKey(c.name, sc, target, parts...)
	}

	details := stringList(t, "details")

	return checks.Finding{
		Check:       c.name,
		Target:      target,
		URL:         urlStr,
		Severity:    sev,
		Title:       lvalString(t.RawGetString("title")),
		Detail:      lvalString(t.RawGetString("detail")),
		Details:     details,
		CWE:         cwe,
		OWASP:       owasp,
		Remediation: remediation,
		Evidence:    evidenceFromArg(t.RawGetString("evidence")),
		DedupeKey:   dedupeKey,
	}, nil
}
