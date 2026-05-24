package checks

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// CmdInjectionBlind probes for OS command injection via error-based detection.
// Unlike the timing-based CmdInjection check, this targets scenarios where
// command execution is blind (output not directly visible) but errors from
// command execution leak into the response. Detects injection in contexts
// where timing-based approaches fail (cached responses, fixed latencies,
// suppressed delays).
//
// For each sink, the check sends payloads designed to trigger command
// execution failures (e.g. nonexistent commands, syntax errors) and scans
// the response body for shell error signatures ("command not found",
// "is not recognized", syntax errors, etc). A hit on both the injected
// command markers AND error patterns confirms RCE.
//
// Complements CmdInjection by catching blind RCE in different contexts:
// - Cached responses where timing can't be measured
// - Contexts where output is captured but not user-visible
// - Scenarios with suppressed error output in timing check
//
// Per sink: 1 probe per payload (fast on non-vulnerable sinks).
// With low overhead and no confirmation overhead, this runs efficiently
// alongside CmdInjection.
//
// Active (LevelDefault) check.
type CmdInjectionBlind struct{}

func (CmdInjectionBlind) Name() string { return "cmd-injection-blind" }

func (CmdInjectionBlind) Level() Level { return LevelDefault }

func (c CmdInjectionBlind) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if !sc.Allows(u) {
		return nil, nil
	}
	sinks := SinksFor(p)
	if len(sinks) == 0 {
		return nil, nil
	}

	var findings []Finding
	var firstErr error
	seen := map[string]struct{}{}
	for _, sink := range sinks {
		if ctx.Err() != nil {
			break
		}
		if u2, err := url.Parse(sink.URL); err == nil && !sc.Allows(u2) {
			continue
		}
		f, err := c.probe(ctx, client, p.URL, sink)
		if err != nil {
			Report(ctx, fmt.Errorf("blind-probe %s %s=%s: %w", sink.Loc, sink.Name, sink.URL, err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if f == nil {
			continue
		}
		if _, dup := seen[f.DedupeKey]; dup {
			continue
		}
		seen[f.DedupeKey] = struct{}{}
		findings = append(findings, *f)
	}
	return findings, firstErr
}

// probe dispatches error-based payloads for one sink. Returns a finding
// if a payload triggers both the injected command marker and error signatures.
func (c CmdInjectionBlind) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	anchor := sink.Value
	if anchor == "" {
		anchor = cmdInjectionFillerValue
	}

	canary := NewCanary()
	for _, p := range PayloadsFor(PayloadCmdInjectBlind) {
		if ctx.Err() != nil {
			break
		}
		wireValue := anchor + p.Render(canary, 0)

		req, err := sink.MutateRequest(ctx, wireValue)
		if err != nil {
			Report(ctx, fmt.Errorf("cmd-injection-blind mutate %s %s=%s pl=%s: %w",
				sink.Loc, sink.Name, sink.URL, p.Name, err))
			continue
		}

		resp, err := client.Do(ctx, req)
		if err != nil {
			Report(ctx, fmt.Errorf("cmd-injection-blind send %s %s=%s pl=%s: %w",
				sink.Loc, sink.Name, sink.URL, p.Name, err))
			continue
		}
		defer resp.Body.Close()

		body, truncated, err := httpclient.ReadBodyCapped(resp, cmdInjectionBodyCap)
		if err != nil {
			Report(ctx, fmt.Errorf("cmd-injection-blind read %s %s=%s pl=%s: %w",
				sink.Loc, sink.Name, sink.URL, p.Name, err))
			continue
		}

		// Match both: the injected canary (proves injection) AND error patterns
		// (proves execution). Both conditions must fire to avoid false positives
		// from unrelated errors in the page.
		bodyStr := strings.ToLower(string(body))
		if !strings.Contains(bodyStr, strings.ToLower(canary)) {
			continue
		}

		matchedError := ""
		for _, errSig := range CmdErrorPatterns() {
			if strings.Contains(bodyStr, errSig) {
				matchedError = errSig
				break
			}
		}
		if matchedError == "" {
			continue
		}

		probeURL := ""
		method := ""
		if req != nil {
			method = req.Method
			if req.URL != nil {
				probeURL = req.URL.String()
			}
		}
		status := statusOf(resp)

		return &Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      probeURL,
			Severity: SeverityCritical,
			Title:    fmt.Sprintf("Blind OS command injection in %s parameter %q", sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) is concatenated into a shell command. "+
					"Payload cmd-injection-blind/%s with canary %q triggered both the injected canary "+
					"(confirming injection reached execution context) and error signature %q (confirming command execution). "+
					"The application is vulnerable to blind RCE: an attacker can execute arbitrary OS commands as the web server process, "+
					"enabling filesystem read/write, network reconnaissance, or full system compromise.",
				sink.Name, sink.Loc, p.Name, canary, matchedError),
			CWE:   "CWE-78",
			OWASP: "A03:2021 Injection",
			Remediation: "Never pass user input to a shell. Use the language's exec API that takes an argv slice " +
				"(e.g. Go's exec.Command(name, args...), Python's subprocess with shell=False) so arguments are passed as " +
				"separate elements rather than concatenated into a shell-parsed string. When a shell is unavoidable, " +
				"strictly allowlist the permitted argument shape - blocklists of metacharacters are routinely bypassed.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     status,
				Snippet: fmt.Sprintf("canary=%q error-signature=%q", canary, matchedError),
				Exchange: RecordExchange(req, nil, false, resp, body, truncated),
			},
			DedupeKey: MakeKey(c.Name(), ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}
	return nil, nil
}

// CmdErrorPatterns returns shell error signatures that indicate command
// execution. Patterns are lowercase and matched against a lowercased response
// body. When found in a response alongside an injected canary, they confirm
// blind RCE. Curated to cover POSIX shells and Windows cmd.exe.
func CmdErrorPatterns() []string {
	return []string{
		// POSIX shells: command not found is the most reliable signal
		"command not found",
		"not found: command",
		// bash-specific
		": not found",
		"bad substitution",
		"command substitution: line",
		// zsh
		"command not found:",
		// Broader POSIX syntax errors
		"syntax error",
		"unexpected token",
		"unexpected operator",
		// Windows cmd.exe
		"is not recognized as an internal or external command",
		"'\\' is not recognized",
		"cannot find the path specified",
		// PowerShell
		"is not recognized as the name of a cmdlet",
		"is not recognized as the name of",
		"object reference not set to an instance",
		// Generic shell indicators
		"bash: ",
		"sh: ",
		"/bin/sh: ",
		"permission denied",
		"no such file or directory",
	}
}
