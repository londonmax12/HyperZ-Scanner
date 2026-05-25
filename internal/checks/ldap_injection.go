package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// LDAPi probes for LDAP filter injection against parameters whose values
// are concatenated into an LDAP search filter by the backend. Two
// detection paths run per probable sink:
//
//  1. Filter-break (boolean): each pair appends a truthy suffix (closes
//     the value literal, opens an OR with an always-match operand) and a
//     falsy suffix (closes the value literal, opens an AND with a
//     never-match canary) onto sink.Value. On a vulnerable AND-template
//     backend - e.g. `(&(uid=USER)(active=1))` - the truthy variant still
//     matches the original entry (the always-match operand is satisfied)
//     while the falsy variant collapses to no rows (the AND with the
//     canary cannot match). BooleanCompare flags the canonical
//     truthy~baseline / falsy!=baseline shape as BoolVulnerable. Severity
//     High.
//
//  2. Error-based: payloads engineered to break LDAP filter parsing -
//     unbalanced parens, a lone backslash (an escape with no hex digit
//     pair), the empty-filter operator `(|`, the auth-bypass shape
//     `*)(uid=*))(|(uid=*` - are appended to sink.Value. A response that
//     leaks a recognizable LDAP driver error string not already in the
//     baseline body fires the finding. Severity High.
//
// Probable sinks (sinkProbable): query, form, JSON body, and path
// values. Header / cookie sinks are excluded - LDAP filter strings are
// built from application-controlled inputs (form fields, query params),
// not from request metadata, so probing them would just waste requests.
//
// This is an active (LevelDefault) check.
type LDAPi struct{}

func (LDAPi) Name() string { return "ldapi" }

func (LDAPi) Level() Level { return LevelDefault }

// ldapiBodyCap matches the SQLi-boolean cap because the boolean phase
// uses BooleanCompare's similarity scoring - a too-small sample of a
// large templated page wouldn't capture the entry-set divergence we're
// after. The error phase shares the same buffer; driver errors are
// short and ride comfortably inside it.
const ldapiBodyCap = 64 << 10

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

func (c LDAPi) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
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
	var probedAny bool
	seen := map[string]struct{}{}
	for _, sink := range sinks {
		if ctx.Err() != nil {
			break
		}
		if !c.sinkProbable(sink) {
			continue
		}
		if u2, err := url.Parse(sink.URL); err == nil && !sc.Allows(u2) {
			continue
		}
		f, err := c.probe(ctx, client, p.URL, sink)
		if err != nil {
			Report(ctx, fmt.Errorf("probe %s %s=%s: %w", sink.Loc, sink.Name, sink.URL, err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		probedAny = true
		if f == nil {
			continue
		}
		if _, dup := seen[f.DedupeKey]; dup {
			continue
		}
		seen[f.DedupeKey] = struct{}{}
		findings = append(findings, *f)
	}
	if !probedAny && firstErr != nil {
		return nil, firstErr
	}
	return findings, nil
}

// sinkProbable reports whether sink.Loc carries LDAP-filter-
// concatenation risk. Query, form, JSON, and path values commonly flow
// into search filters (login forms, user lookup endpoints, directory
// search). Headers and cookies are not used to construct LDAP filters
// in practice, so probing them would just waste requests.
func (LDAPi) sinkProbable(s Sink) bool {
	switch s.Loc {
	case LocQuery, LocForm, LocJSON, LocPath:
		return true
	}
	return false
}

// probe runs the baseline + boolean + error sweep for one sink. The
// baseline doubles for both phases: BooleanCompare anchors on it, and
// the error phase subtracts any LDAP-error signatures already present
// in the benign baseline so a docs page mentioning "javax.naming" does
// not produce a false positive.
func (c LDAPi) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	_, baseResp, baseBody, _, err := c.send(ctx, client, sink, sink.Value)
	if err != nil {
		return nil, err
	}
	baselineErrors := matchLDAPErrors(baseBody)

	// Pre-strip the sink's original value from the baseline body. Both
	// truthy and falsy variants carry sink.Value as the wire prefix, so
	// leaving the value's echo in place would inflate baseline~truthy
	// similarity on echo-only pages while artificially deflating
	// baseline~falsy. Uniform stripping across all three variants leaves
	// the comparison turning on what the backend DID with the input.
	valueBytes := []byte(sink.Value)
	basePrep := baseBody
	if len(valueBytes) > 0 {
		basePrep = bytes.ReplaceAll(baseBody, valueBytes, nil)
	}
	baseSnap := Snapshot{Status: statusOf(baseResp), Body: basePrep}

	for _, pair := range ldapiBooleanPairs {
		if ctx.Err() != nil {
			break
		}
		canary := NewCanary()
		falsySuffix := strings.ReplaceAll(pair.FalsyTpl, ldapiCanaryPlaceholder, canary)
		truthyWire := sink.Value + pair.Truthy
		falsyWire := sink.Value + falsySuffix

		_, tResp, tBody, _, err := c.send(ctx, client, sink, truthyWire)
		if err != nil {
			Report(ctx, fmt.Errorf("ldapi truthy %s %s=%s pair=%s: %w",
				sink.Loc, sink.Name, sink.URL, pair.Name, err))
			continue
		}
		fReq, fResp, fBody, fTruncated, err := c.send(ctx, client, sink, falsyWire)
		if err != nil {
			Report(ctx, fmt.Errorf("ldapi falsy %s %s=%s pair=%s: %w",
				sink.Loc, sink.Name, sink.URL, pair.Name, err))
			continue
		}

		// Strip the value echo, the literal injection suffixes, and the
		// per-pair canary from each variant body. After stripping, what
		// remains is the structural skeleton the backend produced - if
		// the only divergence between truthy and falsy is the reflected
		// suffix (echo-only page, no LDAP query), all three bodies look
		// identical and BoolNoSignal suppresses the false positive.
		tStripped := tBody
		fStripped := fBody
		if len(valueBytes) > 0 {
			tStripped = bytes.ReplaceAll(tBody, valueBytes, nil)
			fStripped = bytes.ReplaceAll(fBody, valueBytes, nil)
		}
		tStripped = bytes.ReplaceAll(tStripped, []byte(pair.Truthy), nil)
		fStripped = bytes.ReplaceAll(fStripped, []byte(falsySuffix), nil)
		fStripped = bytes.ReplaceAll(fStripped, []byte(canary), nil)

		result := BooleanCompare(
			baseSnap,
			Snapshot{Status: statusOf(tResp), Body: tStripped},
			Snapshot{Status: statusOf(fResp), Body: fStripped},
		)
		if result.Decision != BoolVulnerable {
			continue
		}

		method, probeURL := requestIdentity(fReq)
		return &Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      probeURL,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("LDAP injection (filter-break) in %s parameter %q", sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) is concatenated into an LDAP search filter: pair ldapi/%s "+
					"produced truthy~baseline (sim=%.3f, status=%d) and falsy!=baseline (sim=%.3f, status=%d). "+
					"%s. An attacker can bypass authentication, enumerate directory entries, or extract "+
					"attributes by injecting filter operators in place of literal values.",
				sink.Name, sink.Loc, pair.Name,
				result.TruthySim, statusOf(tResp), result.FalsySim, statusOf(fResp), result.Detail),
			CWE:   "CWE-90",
			OWASP: "A03:2021 Injection",
			Remediation: "Escape every metacharacter LDAP filters treat specially (RFC 4515 lists `( ) * \\ NUL`) " +
				"before concatenating user input into a filter string. Prefer libraries that build filters from typed " +
				"values (FilterBuilder APIs) over string concatenation. For authentication, bind with the user's DN " +
				"rather than embedding the username and password in a search filter.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     statusOf(fResp),
				Snippet:    snippet(fBody, []byte(canary), false),
				Exchange:   RecordExchange(fReq, nil, false, fResp, fBody, fTruncated),
			},
			DedupeKey: MakeKey(c.Name(), ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}

	for _, payload := range ldapiErrorPayloads {
		if ctx.Err() != nil {
			break
		}
		wire := sink.Value + payload
		req, resp, body, truncated, err := c.send(ctx, client, sink, wire)
		if err != nil {
			// Match the boolean phase: a single payload's transport
			// failure shouldn't suppress every payload that follows.
			// Report and keep trying so one network blip doesn't mask
			// a vulnerability the next payload would have surfaced.
			Report(ctx, fmt.Errorf("ldapi error-based %s %s=%s payload=%q: %w",
				sink.Loc, sink.Name, sink.URL, payload, err))
			continue
		}
		hits := matchLDAPErrors(body)
		newHits := subtractPatterns(hits, baselineErrors)
		if len(newHits) == 0 {
			continue
		}
		method, probeURL := requestIdentity(req)
		return &Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      probeURL,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("LDAP injection (error-based) in %s parameter %q", sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) appears to flow into an LDAP search filter: payload %q provoked driver "+
					"error signature %q in the response. An attacker can probably extract directory contents or "+
					"bypass authentication by injecting filter operators in place of literal values.",
				sink.Name, sink.Loc, payload, newHits[0]),
			CWE:   "CWE-90",
			OWASP: "A03:2021 Injection",
			Remediation: "Escape every metacharacter LDAP filters treat specially (RFC 4515 lists `( ) * \\ NUL`) " +
				"before concatenating user input into a filter string. Suppress verbose LDAP error output in production " +
				"responses regardless; leaked stack traces accelerate exploitation even when the underlying bug is patched.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     statusOf(resp),
				Snippet:    snippet(body, []byte(newHits[0]), true),
				Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
			},
			DedupeKey: MakeKey(c.Name(), ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}
	return nil, nil
}

// send mutates sink with wireValue, dispatches the request, and reads up
// to ldapiBodyCap of the body. Mirrors the sibling injection checks'
// send shape so a future shared HTTP shell drops in without per-check
// change.
func (c LDAPi) send(ctx context.Context, client *httpclient.Client, sink Sink, wireValue string) (*http.Request, *http.Response, []byte, bool, error) {
	req, err := sink.MutateRequest(ctx, wireValue)
	if err != nil {
		return nil, nil, nil, false, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, nil, false, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, ldapiBodyCap)
	if err != nil {
		return req, resp, nil, false, err
	}
	return req, resp, body, truncated, nil
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

// Compile-time check: LDAPi satisfies Check.
var _ Check = LDAPi{}
