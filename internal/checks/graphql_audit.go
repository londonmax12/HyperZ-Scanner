package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// GraphQLAudit probes GraphQL endpoints for the exposures that turn an
// otherwise-quiet API into a recon, DoS, and credential-attack surface.
// Two probe families run in sequence:
//
// Configuration exposures (recon-and-amplification levers):
//
//   1. Introspection enabled: the canonical __schema / __type query
//      returns the full type system, every resolver name, every
//      argument shape. Production gateways should disable it; many
//      forget to.
//   2. Field suggestions enabled: even with introspection off, a
//      mistyped field name often comes back with "Did you mean ..."
//      which leaks the same schema piecemeal over many queries.
//   3. Query batching accepted: a JSON array of operations in one
//      HTTP request lets a caller multiply server-side work without
//      paying for distinct rate-limited round-trips. Combined with
//      aliasing or expensive resolvers this is a denial-of-service
//      lever.
//   4. Alias-based field amplification: one query can call the same
//      field N times via aliases, bypassing per-field rate limits and
//      amplifying password-guessing or expensive-lookup endpoints.
//
// Active exploitation probes (cross the line from "misconfig" to
// "weaponised lever"). These three only fire at LevelAggressive because
// each sends traffic that lands in the target's auth or DoS-mitigation
// logs as a real attack: forged credential attempts, batched login
// mutations, and a depth-8 introspection query that on a vulnerable
// target IS the DoS payload it measures. Operators who want them set
// --level=aggressive explicitly.
//
//   5. Alias-based auth bypass: one mutation aliases a login-shaped
//      resolver N times so the credential check runs N times in one
//      HTTP request. Per-request rate limits count one attempt; the
//      server actually processes N. This is the rate-limit bypass
//      attackers use to brute-force OTPs / passwords behind a "5
//      attempts per minute" policy.
//   6. Batched mutations: an HTTP-level array of N mutation operations
//      that the server processes per-element. Distinct from probe 3
//      because some gateways accept batched queries but reject mutation
//      batches; when both succeed (3 and 6) the per-request limit on
//      state-changing operations is decorative.
//   7. Query depth limit not enforced: a query nested 8 levels deep
//      through the introspection ofType chain that the server resolves
//      without rejection. GraphQL has no inherent depth limit, and an
//      unbounded depth is the canonical DoS amplifier on schemas with
//      self-referential connections (User.friends.friends.friends...).
//
// Gate: the check inspects the already-fetched page first. A body
// that carries GraphiQL / Apollo Sandbox / Yoga / Playground HTML
// markers - or the JSON "must provide query string" envelope a GET
// against a GraphQL endpoint typically returns - is conclusive and
// the probes fire directly. When the body is empty or inconclusive,
// the check falls back to the URL path gate (/graphql, /graphiql,
// etc.) plus a one-shot discovery POST. Pages that match neither cost
// zero requests.
//
// Per endpoint at LevelDefault: at most 1 discovery POST + 4
// configuration probes = 5 requests. At LevelAggressive the three
// exploitation probes add up to 7 more (each iterates loginMutationCandidates
// and stops on the first match), so the worst case is 12 requests against
// a target that doesn't recognise any candidate field. The probes are
// independent - one failed probe does not suppress the others, so a target
// that rejects array bodies still gets audited for introspection,
// suggestions, and alias amplification.
//
// Active (LevelDefault) check.
type GraphQLAudit struct{}

func (GraphQLAudit) Name() string { return "graphql-audit" }

func (GraphQLAudit) Level() Level { return LevelDefault }

const (
	// graphqlBodyCap bounds response bodies the check buffers. The
	// signals (presence of __schema, "Did you mean", array-shaped
	// response, aliased fields) all land near the start of any
	// reasonable JSON response; 64 KiB tolerates pretty-printed
	// introspection schemas without dragging large error blobs into
	// memory.
	graphqlBodyCap = 64 << 10
	// graphqlAliasCount is the alias multiplier the alias-abuse probe
	// uses. 10 is high enough to surface as obvious amplification in
	// reports without crossing typical query-complexity limits a
	// security-conscious operator would have set. The point is to
	// demonstrate the lever exists, not to actually DoS the target.
	graphqlAliasCount = 10
	// graphqlAliasAuthCount is the alias multiplier the alias-based
	// auth-bypass probe uses. Smaller than graphqlAliasCount because
	// every alias here triggers an actual credential-check resolver
	// invocation: 5 attempts is enough to prove the per-request rate
	// limit is bypassed without amounting to a serious brute-force
	// attempt against the target's account store.
	graphqlAliasAuthCount = 5
	// graphqlBatchMutationCount is the array length the batched-
	// mutation probe sends. 3 distinguishes "batched mutations
	// executed per-element" from "batch rejected globally" without
	// significantly amplifying the credential-attempt traffic.
	graphqlBatchMutationCount = 3
	// graphqlDepthLevels is the nesting depth the depth probe asks
	// the server to traverse. 8 is comfortably above the cap any
	// security-conscious gateway sets (graphql-armor defaults to 7,
	// Apollo / Yoga examples suggest 5-10): a server that resolves
	// the full chain has effectively no depth limit.
	graphqlDepthLevels = 8
)

// loginMutationCandidates are the field names most commonly used for
// the credential-check entry point on a GraphQL Mutation type. The
// alias-auth-bypass and batched-mutations probes iterate this list
// and stop at the first candidate that produces per-alias / per-
// element execution evidence; an absent field returns a single
// global validation error rather than per-call processing, which the
// signal helpers correctly classify as "no bypass".
//
// Order matters: the canonical, most-common names sit first so a real
// match short-circuits the iteration after one probe. The tail catches
// variants seen in the wild (loginUser / userLogin from generated
// resolvers, signin one-word from camelCase-averse schemas, logIn
// from PascalCase-light schemas, and the two OTP / passwordless entry
// points that share the same rate-limit bypass shape).
var loginMutationCandidates = []string{
	"login",
	"signIn",
	"authenticate",
	"loginUser",
	"userLogin",
	"signin",
	"logIn",
	"verifyOtp",
	"requestPasswordReset",
}

// graphqlPaths are the URL path suffixes the check treats as evidence
// of a GraphQL endpoint. Matched case-insensitively against the page
// path. Curated to the conventions every major GraphQL server framework
// ships with by default; rare custom mounts (/api/data, /query) are
// missed by design - the page-gate would otherwise fire on every JSON
// API and bury operators in failed-discovery reports.
var graphqlPaths = []string{
	"/graphql",
	"/graphiql",
	"/playground",
	"/altair",
	"/api/graphql",
	"/v1/graphql",
	"/v2/graphql",
	"/api/v1/graphql",
	"/api/v2/graphql",
}

func (c GraphQLAudit) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if !sc.Allows(u) {
		return nil, nil
	}

	// Two-tier gate. First try the already-fetched body and response
	// headers: a GraphiQL / Apollo Sandbox / Yoga / Playground UI is
	// unambiguous evidence, as is a GraphQL JSON error envelope
	// returned to a GET, as is a Hasura-style x-hasura-* response
	// header. When that fingerprint hits we skip the discovery probe
	// entirely - the page itself is the proof. Falling back to a path
	// heuristic plus a confirmation POST catches POST-only endpoints
	// whose GET response is empty or 405. Pages that match neither
	// gate cost zero requests.
	pageEvidence := pageBodyLooksGraphQL(p) || pageHeadersLookGraphQL(p)
	if !pageEvidence {
		if !looksGraphQLPath(u.Path) {
			return nil, nil
		}
		if !c.discover(ctx, client, p.URL) {
			return nil, nil
		}
	}

	var findings []Finding
	if f, err := c.probeIntrospection(ctx, client, p.URL); err != nil {
		Report(ctx, fmt.Errorf("graphql-audit introspection %s: %w", p.URL, err))
	} else if f != nil {
		findings = append(findings, *f)
	}
	if f, err := c.probeSuggestions(ctx, client, p.URL); err != nil {
		Report(ctx, fmt.Errorf("graphql-audit suggestions %s: %w", p.URL, err))
	} else if f != nil {
		findings = append(findings, *f)
	}
	if f, err := c.probeBatch(ctx, client, p.URL); err != nil {
		Report(ctx, fmt.Errorf("graphql-audit batch %s: %w", p.URL, err))
	} else if f != nil {
		findings = append(findings, *f)
	}
	if f, err := c.probeAlias(ctx, client, p.URL); err != nil {
		Report(ctx, fmt.Errorf("graphql-audit alias %s: %w", p.URL, err))
	} else if f != nil {
		findings = append(findings, *f)
	}

	// Exploitation probes: forge credential attempts, mutation batches,
	// and a deep introspection query. Each lands in the target's auth or
	// DoS-mitigation logs as a real attack; gated behind LevelAggressive
	// so default scans stay safe to point at a production endpoint
	// without burning the scan IP through the target's WAF.
	if LevelFrom(ctx) < LevelAggressive {
		return findings, nil
	}
	if f, err := c.probeAliasAuthBypass(ctx, client, p.URL); err != nil {
		Report(ctx, fmt.Errorf("graphql-audit alias-auth-bypass %s: %w", p.URL, err))
	} else if f != nil {
		findings = append(findings, *f)
	}
	if f, err := c.probeBatchMutations(ctx, client, p.URL); err != nil {
		Report(ctx, fmt.Errorf("graphql-audit batch-mutations %s: %w", p.URL, err))
	} else if f != nil {
		findings = append(findings, *f)
	}
	if f, err := c.probeDepth(ctx, client, p.URL); err != nil {
		Report(ctx, fmt.Errorf("graphql-audit depth %s: %w", p.URL, err))
	} else if f != nil {
		findings = append(findings, *f)
	}
	return findings, nil
}

// graphqlBodyMarkers are case-insensitive substrings that, when found
// in an already-fetched response body, identify the URL as a GraphQL
// endpoint without sending a discovery probe. Two classes are folded
// in: HTML UI markers (GraphiQL / Apollo Sandbox / Yoga / Playground
// landing pages every major GraphQL server ships with a GET handler)
// and JSON error-envelope phrases that GraphQL servers return when a
// GET arrives without a query parameter. Each entry is curated to be
// specific enough that a non-GraphQL page is extremely unlikely to
// carry it incidentally.
var graphqlBodyMarkers = []string{
	// GraphiQL UI - the canonical in-browser explorer; ships with
	// Apollo Server, express-graphql, and most reference servers.
	"graphiql",
	// Apollo Sandbox / Studio - the successor to GraphiQL in Apollo's
	// default Open hosted explorer; uses a distinct embed script.
	"apollo sandbox",
	"embeddable-explorer",
	"embeddable-sandbox",
	// GraphQL Playground - the legacy Prisma-era explorer, still
	// bundled with several frameworks (Hot Chocolate, Yoga v1).
	"graphql playground",
	"prisma-cloud",
	// GraphQL Yoga's landing page, served by yoga's GET handler.
	"yoga graphql",
	"graphql-yoga",
	// Altair (third-party explorer) - some teams expose it directly.
	"altair graphql",
	// JSON error envelope phrases. graphql-js and ports almost
	// universally use this exact wording on bare GETs; quoted forms
	// like "must provide query string" or "must provide a query"
	// (Apollo) and "you must provide a query string" (some forks)
	// all collapse to the same case-insensitive substring.
	"must provide query",
	"must provide a query",
	"must provide an operation",
}

// pageBodyLooksGraphQL returns true when the already-fetched body
// carries an unambiguous GraphQL fingerprint. Used as a zero-request
// gate so the crawler's existing GET response is enough to decide
// whether to fire the finding probes. Matching is case-insensitive
// and bounded to the first 64 KiB of body to keep the cost predictable
// on pages that mysteriously balloon (e.g. an error template that
// echoes a huge stack trace).
func pageBodyLooksGraphQL(p page.Page) bool {
	if len(p.Body) == 0 {
		return false
	}
	scan := p.Body
	if len(scan) > graphqlBodyCap {
		scan = scan[:graphqlBodyCap]
	}
	low := bytes.ToLower(scan)
	for _, m := range graphqlBodyMarkers {
		if bytes.Contains(low, []byte(m)) {
			return true
		}
	}
	return false
}

// pageHeadersLookGraphQL returns true when the page's response
// headers carry an unambiguous GraphQL server fingerprint. Currently
// matches Hasura's x-hasura-* response header family, which Hasura's
// engine sets on every response regardless of whether the request hit
// a query path or a static asset. Cheap zero-request gate that catches
// Hasura deployments mounted at non-standard paths the path gate
// would miss.
func pageHeadersLookGraphQL(p page.Page) bool {
	if p.Headers == nil {
		return false
	}
	for k := range p.Headers {
		if strings.HasPrefix(strings.ToLower(k), "x-hasura-") {
			return true
		}
	}
	return false
}

// looksGraphQLPath returns true when path matches one of the curated
// GraphQL endpoint conventions. Comparison is case-insensitive and
// matches either an exact path or a path containing the suffix as a
// segment so /api/v1/graphql/healthz still gates correctly.
func looksGraphQLPath(path string) bool {
	low := strings.ToLower(path)
	for _, suffix := range graphqlPaths {
		if low == suffix || strings.HasSuffix(low, suffix) || strings.Contains(low, suffix+"/") {
			return true
		}
	}
	return false
}

// discover sends `{__typename}` and returns true when the response
// looks like a GraphQL reply. __typename is the most reliable probe:
// it exists in every schema, requires no schema knowledge, and a
// non-GraphQL JSON endpoint will not return data.__typename on the
// shape of a {query} body.
func (c GraphQLAudit) discover(ctx context.Context, client *httpclient.Client, target string) bool {
	body, status, _, err := c.postQuery(ctx, client, target, map[string]any{"query": "{__typename}"})
	if err != nil || status == 0 {
		return false
	}
	// GraphQL responses always carry "data" or "errors" at the top
	// level. Either is sufficient for discovery: an endpoint that
	// rejects the query with an "errors" key still validates that we
	// reached a GraphQL parser.
	return graphqlShapeMatches(body)
}

// probeIntrospection runs the canonical introspection query and emits
// a finding when the response contains __schema data. Severity is
// Medium: schema disclosure dramatically lowers the bar for further
// exploitation (every resolver name, every argument type, every
// privileged mutation is revealed) but is not by itself an injection
// or auth bypass.
func (c GraphQLAudit) probeIntrospection(ctx context.Context, client *httpclient.Client, target string) (*Finding, error) {
	query := `query IntrospectionQuery { __schema { queryType { name } types { name kind } } }`
	body, status, exch, err := c.postQuery(ctx, client, target, map[string]any{"query": query})
	if err != nil {
		return nil, err
	}
	if !introspectionEnabled(body) {
		return nil, nil
	}
	return &Finding{
		Check:    c.Name(),
		Target:   target,
		URL:      target,
		Severity: SeverityMedium,
		Title:    "GraphQL introspection enabled",
		Detail: "The endpoint responded to a __schema introspection query with the full type system. " +
			"An attacker can enumerate every resolver name, argument shape, and return type without authentication, " +
			"dramatically lowering the bar for finding privileged mutations, hidden fields, and injection-prone arguments. " +
			"Introspection is a development convenience; production gateways should disable it.",
		CWE:   "CWE-200",
		OWASP: "A05:2021 Security Misconfiguration",
		Remediation: "Disable introspection on production GraphQL endpoints. Apollo Server: set introspection: false. " +
			"GraphQL Yoga: pass disableIntrospection or the graphql-armor plugin. Hot Chocolate (.NET): RemoveAllowedDefinitions or " +
			"the AddIntrospectionAllowedFor configuration. If a tooling client legitimately needs the schema, ship a static " +
			"schema.graphql artifact rather than exposing live introspection.",
		Evidence: &Evidence{
			Method:     http.MethodPost,
			RequestURL: target,
			Status:     status,
			Snippet:    snippetJSON(body),
			Exchange:   exch,
		},
		DedupeKey: MakeKey(c.Name(), ScopePage, target, "introspection"),
	}, nil
}

// probeSuggestions sends a deliberately misspelled field and looks for
// the "Did you mean ..." hint in the response. Many GraphQL servers
// enable suggestions by default for developer-experience reasons; when
// introspection is disabled but suggestions are not, an attacker can
// reconstruct the schema field-by-field over many queries.
func (c GraphQLAudit) probeSuggestions(ctx context.Context, client *httpclient.Client, target string) (*Finding, error) {
	// Use a name that lexically resembles common field names so the
	// server's suggestion algorithm has something to suggest. A wholly
	// random alphabet (zzzz...) often returns no suggestion not because
	// the feature is off but because nothing in the schema is close.
	query := `{ usre { id } }`
	body, status, exch, err := c.postQuery(ctx, client, target, map[string]any{"query": query})
	if err != nil {
		return nil, err
	}
	if !suggestionsLeaked(body) {
		return nil, nil
	}
	return &Finding{
		Check:    c.Name(),
		Target:   target,
		URL:      target,
		Severity: SeverityLow,
		Title:    "GraphQL field suggestions enabled",
		Detail: "The endpoint returned 'Did you mean ...' suggestions for a mistyped field. " +
			"Field suggestions reveal real schema names piecemeal even when introspection is disabled - an attacker can " +
			"reconstruct the schema by querying near-miss names. Suggestions exist for developer ergonomics; production " +
			"endpoints should suppress them so the introspection-off configuration is not undermined.",
		CWE:   "CWE-200",
		OWASP: "A05:2021 Security Misconfiguration",
		Remediation: "Disable field suggestions on production. Apollo Server v4: use the NoSuggestionsValidationRule from " +
			"graphql-armor or configure the GraphQL validation pipeline to strip the FieldsOnCorrectType message. " +
			"For other servers, configure the validation layer to suppress 'Did you mean ...' hints in non-development environments.",
		Evidence: &Evidence{
			Method:     http.MethodPost,
			RequestURL: target,
			Status:     status,
			Snippet:    snippetJSON(body),
			Exchange:   exch,
		},
		DedupeKey: MakeKey(c.Name(), ScopePage, target, "suggestions"),
	}, nil
}

// probeBatch sends an array of operations in one HTTP request. A server
// that returns an array of responses is accepting unrestricted batching,
// which lets a caller amplify per-request work and bypass per-request
// rate limits.
func (c GraphQLAudit) probeBatch(ctx context.Context, client *httpclient.Client, target string) (*Finding, error) {
	// Two operations is the smallest batch that distinguishes "batching
	// enabled" from "single query in a single-element array (some
	// servers tolerate this)". A two-element array forces a real
	// batch executor to run twice.
	batch := []any{
		map[string]any{"query": "{__typename}"},
		map[string]any{"query": "{__typename}"},
	}
	body, status, exch, err := c.postBody(ctx, client, target, batch)
	if err != nil {
		return nil, err
	}
	if !batchAccepted(body) {
		return nil, nil
	}
	return &Finding{
		Check:    c.Name(),
		Target:   target,
		URL:      target,
		Severity: SeverityMedium,
		Title:    "GraphQL query batching accepted",
		Detail: "The endpoint accepted a batched array of two operations and returned an array of responses. " +
			"Unrestricted batching lets a caller multiply server-side work without paying for distinct HTTP round trips, " +
			"undermines per-request rate limiting, and amplifies any expensive resolver. When combined with aliasing it " +
			"becomes a practical denial-of-service lever.",
		CWE:   "CWE-770",
		OWASP: "A04:2021 Insecure Design",
		Remediation: "Disable batching unless required, or cap the array length and reject oversize batches at the parser. " +
			"Apollo Server: set allowBatchedHttpRequests: false (v4) or configure the BatchHttpLink rejection on the gateway. " +
			"Yoga / Helix: configure the batching plugin to enforce a maxBatchSize. Combine with query-complexity limits so " +
			"a small batch cannot still amplify expensive resolvers.",
		Evidence: &Evidence{
			Method:     http.MethodPost,
			RequestURL: target,
			Status:     status,
			Snippet:    snippetJSON(body),
			Exchange:   exch,
		},
		DedupeKey: MakeKey(c.Name(), ScopePage, target, "batch"),
	}, nil
}

// probeAlias sends one query that calls __typename ten times under
// distinct aliases. A server that returns ten alias keys in data has no
// alias-count limit, which is the same lever batching gives but inside
// a single operation - useful to amplify any expensive field or to
// bypass per-field rate limits on password / token endpoints.
func (c GraphQLAudit) probeAlias(ctx context.Context, client *httpclient.Client, target string) (*Finding, error) {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < graphqlAliasCount; i++ {
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "a%d:__typename", i)
	}
	b.WriteString("}")
	body, status, exch, err := c.postQuery(ctx, client, target, map[string]any{"query": b.String()})
	if err != nil {
		return nil, err
	}
	got := aliasResponseCount(body)
	if got < graphqlAliasCount {
		return nil, nil
	}
	return &Finding{
		Check:    c.Name(),
		Target:   target,
		URL:      target,
		Severity: SeverityMedium,
		Title:    fmt.Sprintf("GraphQL alias amplification accepted (%d aliases per query)", got),
		Detail: fmt.Sprintf(
			"The endpoint resolved a query containing %d alias calls of the same field in one operation. "+
				"Aliases let a caller execute the same resolver many times inside a single HTTP request, "+
				"amplifying expensive operations and bypassing per-field rate limits. On login or token "+
				"endpoints this turns into password / OTP brute-forcing at the alias-per-request rate; on "+
				"data-heavy resolvers it is a denial-of-service lever.",
			got),
		CWE:   "CWE-770",
		OWASP: "A04:2021 Insecure Design",
		Remediation: "Cap the alias count per operation at the GraphQL gateway. graphql-armor's MaxAliasesRule sets a hard limit; " +
			"Apollo and Yoga can install a custom validation rule that walks the AST and rejects operations exceeding the cap. " +
			"Combine with query-complexity limits and per-resolver rate limits so the cap is enforced even when one alias still " +
			"reaches an expensive field.",
		Evidence: &Evidence{
			Method:     http.MethodPost,
			RequestURL: target,
			Status:     status,
			Snippet:    snippetJSON(body),
			Exchange:   exch,
		},
		DedupeKey: MakeKey(c.Name(), ScopePage, target, "alias"),
	}, nil
}

// probeAliasAuthBypass tests whether per-request rate limits on the
// credential-check mutation can be bypassed by calling that mutation
// multiple times via aliases inside one operation. Iterates the
// loginMutationCandidates list and stops at the first field that
// produces per-alias execution evidence in the response (either N
// data keys, or N errors[].path entries each rooted at a distinct
// alias). An absent field returns a single global validation error
// and yields no alias signal, so the probe correctly skips it.
//
// Severity High because the bypass turns any HTTP-layer brute-force
// limit on the login mutation into "N attempts per request"; on a
// "5 per minute" policy with N=5 aliases the effective rate is 25
// per minute, and at N=100 (which servers without alias caps will
// happily accept) it is 500 per minute. Credentials submitted are
// garbage probe values, not enumerable usernames, so the probe does
// not contribute to account-takeover noise on the target.
func (c GraphQLAudit) probeAliasAuthBypass(ctx context.Context, client *httpclient.Client, target string) (*Finding, error) {
	for _, field := range loginMutationCandidates {
		query := buildAliasAuthQuery(field, graphqlAliasAuthCount)
		body, status, exch, err := c.postQuery(ctx, client, target, map[string]any{"query": query})
		if err != nil {
			return nil, err
		}
		got := perAliasResolveCount(body)
		if got < graphqlAliasAuthCount {
			continue
		}
		return &Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      target,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("GraphQL alias-based auth bypass on %s (%d resolver invocations per HTTP request)", field, got),
			Detail: fmt.Sprintf(
				"A single mutation aliasing %d calls of %s was resolved %d times in one HTTP request. "+
					"Rate limits that count HTTP requests on the credential-check mutation do not bound the number of "+
					"actual credential checks the server performs, so an attacker can multiply password / OTP attempts by "+
					"the alias count without sending additional requests. This is the canonical lever used to defeat "+
					"'N attempts per minute' policies on login, password-reset, and MFA-verification mutations.",
				graphqlAliasAuthCount, field, got),
			CWE:   "CWE-307",
			OWASP: "A07:2021 Identification and Authentication Failures",
			Remediation: "Enforce credential-check rate limits at the resolver layer, not at the HTTP request boundary. " +
				"Install a validation rule that caps aliases per operation (graphql-armor's MaxAliasesRule, or a custom rule " +
				"that walks the AST and rejects more than one alias for sensitive mutations - login, signIn, authenticate, " +
				"requestPasswordReset, verifyOtp, charge). For Apollo Server v4 the rule plugs into the validationRules array; " +
				"Yoga / Helix expose the same hook on the schema construction.",
			Evidence: &Evidence{
				Method:     http.MethodPost,
				RequestURL: target,
				Status:     status,
				Snippet:    snippetJSON(body),
				Exchange:   exch,
			},
			DedupeKey: MakeKey(c.Name(), ScopePage, target, "alias-auth-bypass", field),
		}, nil
	}
	return nil, nil
}

// probeBatchMutations tests whether the server processes a JSON-array
// batch of mutation operations per-element. Distinct from probeBatch
// because some gateways accept batched queries but reject batched
// mutations: the batch signal alone does not prove state-changing
// operations can also be amplified at the HTTP boundary. Iterates the
// loginMutationCandidates list and stops at the first field whose
// per-element execution is confirmed (the batch response is an array
// of length >= 2 where each element carries a data / errors envelope
// AND at least two elements reference the candidate field by data key
// or errors[].path - the proof that the server invoked the resolver
// per batch entry rather than rejecting the whole array globally).
//
// Severity High because batched mutations combine with the alias-
// based bypass for compounding amplification: each HTTP request
// carries N batch entries, each entry carries M alias calls, total
// credential attempts per request = N * M.
func (c GraphQLAudit) probeBatchMutations(ctx context.Context, client *httpclient.Client, target string) (*Finding, error) {
	for _, field := range loginMutationCandidates {
		batch := buildMutationBatch(field, graphqlBatchMutationCount)
		body, status, exch, err := c.postBody(ctx, client, target, batch)
		if err != nil {
			return nil, err
		}
		if !batchMutationsExecuted(body, field) {
			continue
		}
		return &Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      target,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("GraphQL batched mutations accepted (%s)", field),
			Detail: fmt.Sprintf(
				"An HTTP-level batch array of %d %s mutations was processed and returned an array of independent "+
					"per-element responses. Batched mutations bypass any rate limit that counts HTTP requests on state-"+
					"changing operations: one POST equals N credential checks, N account creations, N payment attempts, "+
					"or N of whatever the mutation does. When combined with the alias-based auth-bypass lever the "+
					"amplification compounds (N batch entries * M aliases per entry = N*M attempts per request).",
				graphqlBatchMutationCount, field),
			CWE:   "CWE-770",
			OWASP: "A04:2021 Insecure Design",
			Remediation: "Reject HTTP-level batching for mutation operations. Apollo Server v4: set allowBatchedHttpRequests: " +
				"false to disable batching wholesale, or wrap the gateway with a filter that rejects array-shaped POST bodies " +
				"whose elements include a mutation operation. For servers that legitimately batch queries, gate mutations at " +
				"the resolver layer with a per-resolver rate counter so the limit is independent of the HTTP boundary. Pair " +
				"with graphql-armor's MaxAliasesRule so the alias-amplification path stays closed.",
			Evidence: &Evidence{
				Method:     http.MethodPost,
				RequestURL: target,
				Status:     status,
				Snippet:    snippetJSON(body),
				Exchange:   exch,
			},
			DedupeKey: MakeKey(c.Name(), ScopePage, target, "batch-mutations", field),
		}, nil
	}
	return nil, nil
}

// probeDepth tests whether the server enforces a per-operation
// query-depth limit. The probe builds a nested query through the
// universally-available __schema -> types -> fields -> type ->
// ofType chain, so it works against any schema without prior
// knowledge of application types (the price is that introspection
// must be enabled; when it is not, the server short-circuits the
// query before depth limits get a chance to fire and the probe
// emits no finding rather than a false positive).
//
// Signal: response body contains at least graphqlDepthLevels
// occurrences of "ofType" (the server actually traversed the nested
// chain) AND no error message mentions depth / complexity rejection.
// A server enforcing a depth cap returns an error like "Query
// exceeds maximum depth 5" before the nested chain resolves; that
// message is matched and the probe skips.
//
// Severity Medium because depth abuse is a clear DoS amplifier on
// schemas with self-referential connections (User.friends.friends...)
// but does not by itself bypass authentication or modify data.
func (c GraphQLAudit) probeDepth(ctx context.Context, client *httpclient.Client, target string) (*Finding, error) {
	query := buildDepthQuery(graphqlDepthLevels)
	body, status, exch, err := c.postQuery(ctx, client, target, map[string]any{"query": query})
	if err != nil {
		return nil, err
	}
	if !depthResolved(body, graphqlDepthLevels) {
		return nil, nil
	}
	return &Finding{
		Check:    c.Name(),
		Target:   target,
		URL:      target,
		Severity: SeverityMedium,
		Title:    fmt.Sprintf("GraphQL query-depth limit not enforced (depth %d resolved)", graphqlDepthLevels),
		Detail: fmt.Sprintf(
			"A query nested %d levels deep through the introspection ofType chain resolved without rejection. "+
				"GraphQL has no inherent depth cap; on schemas with self-referential connections (User.friends.friends, "+
				"Post.comments.author.posts, organisation.members.organisation.members...) an attacker can craft a query "+
				"whose resolver count grows geometrically with depth, which is the canonical CPU / database-burn lever. "+
				"Combined with field aliasing the cost compounds: a depth-D query with K aliases at each level invokes "+
				"O(K^D) resolvers from one HTTP request.",
			graphqlDepthLevels),
		CWE:   "CWE-770",
		OWASP: "A04:2021 Insecure Design",
		Remediation: "Configure a maximum query depth at the gateway. graphql-armor's MaxDepthRule and the standalone " +
			"graphql-depth-limit package both expose a hard cap (a typical safe range is 5-10, depending on how deep " +
			"legitimate clients legitimately nest). Pair with a query-complexity scoring rule (graphql-armor's CostLimitRule, " +
			"graphql-cost-analysis) so a shallow query that fans out via aliases or large list arguments is still rejected " +
			"on cost grounds even when its depth is in bounds.",
		Evidence: &Evidence{
			Method:     http.MethodPost,
			RequestURL: target,
			Status:     status,
			Snippet:    snippetJSON(body),
			Exchange:   exch,
		},
		DedupeKey: MakeKey(c.Name(), ScopePage, target, "depth"),
	}, nil
}

// buildAliasAuthQuery returns a mutation that aliases count calls of
// field, each with a garbage credential pair. The { __typename } sub-
// selection makes the query valid regardless of the field's return
// type (login resolvers commonly return a Session / AuthPayload
// object, but a few return a scalar token; __typename satisfies the
// required-sub-selection rule for the object case and is silently
// dropped for the scalar case).
func buildAliasAuthQuery(field string, count int) string {
	var b strings.Builder
	b.WriteString("mutation AuthBypass {")
	for i := 0; i < count; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, ` a%d: %s(email:"probe%d@hyperz.invalid", password:"hyperz-probe") { __typename }`, i, field, i)
	}
	b.WriteString(" }")
	return b.String()
}

// buildMutationBatch returns an array body of count mutation
// operations, each invoking field once with a garbage credential
// pair. The probe distinguishes its credential values across
// elements so a logging operator can correlate each batch entry to
// the originating probe rather than seeing N identical attempts.
func buildMutationBatch(field string, count int) []any {
	batch := make([]any, 0, count)
	for i := 0; i < count; i++ {
		q := fmt.Sprintf(
			`mutation { %s(email:"batch%d@hyperz.invalid", password:"hyperz-probe") { __typename } }`,
			field, i,
		)
		batch = append(batch, map[string]any{"query": q})
	}
	return batch
}

// buildDepthQuery returns an introspection query nested levels deep
// through the well-typed __schema -> types -> fields -> type chain
// terminated by levels chained ofType selections and a final name
// scalar. The shape is universally valid (every GraphQL server's
// introspection schema exposes the wrapper-type ofType chain) so
// the probe needs no prior knowledge of the target's domain types.
func buildDepthQuery(levels int) string {
	var b strings.Builder
	b.WriteString("query DepthProbe { __schema { types { fields { type")
	for i := 0; i < levels; i++ {
		b.WriteString(" { ofType")
	}
	b.WriteString(" { name }")
	for i := 0; i < levels; i++ {
		b.WriteByte(' ')
		b.WriteByte('}')
	}
	b.WriteString(" } } } }")
	return b.String()
}

// perAliasResolveCount returns the number of distinct alias entries
// the server resolved for a query. Used by the alias-based auth-
// bypass probe to distinguish per-alias execution (server processed
// each alias separately - the bypass signal) from a single
// validation error (server rejected the whole operation - no bypass).
//
// Counts data keys first: a successful aliased mutation returns N
// data keys, one per alias. Falls back to counting unique leading
// path segments across errors[] when the calls failed individually
// (e.g. credential-failure errors with path = ["a0"], ["a1"], ...);
// in that case the server still ran the resolver N times and emitted
// N errors at distinct alias roots. A single global validation error
// has an empty or missing path and is not counted, so an absent
// field correctly scores 0.
func perAliasResolveCount(body []byte) int {
	var doc struct {
		Data   map[string]json.RawMessage `json:"data"`
		Errors []struct {
			Path []json.RawMessage `json:"path"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return 0
	}
	if n := len(doc.Data); n > 0 {
		return n
	}
	seen := map[string]struct{}{}
	for _, e := range doc.Errors {
		if len(e.Path) == 0 {
			continue
		}
		seen[string(e.Path[0])] = struct{}{}
	}
	return len(seen)
}

// batchMutationsExecuted returns true when body is a JSON array of
// length >= 2 where every element carries a data / errors envelope
// AND at least two elements reference field by data key or by
// errors[].path. The path / data-key reference is the per-element
// execution signal: a server that processed each batch entry
// independently returns the field name in each entry's response
// envelope. A server that rejected the whole batch globally returns
// the same top-level error per element (no path; no data key for
// field), which fails this check.
func batchMutationsExecuted(body []byte, field string) bool {
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		return false
	}
	if len(arr) < 2 {
		return false
	}
	executed := 0
	for _, elem := range arr {
		_, hasData := elem["data"]
		_, hasErrors := elem["errors"]
		if !hasData && !hasErrors {
			return false
		}
		if elementReferencesField(elem, field) {
			executed++
		}
	}
	return executed >= 2
}

// elementReferencesField returns true when a per-batch response
// element shows evidence the server invoked field for that element,
// rather than rejecting it with a global validation error. The two
// signals: a non-null data object that has field as a key (the
// resolver ran and the server emitted a result key under that
// field's name) and an errors[].path entry whose leading segment is
// field (the resolver ran and threw at field). Both correspond to
// resolver-stage execution; a top-level validation error has empty
// path and no data, and is not a match.
func elementReferencesField(elem map[string]json.RawMessage, field string) bool {
	if raw, ok := elem["data"]; ok {
		if !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			var data map[string]json.RawMessage
			if json.Unmarshal(raw, &data) == nil {
				if _, ok := data[field]; ok {
					return true
				}
			}
		}
	}
	if raw, ok := elem["errors"]; ok {
		var errs []struct {
			Path []json.RawMessage `json:"path"`
		}
		if json.Unmarshal(raw, &errs) == nil {
			quoted, _ := json.Marshal(field)
			for _, e := range errs {
				for _, p := range e.Path {
					if bytes.Equal(p, quoted) {
						return true
					}
				}
			}
		}
	}
	return false
}

// depthResolved returns true when the response carries evidence that
// the server actually traversed the nested ofType chain to the
// requested depth without rejecting on depth / complexity grounds.
//
// First filter: explicit depth / complexity rejection in any error
// message scores as "limit enforced" and the probe emits no finding.
// We also bail on "introspection disabled" so the probe stays silent
// against gateways with introspection off (where depth cannot be
// measured via the introspection chain).
//
// Then: count occurrences of "ofType" in the response. The probe
// query nests requested ofType selections; a server that resolved
// the chain returns at least requested ofType keys in its JSON
// (each level of the response mirrors the requested selection,
// regardless of whether the deepest wrapper resolved to a real type
// or to null). A server that truncated the chain at depth N < requested
// emits at most N ofType keys, and the count threshold rejects.
func depthResolved(body []byte, requested int) bool {
	var doc struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(body, &doc)
	for _, e := range doc.Errors {
		low := strings.ToLower(e.Message)
		if strings.Contains(low, "depth") ||
			strings.Contains(low, "too deep") ||
			strings.Contains(low, "complexity") ||
			strings.Contains(low, "exceeds") ||
			strings.Contains(low, "introspection") {
			return false
		}
	}
	return bytes.Count(bytes.ToLower(body), []byte("oftype")) >= requested
}

// postQuery is the JSON-body POST helper for the standard
// {"query":"..."} envelope. Returns the response body, status, and an
// Exchange snapshot for finding evidence.
func (c GraphQLAudit) postQuery(ctx context.Context, client *httpclient.Client, target string, payload map[string]any) ([]byte, int, *Exchange, error) {
	return c.postBody(ctx, client, target, payload)
}

// postBody serializes payload as JSON and POSTs it to target. Used by
// the standard {"query":"..."} probes and the array-shaped batch probe;
// any JSON-marshalable value works.
func (c GraphQLAudit) postBody(ctx context.Context, client *httpclient.Client, target string, payload any) ([]byte, int, *Exchange, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(raw))
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, graphqlBodyCap)
	if err != nil {
		return nil, 0, nil, err
	}
	return body, resp.StatusCode, RecordExchange(req, raw, false, resp, body, truncated), nil
}

// graphqlShapeMatches returns true when body parses as a JSON object
// with either "data" or "errors" at the top level - the two keys every
// GraphQL response carries. False on non-JSON, non-object, or
// object-without-either-key bodies; that includes 404 HTML pages,
// REST endpoints returning JSON without those keys, and proxy error
// pages.
func graphqlShapeMatches(body []byte) bool {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return false
	}
	_, hasData := doc["data"]
	_, hasErrors := doc["errors"]
	return hasData || hasErrors
}

// introspectionEnabled returns true when body contains an introspection
// response with __schema populated. A nil / empty data.__schema (the
// server returned data: null with an error) does not count - we need
// to see a real schema object to claim introspection is enabled.
func introspectionEnabled(body []byte) bool {
	var doc struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return false
	}
	raw, ok := doc.Data["__schema"]
	if !ok {
		return false
	}
	// __schema must be a non-null object. A null or missing value
	// happens when the server rejects the introspection query but
	// still returns the data envelope; that is the opposite of the
	// signal we want.
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// suggestionsLeaked returns true when body contains a "Did you mean"
// hint in any errors[].message. Matched case-insensitively because
// GraphQL.js emits "Did you mean", Hot Chocolate emits "did you mean",
// and ariadne emits "Did you mean to use".
func suggestionsLeaked(body []byte) bool {
	low := bytes.ToLower(body)
	return bytes.Contains(low, []byte("did you mean"))
}

// batchAccepted returns true when body parses as a JSON array of
// length >= 2 where every element carries a "data" or "errors" key.
// A server that returns a single object (rejecting the array) or an
// HTML 400 page is not batching; both fail the array-shape check.
func batchAccepted(body []byte) bool {
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		return false
	}
	if len(arr) < 2 {
		return false
	}
	for _, elem := range arr {
		_, hasData := elem["data"]
		_, hasErrors := elem["errors"]
		if !hasData && !hasErrors {
			return false
		}
	}
	return true
}

// aliasResponseCount returns the number of distinct alias keys
// returned in the response's data object. Used to verify the alias-
// abuse probe actually resolved every alias rather than being capped
// at one or two by a validation rule.
func aliasResponseCount(body []byte) int {
	var doc struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return 0
	}
	return len(doc.Data)
}

// snippetJSON returns a compact rendering of a JSON body suitable for
// a finding's Snippet. The body is truncated to keep the report
// readable; full bodies live in the Exchange field. Non-JSON input is
// returned verbatim (truncated).
func snippetJSON(body []byte) string {
	const cap = 512
	out := bytes.TrimSpace(body)
	if len(out) > cap {
		out = out[:cap]
	}
	return string(out)
}

