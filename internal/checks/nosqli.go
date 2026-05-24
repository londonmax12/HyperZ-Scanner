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

// NoSQLi probes for NoSQL (MongoDB / Mongoose-shaped) operator injection
// against parameters whose values may be deserialized into query operators
// by the backend framework. Two detection paths run per probable sink:
//
//  1. Operator injection (boolean): each sink is rewritten so the param
//     name carries a bracketed Mongo operator suffix (`name[$eq]`,
//     `name[$in][0]`) - the form an Express + qs / body-parser stack
//     expands into a nested operator object. The value oscillates between
//     the sink's original (truthy) and a fresh canary (falsy). When the
//     backend parses the bracket notation, the truthy probe is the same
//     logical query as baseline and the falsy probe matches nothing - the
//     canonical truthy~baseline / falsy!=baseline shape BooleanCompare
//     flags as BoolVulnerable. Severity High.
//
//  2. Error-based: the param value (no name rewrite) is replaced with
//     payloads engineered to break Mongo / Mongoose driver parsing - a
//     `$where`-shaped JavaScript break, a literal operator-object string
//     a cast or operator validator will reject. A driver-error signature
//     not already in the baseline body fires the finding. Severity High.
//
// Probable sinks (sinkProbable): query params, form fields, and JSON body
// fields. Header / cookie / path values aren't auto-deserialized into
// query operators by any common framework, so the bracket trick has no
// surface there and probing them would just waste requests.
//
// This is an active (LevelDefault) check.
type NoSQLi struct{}

func (NoSQLi) Name() string { return "nosqli" }

func (NoSQLi) Level() Level { return LevelDefault }

// nosqliBodyCap matches the SQLi-boolean cap because the boolean phase
// uses BooleanCompare's similarity scoring - a too-small sample of a
// large templated page wouldn't capture the row-set divergence we're
// after. The error phase shares the same buffer; driver errors are
// short and ride comfortably inside it.
const nosqliBodyCap = 64 << 10

// nosqliOp is one Mongo operator the boolean phase exercises by
// rewriting the param name with a bracket suffix. KeySuffix is what
// appears after the param name on the URL / form wire (`[$eq]`,
// `[$in][0]`). JSONValue produces the equivalent nested object for
// LocJSON sinks where bracket notation has no equivalent shape on the
// wire - the JSON body carries `{name: <JSONValue(v)>}` instead.
type nosqliOp struct {
	Name      string
	KeySuffix string
	JSONValue func(string) any
}

// nosqliBooleanOps is the curated operator set for the boolean phase.
// Both operators preserve "truthy == baseline" semantics: $eq is the
// explicit form of equality, $in with a single-element array is the
// set form. Mongo treats {$eq: v} and {$in: [v]} as equivalent to the
// literal value v, so a vulnerable backend renders truthy ~ baseline
// for either pair.
var nosqliBooleanOps = []nosqliOp{
	{
		Name:      "eq",
		KeySuffix: "[$eq]",
		JSONValue: func(v string) any { return map[string]any{"$eq": v} },
	},
	{
		Name:      "in-array",
		KeySuffix: "[$in][0]",
		JSONValue: func(v string) any { return map[string]any{"$in": []string{v}} },
	},
}

// nosqliErrorPayloads are wire VALUES (not name suffixes) that often
// provoke MongoDB / Mongoose driver errors when the param flows into a
// NoSQL query. They cover the parser paths that fail loudest: a JS
// string break for code paths that embed user input in `$where`, and
// literal operator-object strings that confuse Mongoose's cast layer
// when the schema expected a primitive. Each one is appended to
// sink.Value so numeric / string contexts both still surface the
// payload to the parser.
var nosqliErrorPayloads = []string{
	`';return 1;//`,
	`';return(true);//`,
	`' || '1'=='1`,
	`{"$gt": ""}`,
	`{"$ne": null}`,
}

// mongoErrorPatterns are lowercase substrings of NoSQL driver-error
// signatures across the major runtimes. Caller lowercases body before
// matching. Curated to cover the dominant Mongo stacks (mongoose,
// native Node driver, pymongo, motor) without overlapping into generic
// English - "validation failed", for example, is too noisy to include.
var mongoErrorPatterns = []string{
	"mongoerror",
	"mongoservererror",
	"mongoose.error",
	"mongooseerror",
	"mongo.errors",
	"pymongo.errors",
	"bson.errors",
	"cast to objectid failed",
	"cast to number failed",
	"cast to string failed",
	"casterror",
	"e11000 duplicate key",
	"unknown top level operator",
	"unknown operator",
	"unknown modifier",
	"$where is not a function",
	"$regex must be a string",
	"syntaxerror: missing ;",
	"syntaxerror: unexpected",
	"exception: parse error",
}

func (c NoSQLi) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
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

// sinkProbable reports whether a sink Loc carries operator-parsing risk.
// Only query / form / JSON body inputs get auto-deserialized by common
// frameworks; header / cookie / path values are taken as strings and
// never reach a query parser.
func (NoSQLi) sinkProbable(s Sink) bool {
	switch s.Loc {
	case LocQuery, LocForm, LocJSON:
		return true
	}
	return false
}

// probe runs the baseline + boolean + error-based sweep for one sink.
// The baseline doubles for both phases: BooleanCompare uses it as the
// truthy/falsy comparison anchor, and the error phase subtracts any
// Mongo-error signatures already present so a docs page mentioning
// "MongoError" doesn't fire on the benign value.
func (c NoSQLi) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	_, baseResp, baseBody, _, err := c.sendValue(ctx, client, sink, sink.Value)
	if err != nil {
		return nil, err
	}
	baselineErrors := matchMongoErrors(baseBody)

	// Pre-strip the sink's original value from the baseline body. The
	// truthy probe also carries sink.Value, so leaving the value's echo in
	// place would inflate baseline~truthy similarity on echo-only pages
	// while artificially deflating baseline~falsy (where the canary takes
	// the value's slot). Stripping it from every variant uniformly leaves
	// the comparison turning on what the backend DID with the input, not
	// on which literal it echoed back.
	valueBytes := []byte(sink.Value)
	basePrep := baseBody
	if len(valueBytes) > 0 {
		basePrep = bytes.ReplaceAll(baseBody, valueBytes, nil)
	}
	baseSnap := Snapshot{Status: statusOf(baseResp), Body: basePrep}

	for _, op := range nosqliBooleanOps {
		if ctx.Err() != nil {
			break
		}
		canary := NewCanary()

		_, tResp, tBody, _, err := c.sendOperator(ctx, client, sink, op, sink.Value)
		if err != nil {
			Report(ctx, fmt.Errorf("nosqli truthy %s %s=%s op=%s: %w",
				sink.Loc, sink.Name, sink.URL, op.Name, err))
			continue
		}
		fReq, fResp, fBody, fTruncated, err := c.sendOperator(ctx, client, sink, op, canary)
		if err != nil {
			Report(ctx, fmt.Errorf("nosqli falsy %s %s=%s op=%s: %w",
				sink.Loc, sink.Name, sink.URL, op.Name, err))
			continue
		}

		// Mirror the baseline strip on truthy/falsy: remove the value
		// echo from both, plus the per-pair canary from falsy. After
		// stripping, what's left is the structural skeleton the backend
		// produced - if the only divergence between truthy and falsy is
		// the value echo (echo-only page, no DB), all three bodies look
		// identical and BoolNoSignal suppresses the false positive.
		tStripped := tBody
		fStripped := fBody
		if len(valueBytes) > 0 {
			tStripped = bytes.ReplaceAll(tBody, valueBytes, nil)
			fStripped = bytes.ReplaceAll(fBody, valueBytes, nil)
		}
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
			Title:    fmt.Sprintf("NoSQL injection (operator injection) in %s parameter %q", sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) is deserialized into a MongoDB-style query operator: pair nosqli/%s "+
					"produced truthy~baseline (sim=%.3f, status=%d) and falsy!=baseline (sim=%.3f, status=%d). "+
					"%s. An attacker can bypass authentication checks, enumerate records, or extract data "+
					"by sending operator objects in place of literal values.",
				sink.Name, sink.Loc, op.Name,
				result.TruthySim, statusOf(tResp), result.FalsySim, statusOf(fResp), result.Detail),
			CWE:   "CWE-943",
			OWASP: "A03:2021 Injection",
			Remediation: "Treat client-supplied values as strings, not as structured query fragments. Reject inputs " +
				"whose type does not match the schema - a username field that arrives as an object should fail " +
				"validation before reaching the database driver. In Express/Node, sanitize keys starting with `$` " +
				"(e.g. via express-mongo-sanitize) or disable bracket-object expansion in the body parser / qs.",
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

	for _, payload := range nosqliErrorPayloads {
		if ctx.Err() != nil {
			break
		}
		wire := sink.Value + payload
		req, resp, body, truncated, err := c.sendValue(ctx, client, sink, wire)
		if err != nil {
			// Match the boolean phase: a single payload's transport failure
			// shouldn't suppress every payload that follows. Log it and keep
			// trying so one network blip doesn't mask a vulnerability the
			// next payload would have surfaced.
			Report(ctx, fmt.Errorf("nosqli error-based %s %s=%s payload=%q: %w",
				sink.Loc, sink.Name, sink.URL, payload, err))
			continue
		}
		hits := matchMongoErrors(body)
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
			Title:    fmt.Sprintf("NoSQL injection (error-based) in %s parameter %q", sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) appears to flow into a NoSQL query: payload %q provoked driver error "+
					"signature %q. An attacker can probably extract data or bypass logic by sending operator "+
					"objects in place of literal values.",
				sink.Name, sink.Loc, payload, newHits[0]),
			CWE:   "CWE-943",
			OWASP: "A03:2021 Injection",
			Remediation: "Treat client-supplied values as strings, not structured query fragments. Validate input type " +
				"against the schema and disable bracket-object expansion in your body parser. Avoid `$where` JavaScript " +
				"evaluation in MongoDB queries entirely - it cannot be safely combined with user input.",
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

// sendValue dispatches sink with wireValue substituted into sink.Name
// via the standard MutateRequest path. Used by both baseline and the
// error-based phase - neither rewrites the param name, only the value.
func (c NoSQLi) sendValue(ctx context.Context, client *httpclient.Client, sink Sink, wireValue string) (*http.Request, *http.Response, []byte, bool, error) {
	req, err := sink.MutateRequest(ctx, wireValue)
	if err != nil {
		return nil, nil, nil, false, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, nil, false, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, nosqliBodyCap)
	if err != nil {
		return req, resp, nil, false, err
	}
	return req, resp, body, truncated, nil
}

// sendOperator dispatches sink with op-injected name structure carrying
// opValue. The wire shape depends on Loc: bracket-suffixed key for
// query/form, nested object value for JSON.
func (c NoSQLi) sendOperator(ctx context.Context, client *httpclient.Client, sink Sink, op nosqliOp, opValue string) (*http.Request, *http.Response, []byte, bool, error) {
	req, err := c.buildOperatorRequest(ctx, sink, op, opValue)
	if err != nil {
		return nil, nil, nil, false, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, nil, false, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, nosqliBodyCap)
	if err != nil {
		return req, resp, nil, false, err
	}
	return req, resp, body, truncated, nil
}

// buildOperatorRequest rewrites sink with op-injected param structure.
// For LocQuery / LocForm this swaps the literal name for the bracket-
// suffixed form so a qs-style parser deserializes it into an operator
// object on the backend. For LocJSON it nests op.JSONValue(opValue)
// inside the JSON body's field value directly - bracket notation has
// no analogue on the JSON wire, but the structural shape is identical.
func (c NoSQLi) buildOperatorRequest(ctx context.Context, sink Sink, op nosqliOp, opValue string) (*http.Request, error) {
	method := strings.ToUpper(sink.Method)
	if method == "" {
		method = http.MethodGet
	}
	bracketed := sink.Name + op.KeySuffix
	switch sink.Loc {
	case LocQuery:
		u, err := url.Parse(sink.URL)
		if err != nil {
			return nil, fmt.Errorf("parse url %q: %w", sink.URL, err)
		}
		q := u.Query()
		q.Del(sink.Name)
		q.Set(bracketed, opValue)
		u.RawQuery = q.Encode()
		return http.NewRequestWithContext(ctx, method, u.String(), nil)
	case LocForm:
		body := url.Values{}
		body.Set(bracketed, opValue)
		req, err := http.NewRequestWithContext(ctx, method, sink.URL, strings.NewReader(body.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	case LocJSON:
		body := map[string]any{sink.Name: op.JSONValue(opValue)}
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal json body: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, method, sink.URL, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	default:
		return nil, fmt.Errorf("nosqli: unsupported sink loc %q", sink.Loc)
	}
}

// matchMongoErrors returns every mongoErrorPatterns entry that appears
// in body. Body is lowercased once per call so substring scans are
// case-insensitive without per-pattern allocations.
func matchMongoErrors(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	var hits []string
	for _, pat := range mongoErrorPatterns {
		if bytes.Contains(lower, []byte(pat)) {
			hits = append(hits, pat)
		}
	}
	return hits
}
