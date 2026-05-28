package lua_engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

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

// nosqliSinkProbable reports whether a sink Loc carries operator-parsing risk.
// Only query / form / JSON body inputs get auto-deserialized by common
// frameworks; header / cookie / path values are taken as strings and
// never reach a query parser.
func nosqliSinkProbable(s Sink) bool {
	switch s.Loc {
	case LocQuery, LocForm, LocJSON:
		return true
	}
	return false
}

// nosqliBuildOperatorRequest rewrites sink with op-injected param structure.
// For LocQuery / LocForm this swaps the literal name for the bracket-
// suffixed form so a qs-style parser deserializes it into an operator
// object on the backend. For LocJSON it nests op.JSONValue(opValue)
// inside the JSON body's field value directly - bracket notation has
// no analogue on the JSON wire, but the structural shape is identical.
func nosqliBuildOperatorRequest(ctx context.Context, sink Sink, op nosqliOp, opValue string) (*http.Request, error) {
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
