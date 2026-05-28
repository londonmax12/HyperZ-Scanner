package lua_engine

import (
	"context"
	"fmt"
	"net/http"
)

// This file exposes the nosqli check's helpers to the Lua bridge.
// Sibling to nosqli.go: forwards into the package-private pattern /
// operator / payload sets so the Lua port consumes the same catalogue
// the Go check sweeps.

// MongoErrorNewMatches exposes the NoSQLi check's private pattern set
// against the Lua port's baseline + payload-stage subtraction.
func MongoErrorNewMatches(body, baseline []byte) []string {
	return SubtractPatterns(matchMongoErrors(body), matchMongoErrors(baseline))
}

// NoSQLiBooleanOperator carries one MongoDB operator the Lua port
// iterates. KeySuffix is the wire form for query / form sinks
// ("[$eq]", "[$in][0]"); the JSON-body variant is built by the Lua
// bridge's nosqli_build_operator_request helper (which dispatches on
// op_name to apply the right nested-object shape).
type NoSQLiBooleanOperator struct {
	Name      string
	KeySuffix string
}

func NoSQLiBooleanOpsLua() []NoSQLiBooleanOperator {
	out := make([]NoSQLiBooleanOperator, 0, len(nosqliBooleanOps))
	for _, op := range nosqliBooleanOps {
		out = append(out, NoSQLiBooleanOperator{Name: op.Name, KeySuffix: op.KeySuffix})
	}
	return out
}

func NoSQLiErrorPayloadsLua() []string {
	out := make([]string, len(nosqliErrorPayloads))
	copy(out, nosqliErrorPayloads)
	return out
}

// NoSQLiSinkProbable forwards nosqliSinkProbable so the Lua port
// gates on the same Loc set the Go check accepts (query / form / json).
func NoSQLiSinkProbable(loc string) bool { return nosqliSinkProbable(Sink{Loc: Loc(loc)}) }

// NoSQLiBuildOperatorRequest builds an *http.Request that applies the
// named operator (op_name = "eq" / "in-array") to sink with opValue.
// Wraps the package-private buildOperatorRequest so the Lua port can
// produce the wire-shape rewrites (bracket key for query / form,
// nested JSON for body) without re-implementing the per-loc shape rules.
func NoSQLiBuildOperatorRequest(ctx context.Context, sink Sink, opName, opValue string) (*http.Request, error) {
	var op *nosqliOp
	for i := range nosqliBooleanOps {
		if nosqliBooleanOps[i].Name == opName {
			op = &nosqliBooleanOps[i]
			break
		}
	}
	if op == nil {
		return nil, fmt.Errorf("nosqli: unknown operator %q", opName)
	}
	return nosqliBuildOperatorRequest(ctx, sink, *op, opValue)
}
