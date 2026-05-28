package lua_engine

import "context"

// This file exposes the subdomain-takeover check's helpers to the Lua
// bridge. Sibling to subdomain_takeover.go: forwards into the package-
// level DNS resolver indirections so the checks_lua parity tests can
// swap in synthetic resolvers without reaching into private state.

// SubdomainTakeoverLookupCNAMEForTest / SetSubdomainTakeoverLookupCNAMEForTest
// expose the package-level CNAME resolver indirection so the
// checks_lua parity tests can swap in a synthetic resolver without
// reaching into private state. The Go-side check_test.go uses the
// private var directly; the Lua-side parity tests live in a different
// package and must use these wrappers.
func SubdomainTakeoverLookupCNAMEForTest() func(ctx context.Context, host string) (string, error) {
	return subdomainTakeoverLookupCNAME
}
func SetSubdomainTakeoverLookupCNAMEForTest(fn func(ctx context.Context, host string) (string, error)) {
	subdomainTakeoverLookupCNAME = fn
}

// SubdomainTakeoverLookupHostForTest / SetSubdomainTakeoverLookupHostForTest
// expose the package-level host-resolver indirection for the same
// reason as the CNAME pair above.
func SubdomainTakeoverLookupHostForTest() func(ctx context.Context, host string) ([]string, error) {
	return subdomainTakeoverLookupHost
}
func SetSubdomainTakeoverLookupHostForTest(fn func(ctx context.Context, host string) ([]string, error)) {
	subdomainTakeoverLookupHost = fn
}
