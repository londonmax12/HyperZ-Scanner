package lua_engine

import (
	"net/url"

	"github.com/londonmax12/hyperz/internal/scope"
)

// allows reports whether sc permits probing u. A nil scope is
// permissive so callers in tests that build a Page without a scope
// boundary keep working; production scans always thread a real
// *scope.Scope through, so the nil branch is a developer-ergonomics
// concession rather than a security gap.
func allows(sc *scope.Scope, u *url.URL) bool {
	if sc == nil {
		return true
	}
	return sc.Allows(u)
}
