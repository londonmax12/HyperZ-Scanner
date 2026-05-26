package lua_engine

import (
	"net/http"
	"net/url"

	"github.com/londonmax12/hyperz/internal/scope"
)

// statusOf returns resp.StatusCode or 0 when resp is nil. Centralized
// so active-check helpers can build Snapshot / Evidence values without
// each open-coding the nil guard at every call site. Lives in this
// package because the helpers ported out of internal/checks call it
// bare; internal/core keeps its own copy for the same reason.
func statusOf(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

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
