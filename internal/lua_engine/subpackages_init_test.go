package lua_engine_test

// Side-effect imports for the lua_engine test binary. The package's
// own tests run real .lua checks (content-discovery, drupal-changelog,
// wp-xmlrpc, ...) and those checks call into per-family ctx namespaces
// registered by check subpackage init() funcs. Without these blanks
// the test binary never loads the subpackages and a check that calls
// ctx.discovery.X (et al) crashes on a nil namespace.
//
// Lives in the external lua_engine_test package because the in-package
// tests cannot import sibling subpackages that import lua_engine (that
// would close an import cycle at the package level). Putting the
// side-effect imports in the external test package side-steps the
// cycle: go test compiles both internal and external test packages
// into the same binary, so init() runs once and the in-package tests
// see the registered namespaces.

import (
	_ "github.com/londonmax12/hyperz/internal/lua_engine/checks/access"
	_ "github.com/londonmax12/hyperz/internal/lua_engine/checks/concurrency"
	_ "github.com/londonmax12/hyperz/internal/lua_engine/checks/crypto"
	_ "github.com/londonmax12/hyperz/internal/lua_engine/checks/discovery"
	_ "github.com/londonmax12/hyperz/internal/lua_engine/checks/headers"
	_ "github.com/londonmax12/hyperz/internal/lua_engine/checks/platform/oauth"
	_ "github.com/londonmax12/hyperz/internal/lua_engine/checks/platform/openapi"
	_ "github.com/londonmax12/hyperz/internal/lua_engine/checks/platform/sse"
	_ "github.com/londonmax12/hyperz/internal/lua_engine/checks/platform/websocket"
	_ "github.com/londonmax12/hyperz/internal/lua_engine/checks/smuggling"
	_ "github.com/londonmax12/hyperz/internal/lua_engine/checks/xss"
)
