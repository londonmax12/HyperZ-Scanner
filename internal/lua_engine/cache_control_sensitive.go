package lua_engine

// CacheControlSensitive detects HTML responses that may contain sensitive
// information but lack cache directives (private, no-store, no-cache) that
// prevent storage in shared caches or browser history. Uncontrolled caching
// of authenticated pages, forms, or API responses can leak data to other users,
// proxy operators, or attackers with local access to the browser cache.
type CacheControlSensitive struct{}
