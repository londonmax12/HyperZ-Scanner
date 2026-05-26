package lua_engine

// ServerLeak flags response headers that reveal server software or runtime
// version (Server, X-Powered-By). The information itself isn't a vulnerability
// but it narrows an attacker's search space; pairing "nginx/1.18.0" with a
// public CVE list is a one-step lookup. Severity stays Info to reflect that.
type ServerLeak struct{}

// serverLeakHeaders is the closed set of headers we report. Both fall under
// CWE-200 (Exposure of Sensitive Information) and OWASP A05:2021.
var serverLeakHeaders = []string{"Server", "X-Powered-By"}
