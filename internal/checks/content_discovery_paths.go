package checks

// discoveryEntry is one curated path the ContentDiscovery sweep probes.
//
// Path is the absolute URL path (with leading slash) joined to the
// target's scheme://host. Severity is the worst-case impact assuming
// the resource is exposed verbatim; classifyDiscovery returns it
// unchanged on hits. Title / Detail / CWE / OWASP / Remediation ride
// straight into Finding.
//
// Marker is the optional confirmation needle: when set, classifyDiscovery
// requires the response body to contain this substring before firing on
// a 2xx response. Use it for entries where a soft-404 catch-all would
// otherwise produce noise (the body of "/.git/HEAD" is short and
// distinctive; the body of "/admin/" is not). Leave it empty for paths
// where any non-baseline response is itself the finding (admin consoles,
// info-class artifacts).
//
// ExpectedContentTypes, when set on a markerless entry, narrows the
// 200-distinct verdict to responses whose Content-Type family is in the
// list. Use it for paths whose extension implies a non-HTML body
// (.zip, .sql, .tar.gz) so a soft-200 HTML wrapper that slipped past
// the baseline shape filter doesn't manufacture a false positive.
// Include "application/octet-stream" - the generic binary fallback
// most servers reach for when they don't know the type.
//
// Aggressive marks entries that only probe at LevelAggressive. The
// default tier ships the high-confidence, high-impact entries (VCS
// metadata, environment files, debug endpoints, database dumps); the
// aggressive tier adds admin consoles, dev artifacts, and informational
// endpoints that would otherwise inflate per-host probe count without
// proportional signal.
type discoveryEntry struct {
	Path                 string
	Severity             Severity
	Title                string
	Detail               string
	CWE                  string
	OWASP                string
	Remediation          string
	Marker               string
	ExpectedContentTypes []string
	Aggressive           bool
}

// contentDiscoveryEntries is the curated probe catalog. New entries
// should justify their probe cost: every addition is one more request
// per scanned host, and false-positive defense relies on each path
// being either marker-confirmable or shape-distinct enough that the
// soft-404 baseline does the filtering. Generic admin paths without a
// marker belong on the aggressive tier.
var contentDiscoveryEntries = []discoveryEntry{

	// -- Version control metadata -----------------------------------

	{
		Path:        "/.git/HEAD",
		Severity:    SeverityCritical,
		Title:       "exposed Git repository (.git/HEAD)",
		Detail:      "The .git directory is web-accessible; an attacker can reconstruct the full source tree and history via incremental object fetches.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Block /.git/ at the web server or CDN layer, and deploy from a build artifact that omits the .git directory entirely.",
		Marker:      "ref: refs/heads/",
	},
	{
		Path:        "/.git/config",
		Severity:    SeverityCritical,
		Title:       "exposed Git config (.git/config)",
		Detail:      "The Git repository config file is reachable - typically exposes remote URLs and sometimes embeds credentials in them.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Block /.git/ at the web server or CDN layer.",
		Marker:      "[core]",
	},
	{
		Path:        "/.svn/entries",
		Severity:    SeverityHigh,
		Title:       "exposed Subversion metadata (.svn/entries)",
		Detail:      "The .svn directory is web-accessible, leaking repository structure and prior revision content.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Block /.svn/ at the web server layer; prefer build artifacts that exclude VCS metadata.",
	},
	{
		Path:        "/.hg/store/00manifest.i",
		Severity:    SeverityHigh,
		Title:       "exposed Mercurial metadata (.hg/)",
		Detail:      "The .hg directory is web-accessible.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Block /.hg/ at the web server layer.",
		Aggressive:  true,
	},
	{
		Path:        "/.bzr/branch-format",
		Severity:    SeverityHigh,
		Title:       "exposed Bazaar metadata (.bzr/)",
		Detail:      "The .bzr directory is web-accessible.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Block /.bzr/ at the web server layer.",
		Aggressive:  true,
	},
	{
		Path:        "/.gitignore",
		Severity:    SeverityLow,
		Title:       ".gitignore reachable",
		Detail:      "Reveals file and directory naming conventions; sometimes lists ignored secrets that exist on disk.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Serve only the directories you intend to publish.",
		Aggressive:  true,
	},

	// -- Environment / secret files ---------------------------------

	{
		Path:        "/.env",
		Severity:    SeverityCritical,
		Title:       "exposed environment file (.env)",
		Detail:      "Typically contains database URLs, API keys, and signing secrets loaded by the application at startup.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Store secrets outside the document root and inject them via process environment, not on-disk files. Block /.env at the web server layer as defense in depth.",
		Marker:      "=",
	},
	{
		Path:        "/.env.local",
		Severity:    SeverityCritical,
		Title:       "exposed environment file (.env.local)",
		Detail:      "Local-overlay .env files commonly hold developer or staging credentials that were not meant to ship.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Store secrets outside the document root; block /.env* at the web server layer.",
		Marker:      "=",
	},
	{
		Path:        "/.env.production",
		Severity:    SeverityCritical,
		Title:       "exposed environment file (.env.production)",
		Detail:      "Production .env files hold the live secrets the application needs to operate.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Store secrets outside the document root; block /.env* at the web server layer.",
		Marker:      "=",
	},
	{
		Path:        "/web.config",
		Severity:    SeverityHigh,
		Title:       "exposed IIS web.config",
		Detail:      "web.config carries app pool, routing, and sometimes connection-string configuration.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "IIS should refuse to serve *.config under the document root; verify the staticContent and requestFiltering rules.",
		Marker:      "<configuration",
	},
	{
		Path:        "/appsettings.json",
		Severity:    SeverityHigh,
		Title:       "exposed ASP.NET appsettings.json",
		Detail:      "ASP.NET Core's primary configuration file commonly carries connection strings, JWT signing keys, and third-party API credentials in plaintext.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Move secrets to environment variables, Azure Key Vault, or a user-secrets store; block *.json files under the wwwroot at the IIS or Kestrel layer.",
		Marker:      "ConnectionStrings",
	},
	{
		Path:        "/application.properties",
		Severity:    SeverityHigh,
		Title:       "exposed Spring application.properties",
		Detail:      "Spring's primary configuration file routinely embeds datasource URLs, broker credentials, and OAuth client secrets.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Move secrets out of application.properties (use environment overrides or Spring Cloud Config) and exclude properties files from the served document root.",
		ExpectedContentTypes: []string{"text/plain", "application/octet-stream"},
	},
	{
		Path:        "/id_rsa",
		Severity:    SeverityCritical,
		Title:       "exposed SSH private key (id_rsa)",
		Detail:      "An RSA private key is reachable at the document root - whoever owns this key has SSH access wherever the matching public key is authorized.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Remove the key from the document root and rotate it immediately; any deployment that needs an SSH key should mount it from outside the served tree.",
		Marker:      "PRIVATE KEY",
	},
	{
		Path:        "/wp-config.php",
		Severity:    SeverityHigh,
		Title:       "WordPress wp-config.php reachable",
		Detail:      "If PHP serves the raw file instead of executing it, this discloses DB credentials and authentication salts.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Verify PHP files are executed rather than served; restrict access to wp-config.php at the web server layer as defense in depth.",
		Marker:      "DB_PASSWORD",
		Aggressive:  true,
	},
	{
		Path:        "/.htpasswd",
		Severity:    SeverityHigh,
		Title:       ".htpasswd reachable",
		Detail:      "Apache's password file is served directly - exposes usernames and bcrypt/md5 hashes ready for offline cracking.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Move .htpasswd outside the document root and add a Files directive that denies access to dotfiles as defense in depth.",
		Aggressive:  true,
	},
	{
		Path:        "/.npmrc",
		Severity:    SeverityHigh,
		Title:       ".npmrc reachable",
		Detail:      "An npm runtime config that, when committed alongside the deploy artifact, typically embeds the publisher's npm auth token (_authToken=...).",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude .npmrc from the document root and rotate any auth tokens present in the disclosed file.",
		Aggressive:  true,
	},
	{
		Path:        "/private.key",
		Severity:    SeverityCritical,
		Title:       "exposed private key (private.key)",
		Detail:      "A private key file is reachable at the document root - whichever certificate it pairs with should be considered compromised.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Remove the key from the document root and rotate it; private keys must never be served by the same process that serves public content.",
		Marker:      "PRIVATE KEY",
		Aggressive:  true,
	},
	{
		Path:        "/server.key",
		Severity:    SeverityCritical,
		Title:       "exposed TLS server key (server.key)",
		Detail:      "The server's TLS private key is reachable; an attacker can decrypt past captures (when no PFS) and impersonate the host.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Remove the key from the document root, rotate the TLS keypair, and reissue the certificate.",
		Marker:      "PRIVATE KEY",
		Aggressive:  true,
	},
	{
		Path:        "/id_dsa",
		Severity:    SeverityCritical,
		Title:       "exposed SSH private key (id_dsa)",
		Detail:      "A DSA private key is reachable at the document root.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Remove the key from the document root and rotate it immediately.",
		Marker:      "PRIVATE KEY",
		Aggressive:  true,
	},
	{
		Path:        "/.htaccess",
		Severity:    SeverityLow,
		Title:       ".htaccess reachable",
		Detail:      "Apache rewrite and access rules are visible, often revealing internal routing and protected paths.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Add a Files directive that denies access to dotfiles at the server config level.",
		Aggressive:  true,
	},
	{
		Path:        "/application.yml",
		Severity:    SeverityHigh,
		Title:       "exposed Spring application.yml",
		Detail:      "Spring's YAML configuration file commonly embeds datasource URLs and credentials.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Move secrets out of application.yml and exclude YAML files from the served document root.",
		ExpectedContentTypes: []string{"text/yaml", "application/yaml", "text/plain", "application/x-yaml", "application/octet-stream"},
		Aggressive:           true,
	},

	// -- Framework debug / introspection endpoints ------------------

	{
		Path:        "/actuator/env",
		Severity:    SeverityHigh,
		Title:       "Spring Boot actuator env endpoint reachable",
		Detail:      "/actuator/env discloses every configuration property loaded into the JVM, including credentials and tokens.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Set management.endpoints.web.exposure.exclude=env (or *) and gate actuator behind authentication on a separate management port.",
		Marker:      "propertySources",
	},
	{
		Path:        "/actuator/heapdump",
		Severity:    SeverityCritical,
		Title:       "Spring Boot actuator heapdump endpoint reachable",
		Detail:      "/actuator/heapdump returns a full JVM heap dump containing in-memory secrets, tokens, and session data.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude heapdump from exposed actuators; gate actuator endpoints behind authentication.",
		ExpectedContentTypes: []string{"application/octet-stream", "application/vnd.spring-boot.actuator.v3+json"},
	},
	{
		Path:        "/actuator",
		Severity:    SeverityMedium,
		Title:       "Spring Boot actuator index reachable",
		Detail:      "The actuator index lists every exposed management endpoint, telling an attacker exactly what to probe next.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Restrict actuator exposure with management.endpoints.web.exposure.include and gate it behind authentication.",
		Marker:      "_links",
	},
	{
		Path:        "/debug/pprof/",
		Severity:    SeverityHigh,
		Title:       "Go pprof debug endpoint reachable",
		Detail:      "/debug/pprof exposes runtime profiling data and, via /debug/pprof/heap, the in-memory contents of the Go process.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Do not register net/http/pprof handlers on the public mux; serve them on a separate, firewalled debug listener.",
		Marker:      "Types of profiles available",
	},
	{
		Path:        "/server-status",
		Severity:    SeverityMedium,
		Title:       "Apache mod_status reachable",
		Detail:      "/server-status discloses live request URLs, client IPs, and worker state.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Restrict /server-status to local or admin IPs in the Apache config, or disable mod_status entirely.",
		Marker:      "Apache Server Status",
	},
	{
		Path:        "/server-info",
		Severity:    SeverityMedium,
		Title:       "Apache mod_info reachable",
		Detail:      "/server-info discloses module configuration and loaded module paths.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Restrict /server-info to local or admin IPs, or disable mod_info.",
		Marker:      "Apache Server Information",
		Aggressive:  true,
	},
	{
		Path:        "/phpinfo.php",
		Severity:    SeverityHigh,
		Title:       "phpinfo() output reachable (/phpinfo.php)",
		Detail:      "phpinfo() reveals the PHP version, loaded modules, environment variables, and absolute filesystem paths.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Remove phpinfo.php from the document root.",
		Marker:      "PHP Version",
	},
	{
		Path:        "/info.php",
		Severity:    SeverityHigh,
		Title:       "phpinfo() output reachable (/info.php)",
		Detail:      "phpinfo() reveals the PHP version, loaded modules, environment variables, and absolute filesystem paths.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Remove info.php from the document root.",
		Marker:      "PHP Version",
		Aggressive:  true,
	},
	{
		Path:        "/test.php",
		Severity:    SeverityMedium,
		Title:       "test.php reachable",
		Detail:      "Generic test scripts commonly contain phpinfo() output or ad-hoc debug routines that disclose runtime state.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Remove test scripts from the document root.",
		Aggressive:  true,
	},
	{
		Path:        "/graphql",
		Severity:    SeverityMedium,
		Title:       "GraphQL endpoint reachable",
		Detail:      "A GraphQL endpoint is exposed; when introspection is on, an attacker can map the entire schema and walk every resolver from there.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Disable introspection in production (e.g. NoSchemaIntrospectionCustomRule for graphql-js, Spring's GraphQlSourceBuilder.configure schemaResources etc.) and gate the endpoint behind authentication where possible.",
		Marker:      "GraphiQL",
		Aggressive:  true,
	},
	{
		Path:        "/swagger.json",
		Severity:    SeverityLow,
		Title:       "OpenAPI / Swagger spec reachable (/swagger.json)",
		Detail:      "The full API contract is exposed; an attacker pulls the schema and uses it as a roadmap for every undocumented endpoint and parameter.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Restrict swagger / OpenAPI docs to authenticated internal users in production, or strip them from the deploy artifact entirely.",
		Marker:      "\"swagger\"",
		Aggressive:  true,
	},
	{
		Path:        "/openapi.json",
		Severity:    SeverityLow,
		Title:       "OpenAPI spec reachable (/openapi.json)",
		Detail:      "The OpenAPI 3 spec is exposed; an attacker uses it as a roadmap to every endpoint and parameter the service exposes.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Restrict OpenAPI docs to authenticated internal users in production.",
		Marker:      "\"openapi\"",
		Aggressive:  true,
	},
	{
		Path:        "/v2/api-docs",
		Severity:    SeverityLow,
		Title:       "Springfox / Swagger v2 docs reachable (/v2/api-docs)",
		Detail:      "Springfox's classic API doc endpoint is reachable.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Disable springfox in production profiles or gate the endpoint behind authentication.",
		Marker:      "\"swagger\"",
		Aggressive:  true,
	},

	// -- Backup / dump files ----------------------------------------

	{
		Path:        "/backup.sql",
		Severity:    SeverityCritical,
		Title:       "database dump reachable (backup.sql)",
		Detail:      "A raw SQL dump exposes the entire database schema and contents, including credential hashes and PII.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Store database dumps outside the document root and rotate any credentials present in the dump.",
		ExpectedContentTypes: []string{"text/plain", "application/sql", "application/octet-stream", "application/x-sql"},
	},
	{
		Path:        "/database.sql",
		Severity:    SeverityCritical,
		Title:       "database dump reachable (database.sql)",
		Detail:      "A raw SQL dump exposes the entire database schema and contents.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Store database dumps outside the document root and rotate any credentials present in the dump.",
		ExpectedContentTypes: []string{"text/plain", "application/sql", "application/octet-stream", "application/x-sql"},
	},
	{
		Path:        "/dump.sql",
		Severity:    SeverityCritical,
		Title:       "database dump reachable (dump.sql)",
		Detail:      "A raw SQL dump exposes the entire database schema and contents.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Store database dumps outside the document root and rotate any credentials present in the dump.",
		ExpectedContentTypes: []string{"text/plain", "application/sql", "application/octet-stream", "application/x-sql"},
		Aggressive:           true,
	},
	{
		Path:        "/backup.zip",
		Severity:    SeverityHigh,
		Title:       "backup archive reachable (backup.zip)",
		Detail:      "Compressed site backups typically contain source code and configuration including secrets.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Store backups outside the document root.",
		ExpectedContentTypes: []string{"application/zip", "application/x-zip-compressed", "application/octet-stream"},
	},
	{
		Path:        "/backup.tar.gz",
		Severity:    SeverityHigh,
		Title:       "backup archive reachable (backup.tar.gz)",
		Detail:      "Compressed site backups typically contain source code and configuration including secrets.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Store backups outside the document root.",
		ExpectedContentTypes: []string{"application/gzip", "application/x-gzip", "application/x-tar", "application/octet-stream"},
		Aggressive:           true,
	},
	{
		Path:        "/site.tar.gz",
		Severity:    SeverityHigh,
		Title:       "site backup reachable (site.tar.gz)",
		Detail:      "Compressed site backups typically contain source code and configuration including secrets.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Store backups outside the document root.",
		ExpectedContentTypes: []string{"application/gzip", "application/x-gzip", "application/x-tar", "application/octet-stream"},
		Aggressive:           true,
	},

	// -- Admin / management consoles --------------------------------

	{
		Path:        "/admin/",
		Severity:    SeverityLow,
		Title:       "/admin/ reachable",
		Detail:      "An administrative interface is exposed. Confirm it is intended to be public-facing and that strong authentication and brute-force protections are in place.",
		CWE:         "CWE-284",
		OWASP:       "A01:2021 Broken Access Control",
		Remediation: "Restrict admin endpoints to trusted network ranges (VPN or SSO bastion) where possible, and enforce MFA on the underlying accounts.",
		Aggressive:  true,
	},
	{
		Path:        "/administrator/",
		Severity:    SeverityLow,
		Title:       "Joomla /administrator/ panel reachable",
		Detail:      "Joomla's administrator panel is exposed.",
		CWE:         "CWE-284",
		OWASP:       "A01:2021 Broken Access Control",
		Remediation: "Restrict /administrator/ to trusted ranges; enforce MFA on admin accounts.",
		Aggressive:  true,
	},
	{
		Path:        "/wp-admin/",
		Severity:    SeverityLow,
		Title:       "WordPress /wp-admin/ panel reachable",
		Detail:      "WordPress's admin panel is exposed.",
		CWE:         "CWE-284",
		OWASP:       "A01:2021 Broken Access Control",
		Remediation: "Restrict /wp-admin/ to trusted ranges; enforce MFA on admin accounts.",
		Aggressive:  true,
	},
	{
		Path:        "/phpmyadmin/",
		Severity:    SeverityMedium,
		Title:       "phpMyAdmin reachable",
		Detail:      "phpMyAdmin is a frequent brute-force target; its presence on the public web is rarely intended.",
		CWE:         "CWE-284",
		OWASP:       "A01:2021 Broken Access Control",
		Remediation: "Move phpMyAdmin off the public web or restrict it to admin IPs only.",
		Aggressive:  true,
	},
	{
		Path:        "/adminer.php",
		Severity:    SeverityMedium,
		Title:       "Adminer database UI reachable",
		Detail:      "adminer.php is a single-file database admin tool routinely targeted by automated exploitation.",
		CWE:         "CWE-284",
		OWASP:       "A01:2021 Broken Access Control",
		Remediation: "Remove adminer.php from production; if a DB UI is required, gate it behind a network ACL.",
		Aggressive:  true,
	},
	{
		Path:        "/manager/html",
		Severity:    SeverityMedium,
		Title:       "Tomcat /manager/html reachable",
		Detail:      "Tomcat's manager interface lets an authenticated user deploy arbitrary WAR files; default credentials are a recurring finding.",
		CWE:         "CWE-284",
		OWASP:       "A01:2021 Broken Access Control",
		Remediation: "Disable /manager/html on production Tomcat, or restrict it by IP and enforce strong unique credentials.",
		Aggressive:  true,
	},

	// -- CI / runtime artifacts -------------------------------------

	{
		Path:        "/Dockerfile",
		Severity:    SeverityLow,
		Title:       "Dockerfile reachable",
		Detail:      "Reveals base images, build steps, and any credentials passed in as build args.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude Dockerfile from the document root; produce deploy artifacts via a build pipeline that does not ship build metadata.",
		Marker:      "FROM ",
		Aggressive:  true,
	},
	{
		Path:        "/docker-compose.yml",
		Severity:    SeverityLow,
		Title:       "docker-compose.yml reachable",
		Detail:      "Lists services, volumes, and environment variables - including any credentials passed inline.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude docker-compose.yml from the document root.",
		Marker:      "services:",
		Aggressive:  true,
	},
	{
		Path:        "/.gitlab-ci.yml",
		Severity:    SeverityLow,
		Title:       ".gitlab-ci.yml reachable",
		Detail:      "Reveals CI pipeline structure and, when credentials are passed as variables in the YAML, leaks them too.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude .gitlab-ci.yml from the document root.",
		Aggressive:  true,
	},
	{
		Path:        "/Jenkinsfile",
		Severity:    SeverityLow,
		Title:       "Jenkinsfile reachable",
		Detail:      "Reveals the build pipeline and any credentials referenced inline.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude Jenkinsfile from the document root.",
		Marker:      "pipeline",
		Aggressive:  true,
	},
	{
		Path:        "/.travis.yml",
		Severity:    SeverityLow,
		Title:       ".travis.yml reachable",
		Detail:      "Reveals Travis CI pipeline structure and any credentials referenced inline.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude .travis.yml from the document root.",
		Aggressive:  true,
	},
	{
		Path:        "/.circleci/config.yml",
		Severity:    SeverityLow,
		Title:       "CircleCI config reachable (/.circleci/config.yml)",
		Detail:      "Reveals CircleCI pipeline structure and any credentials referenced inline.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude /.circleci/ from the document root.",
		Aggressive:  true,
	},
	{
		Path:        "/package.json",
		Severity:    SeverityInfo,
		Title:       "package.json reachable",
		Detail:      "Reveals dependency names and versions - useful for an attacker mapping known CVEs.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude package.json from the document root; ship only the runtime bundle.",
		Marker:      "\"dependencies\"",
		Aggressive:  true,
	},
	{
		Path:        "/package-lock.json",
		Severity:    SeverityInfo,
		Title:       "package-lock.json reachable",
		Detail:      "Lists every transitive dependency at its exact resolved version - lets an attacker enumerate known CVEs precisely.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude lockfiles from the document root.",
		Marker:      "\"lockfileVersion\"",
		Aggressive:  true,
	},
	{
		Path:        "/yarn.lock",
		Severity:    SeverityInfo,
		Title:       "yarn.lock reachable",
		Detail:      "Lists every transitive dependency at its exact resolved version.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude lockfiles from the document root.",
		Marker:      "# yarn lockfile",
		Aggressive:  true,
	},
	{
		Path:        "/composer.json",
		Severity:    SeverityInfo,
		Title:       "composer.json reachable",
		Detail:      "Reveals PHP dependency names and versions.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude composer.json from the document root.",
		Aggressive:  true,
	},
	{
		Path:        "/composer.lock",
		Severity:    SeverityInfo,
		Title:       "composer.lock reachable",
		Detail:      "Lists PHP dependencies at their exact resolved versions.",
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude composer.lock from the document root.",
		Marker:      "\"packages\"",
		Aggressive:  true,
	},

	// -- Informational ----------------------------------------------

	{
		Path:        "/.DS_Store",
		Severity:    SeverityLow,
		Title:       "macOS .DS_Store reachable",
		Detail:      "Contains directory listings from a developer's macOS workstation, revealing filenames that are not otherwise linked.",
		CWE:         "CWE-538",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Exclude .DS_Store from deployment artifacts.",
		Aggressive:  true,
	},
	{
		Path:        "/crossdomain.xml",
		Severity:    SeverityInfo,
		Title:       "Flash crossdomain.xml reachable",
		Detail:      "Legacy Flash policy file; rarely needed today and can over-permit cross-origin access if mis-set.",
		CWE:         "CWE-942",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Remove crossdomain.xml unless an active Flash dependency requires it; if kept, restrict allow-access-from domains.",
		Aggressive:  true,
	},
}

// discoveryFollowUpGroup expands the sweep after a confirming hit. When
// any path in Triggers fires a finding on the main sweep, every entry in
// Entries gets a second-wave probe. Use it to enumerate a directory or
// file family that is only worth touching after the parent confirms - a
// 95-entry /.git/* dictionary is wasteful when /.git/HEAD doesn't
// resolve, but is high-yield once we know the directory is exposed.
//
// Entries are deduped against the main sweep by Path, so listing a path
// here that also appears in contentDiscoveryEntries is harmless - the
// follow-up wave just skips it.
type discoveryFollowUpGroup struct {
	Triggers []string
	Entries  []discoveryEntry
}

var contentDiscoveryFollowUpGroups = []discoveryFollowUpGroup{
	{
		Triggers: []string{"/.git/HEAD", "/.git/config"},
		Entries: []discoveryEntry{
			{
				Path:        "/.git/logs/HEAD",
				Severity:    SeverityCritical,
				Title:       "exposed Git ref log (.git/logs/HEAD)",
				Detail:      "The ref log records every HEAD update, including commits that were rewritten or force-pushed away - effectively the full local history.",
				CWE:         "CWE-538",
				OWASP:       "A05:2021 Security Misconfiguration",
				Remediation: "Block /.git/ at the web server or CDN layer.",
				Marker:      "0000000000000000000000000000000000000000",
			},
			{
				Path:        "/.git/index",
				Severity:    SeverityCritical,
				Title:       "exposed Git index (.git/index)",
				Detail:      "The Git index lists every tracked file and its blob SHA, giving an attacker the full file inventory to fetch one blob at a time.",
				CWE:         "CWE-538",
				OWASP:       "A05:2021 Security Misconfiguration",
				Remediation: "Block /.git/ at the web server or CDN layer.",
				Marker:      "DIRC",
			},
			{
				Path:        "/.git/packed-refs",
				Severity:    SeverityHigh,
				Title:       "exposed Git packed-refs",
				Detail:      "Lists every ref the repository tracked - branch and tag names plus their commit SHAs.",
				CWE:         "CWE-538",
				OWASP:       "A05:2021 Security Misconfiguration",
				Remediation: "Block /.git/ at the web server or CDN layer.",
				Marker:      "# pack-refs",
			},
			{
				Path:        "/.git/description",
				Severity:    SeverityLow,
				Title:       ".git/description reachable",
				Detail:      "Confirms the .git directory is web-served.",
				CWE:         "CWE-538",
				OWASP:       "A05:2021 Security Misconfiguration",
				Remediation: "Block /.git/ at the web server or CDN layer.",
				Marker:      "Unnamed repository",
			},
		},
	},
	{
		Triggers: []string{"/.env", "/.env.local", "/.env.production"},
		Entries: []discoveryEntry{
			{Path: "/.env.dev", Severity: SeverityCritical, Title: "exposed environment file (.env.dev)", Detail: "Developer-overlay .env file is reachable.", CWE: "CWE-538", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Store secrets outside the document root; block /.env* at the web server layer.", Marker: "="},
			{Path: "/.env.development", Severity: SeverityCritical, Title: "exposed environment file (.env.development)", Detail: "Development-overlay .env file is reachable.", CWE: "CWE-538", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Store secrets outside the document root; block /.env* at the web server layer.", Marker: "="},
			{Path: "/.env.staging", Severity: SeverityCritical, Title: "exposed environment file (.env.staging)", Detail: "Staging-overlay .env file is reachable.", CWE: "CWE-538", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Store secrets outside the document root; block /.env* at the web server layer.", Marker: "="},
			{Path: "/.env.test", Severity: SeverityHigh, Title: "exposed environment file (.env.test)", Detail: "Test-overlay .env file is reachable.", CWE: "CWE-538", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Store secrets outside the document root; block /.env* at the web server layer.", Marker: "="},
			{Path: "/.env.backup", Severity: SeverityCritical, Title: "exposed environment file (.env.backup)", Detail: "Backup .env file is reachable.", CWE: "CWE-538", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Store secrets outside the document root; block /.env* at the web server layer.", Marker: "="},
			{Path: "/.env.bak", Severity: SeverityCritical, Title: "exposed environment file (.env.bak)", Detail: "Backup .env file is reachable.", CWE: "CWE-538", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Store secrets outside the document root; block /.env* at the web server layer.", Marker: "="},
			{Path: "/.env.old", Severity: SeverityCritical, Title: "exposed environment file (.env.old)", Detail: "Older .env file is reachable.", CWE: "CWE-538", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Store secrets outside the document root; block /.env* at the web server layer.", Marker: "="},
		},
	},
	{
		Triggers: []string{"/actuator", "/actuator/env", "/actuator/heapdump"},
		Entries: []discoveryEntry{
			{Path: "/actuator/health", Severity: SeverityLow, Title: "Spring Boot /actuator/health reachable", Detail: "Health endpoint discloses dependency status (DBs, brokers, downstream services).", CWE: "CWE-200", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Set management.endpoints.web.exposure.exclude to drop unintended endpoints and gate actuator behind authentication.", Marker: "\"status\""},
			{Path: "/actuator/mappings", Severity: SeverityMedium, Title: "Spring Boot /actuator/mappings reachable", Detail: "Lists every request mapping the app exposes - a one-shot endpoint map for an attacker.", CWE: "CWE-200", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Exclude mappings from the exposed actuators.", Marker: "\"mappings\""},
			{Path: "/actuator/configprops", Severity: SeverityHigh, Title: "Spring Boot /actuator/configprops reachable", Detail: "Discloses every @ConfigurationProperties bean and its resolved values - frequently includes secrets.", CWE: "CWE-200", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Exclude configprops from the exposed actuators.", Marker: "\"contexts\""},
			{Path: "/actuator/threaddump", Severity: SeverityMedium, Title: "Spring Boot /actuator/threaddump reachable", Detail: "Returns a full JVM thread dump - leaks code paths and any in-flight request data carried on a stack frame.", CWE: "CWE-200", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Exclude threaddump from the exposed actuators.", Marker: "\"threads\""},
		},
	},
	{
		Triggers: []string{"/wp-config.php"},
		Entries: []discoveryEntry{
			{Path: "/wp-config.php.bak", Severity: SeverityHigh, Title: "WordPress wp-config.php.bak reachable", Detail: "Backup of wp-config.php is served directly, disclosing DB credentials and authentication salts.", CWE: "CWE-538", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Remove backup copies from the document root.", Marker: "DB_PASSWORD"},
			{Path: "/wp-config.php.old", Severity: SeverityHigh, Title: "WordPress wp-config.php.old reachable", Detail: "Older copy of wp-config.php is served directly.", CWE: "CWE-538", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Remove backup copies from the document root.", Marker: "DB_PASSWORD"},
			{Path: "/wp-config.php~", Severity: SeverityHigh, Title: "WordPress wp-config.php~ reachable", Detail: "Editor backup of wp-config.php is served directly.", CWE: "CWE-538", OWASP: "A05:2021 Security Misconfiguration", Remediation: "Remove editor backup files from the document root.", Marker: "DB_PASSWORD"},
		},
	},
}
