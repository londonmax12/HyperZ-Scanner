package lua_engine

import "regexp"

// secretPattern is one named credential matcher. id is the short stable
// token used in dedupe keys and detail prefixes; label is the human name
// of the secret type that appears in finding text. re is anchored on a
// vendor-specific prefix or structural marker; only the full match is
// used downstream.
//
// contextRE is optional. When non-nil, a hit is kept only if the regex
// also matches inside a window of [secretContextWindow] bytes around
// the candidate. This is the escape hatch for patterns whose shape is
// inherently ambiguous (a key-<32hex> string is indistinguishable from
// a generic content digest) and would otherwise produce a flood of
// false positives on cache-key-heavy bodies.
type secretPattern struct {
	id        string
	label     string
	severity  Severity
	re        *regexp.Regexp
	contextRE *regexp.Regexp
}

// secretContextWindow is the per-side byte radius searched for a
// pattern's optional contextRE. 256 bytes is enough to catch an
// adjacent assignment like `MAILGUN_API_KEY = "..."` even with
// intervening template syntax, but tight enough that an unrelated
// mention of "mailgun" elsewhere in a bundle does not drag in a
// random key-<hex> hit.
const secretContextWindow = 256

// Each category slice below groups patterns by the kind of system they
// protect. The flat secretPatterns slice at the bottom is what the check
// iterates - the split exists so adding a new vendor lands next to its
// peers and so the catalogue stays auditable as it grows.
//
// Rules every pattern in this file must follow:
//   - Anchor on a vendor-specific prefix or structural marker. No
//     entropy-only matchers; the false-positive cost is too high in
//     bodies that legitimately contain base64 / hex blobs (assets,
//     content hashes, opaque IDs).
//   - Severity reflects access granted, not credential value. Long-lived
//     production credentials are Critical, scoped service tokens are
//     High, session-style tokens (JWT, DSNs) are Medium.
//   - Length floors come from the vendor's documented minimum, not the
//     typical observed length, so a token a logger or proxy clipped
//     still matches.

// secretsCloud covers IaaS providers. Cloud keys typically grant the
// broadest blast radius of any leak (full account API access) so the
// bar to land here is Critical.
var secretsCloud = []secretPattern{
	{
		id:       "aws-access-key-id",
		label:    "AWS access key ID",
		severity: SeverityCritical,
		// AKIA = long-term IAM user key; ASIA = temporary STS key; both
		// grant API access and both should be flagged. Suffix is the
		// canonical 16-char uppercase alphanumeric body.
		re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	},
	{
		id:       "digitalocean-pat",
		label:    "DigitalOcean personal access token",
		severity: SeverityCritical,
		// dop_v1_ prefix + 64 lowercase hex. Grants full DO API access.
		re: regexp.MustCompile(`\bdop_v1_[a-f0-9]{64}\b`),
	},
}

// secretsVCS covers code hosting / source control. Leaked VCS tokens
// give read or write access to repositories, which is a path to source
// disclosure and supply-chain compromise via pushed commits.
var secretsVCS = []secretPattern{
	{
		id:       "github-token",
		label:    "GitHub personal access / OAuth token",
		severity: SeverityCritical,
		// ghp = personal access token, gho = OAuth, ghu = user-to-server,
		// ghs = server-to-server, ghr = refresh. GitHub's documented
		// body length is 36 chars but newer tokens can be longer; allow
		// up to 255 to stay forward-compatible.
		re: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b`),
	},
	{
		id:       "github-fine-grained-pat",
		label:    "GitHub fine-grained personal access token",
		severity: SeverityCritical,
		re:       regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`),
	},
	{
		id:       "gitlab-pat",
		label:    "GitLab personal access token",
		severity: SeverityCritical,
		// glpat- + 20 url-safe chars. GitLab also issues glptt- (project
		// trigger) and glsoat- (OAuth) but glpat is the one that grants
		// user-equivalent API access.
		re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`),
	},
}

// secretsPackages covers package registries. Leaked publish tokens are
// a direct supply-chain risk: a malicious version pushed to a popular
// package executes on every install downstream.
var secretsPackages = []secretPattern{
	{
		id:       "npm-token",
		label:    "npm access token",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
	},
	{
		id:       "pypi-token",
		label:    "PyPI API token",
		severity: SeverityHigh,
		// PyPI tokens are macaroons - "pypi-" + base64(macaroon body),
		// always starting with AgE (the macaroon version prefix). The
		// body is long; 50 chars is a safe minimum floor.
		re: regexp.MustCompile(`\bpypi-AgE[A-Za-z0-9_-]{50,}\b`),
	},
}

// secretsPayments covers card / billing platforms. Live keys read or
// move money; webhook secrets allow forging callback events that
// trigger payment-side state changes.
var secretsPayments = []secretPattern{
	{
		id:       "stripe-live-secret-key",
		label:    "Stripe live secret key",
		severity: SeverityCritical,
		re:       regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{20,}\b`),
	},
	{
		id:       "stripe-live-restricted-key",
		label:    "Stripe live restricted key",
		severity: SeverityCritical,
		re:       regexp.MustCompile(`\brk_live_[0-9A-Za-z]{20,}\b`),
	},
	{
		id:       "stripe-webhook-secret",
		label:    "Stripe webhook signing secret",
		severity: SeverityHigh,
		// whsec_ + base32-ish body. Allows forging valid signatures on
		// Stripe webhook callbacks, which most integrations treat as
		// authenticated server-to-server events.
		re: regexp.MustCompile(`\bwhsec_[A-Za-z0-9]{32,}\b`),
	},
	{
		id:       "square-access-token",
		label:    "Square access token",
		severity: SeverityHigh,
		// Production access tokens (sq0atp-) and application secrets
		// (sq0csp-). The newer EAAA... OAuth format is not anchored
		// tightly enough to include without FP risk.
		re: regexp.MustCompile(`\bsq0(?:atp|csp)-[0-9A-Za-z_-]{22,43}\b`),
	},
	{
		id:       "stripe-test-secret-key",
		label:    "Stripe test secret key",
		severity: SeverityMedium,
		re:       regexp.MustCompile(`\bsk_test_[0-9A-Za-z]{20,}\b`),
	},
}

// secretsComms covers messaging / email / SMS providers. These keys
// don't usually move money directly but they reach users (phishing
// vector) and often carry reply-to / domain authority that gets a
// crafted message through spam filters.
var secretsComms = []secretPattern{
	{
		id:       "slack-token",
		label:    "Slack token",
		severity: SeverityHigh,
		// xoxa = workspace, xoxb = bot, xoxp = user, xoxr = refresh,
		// xoxs = legacy. All grant Slack API access against the
		// workspace.
		re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`),
	},
	{
		id:       "slack-app-token",
		label:    "Slack app-level token",
		severity: SeverityHigh,
		// xapp- tokens scope to a specific app and are used for Socket
		// Mode connections; format is xapp-N-A...-N-hex.
		re: regexp.MustCompile(`\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+\b`),
	},
	{
		id:       "slack-webhook",
		label:    "Slack incoming webhook URL",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`\bhttps://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+\b`),
	},
	{
		id:       "discord-webhook",
		label:    "Discord webhook URL",
		severity: SeverityHigh,
		// discord.com and the legacy discordapp.com host both work.
		re: regexp.MustCompile(`\bhttps://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_-]{60,}\b`),
	},
	{
		id:       "telegram-bot-token",
		label:    "Telegram bot token",
		severity: SeverityHigh,
		// <bot id>:<35 url-safe chars>. The colon-separated structure
		// is distinctive enough to anchor on despite the absence of a
		// vendor prefix.
		re: regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{35}\b`),
	},
	{
		id:       "sendgrid-api-key",
		label:    "SendGrid API key",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`),
	},
	{
		id:       "mailgun-api-key",
		label:    "Mailgun API key",
		severity: SeverityHigh,
		// The bare key- + 32 hex shape collides with internal cache-key
		// / content-digest formats common in build outputs. The
		// contextRE narrows the matcher to hits that sit near a
		// Mailgun-shaped identifier ("mailgun" word or an "mg." host
		// fragment), which is what every real Mailgun integration ships.
		re:        regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`),
		contextRE: regexp.MustCompile(`(?i)mailgun|\bmg\.`),
	},
}

// secretsGoogle covers Google's three distinct user-facing credential
// formats. They live in their own group because a "Google API key"
// gates a huge spread of products (Maps, Translate, Vision, Speech,
// YouTube Data, Drive, Cloud APIs); it isn't a comms credential and
// it isn't a cloud-IaaS credential either. Service-account JSON keys
// are not listed here because their inner -----BEGIN PRIVATE KEY-----
// block is already caught by the PEM matcher in secretsCrypto.
var secretsGoogle = []secretPattern{
	{
		id:       "google-api-key",
		label:    "Google API key",
		severity: SeverityHigh,
		// Documented as AIza + 35 chars of URL-safe alphanumerics.
		re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
	},
	{
		id:       "gcp-oauth-client-secret",
		label:    "GCP OAuth client secret",
		severity: SeverityHigh,
		// GOCSPX- + 28 url-safe chars. Granting impersonation of the
		// OAuth client; a leak lets an attacker mint user-consented
		// tokens against any scope the client is registered for.
		re: regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9_-]{28}\b`),
	},
	{
		id:       "google-oauth-access-token",
		label:    "Google OAuth access token",
		severity: SeverityMedium,
		// ya29. prefix is the documented anchor for OAuth2 bearer
		// access tokens. Short-lived (typically 1h) but valid as a
		// bearer for the issued scopes until expiry, so worth
		// surfacing - just one tier below the long-lived credentials.
		re: regexp.MustCompile(`\bya29\.[A-Za-z0-9_-]{30,}\b`),
	},
}

// secretsAI covers LLM / model provider API keys. These bill against
// the holder's account and many also grant access to fine-tunes or
// custom assistants attached to that account, so a leak is both a
// financial exposure and a model-state exposure.
var secretsAI = []secretPattern{
	{
		id:       "openai-api-key",
		label:    "OpenAI API key",
		severity: SeverityCritical,
		// Classic OpenAI keys are sk- + 20 chars + the literal T3BlbkFJ
		// marker (base64 of "OpenAI") + 20 chars. The marker is what
		// makes this safely anchorable; bare sk-... is too generic.
		re: regexp.MustCompile(`\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b`),
	},
	{
		id:       "openai-project-key",
		label:    "OpenAI project key",
		severity: SeverityCritical,
		// Project-scoped keys use sk-proj- with a long opaque body.
		re: regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{40,}\b`),
	},
	{
		id:       "anthropic-api-key",
		label:    "Anthropic API key",
		severity: SeverityCritical,
		// sk-ant-api<NN>- prefix is highly distinctive; allow {80,} on
		// the body so future-length tokens still match without us
		// chasing every format revision.
		re: regexp.MustCompile(`\bsk-ant-api\d{2}-[A-Za-z0-9_\-]{80,}\b`),
	},
	{
		id:       "huggingface-token",
		label:    "Hugging Face access token",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`\bhf_[A-Za-z0-9]{34}\b`),
	},
}

// secretsObservability covers logging / metrics / error-tracking
// platforms. A leaked write key lets an attacker pollute or spam your
// observability pipeline; a leaked read key exfiltrates the operational
// picture of your system (latencies, error payloads, user identifiers
// in traces). DSNs sit lower in severity because they're write-only.
var secretsObservability = []secretPattern{
	{
		id:       "sentry-auth-token",
		label:    "Sentry auth token",
		severity: SeverityHigh,
		// sntrys_ is the org auth token prefix; sntryu_ is user.
		re: regexp.MustCompile(`\bsntr(?:ys|yu)_[A-Za-z0-9_=+/-]{40,}\b`),
	},
	{
		id:       "newrelic-license-key",
		label:    "New Relic license key",
		severity: SeverityHigh,
		// 40 lowercase hex + literal NRAL suffix is what makes this
		// safely anchorable - bare 40-hex would collide with countless
		// content digests.
		re: regexp.MustCompile(`\b[a-f0-9]{40}NRAL\b`),
	},
	{
		id:       "newrelic-api-key",
		label:    "New Relic API key",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`\bNRAK-[A-Z0-9]{27}\b`),
	},
	{
		id:       "sentry-dsn",
		label:    "Sentry DSN",
		severity: SeverityMedium,
		// DSNs embed a public key in a URL; they're send-only but a
		// leaked DSN still lets attackers spam events into the
		// project. Kept Medium because read paths are not exposed.
		re: regexp.MustCompile(`\bhttps://[a-f0-9]{32}@(?:[a-z0-9.-]+\.)?(?:ingest\.)?sentry\.io/\d+\b`),
	},
}

// secretsSaaS covers application-tier SaaS tokens. Most grant API
// access scoped to one organisation; the impact depends on what that
// org's data is, but the access path is direct (most are bearer
// tokens used as-is with no signing handshake).
var secretsSaaS = []secretPattern{
	{
		id:       "shopify-access-token",
		label:    "Shopify access token",
		severity: SeverityCritical,
		// shpat_ = admin API access token (admin-equivalent),
		// shpca_ = custom app token, shpss_ = shared secret. All
		// three are credential material against a live store.
		re: regexp.MustCompile(`\bshp(?:at|ca|ss)_[a-f0-9]{32}\b`),
	},
	{
		id:       "linear-api-key",
		label:    "Linear API key",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`\blin_api_[A-Za-z0-9]{40}\b`),
	},
	{
		id:       "notion-integration-token",
		label:    "Notion integration token",
		severity: SeverityHigh,
		// secret_ + 43 url-safe chars. The prefix is generic on its
		// own but the fixed-length body makes it safely anchorable.
		re: regexp.MustCompile(`\bsecret_[A-Za-z0-9]{43}\b`),
	},
	{
		id:       "supabase-secret-key",
		label:    "Supabase secret API key",
		severity: SeverityCritical,
		// sb_secret_ + url-safe body. Replaces the legacy service_role
		// JWT; bypasses Row Level Security so a leak is admin-equivalent
		// DB access. Floor of 20 chars on the body keeps the matcher
		// forward-compatible if Supabase tweaks the encoding length.
		re: regexp.MustCompile(`\bsb_secret_[A-Za-z0-9_-]{20,}\b`),
	},
	{
		id:       "supabase-access-token",
		label:    "Supabase personal access token",
		severity: SeverityCritical,
		// sbp_ + 40 lowercase hex. Grants project-admin access against
		// the Supabase management API for every project the issuing
		// user owns.
		re: regexp.MustCompile(`\bsbp_[a-f0-9]{40}\b`),
	},
}

// secretsCrypto covers raw cryptographic material that isn't tied to
// a single vendor. A private key in a response body is almost always
// a misconfigured deploy (build artifact accidentally served, debug
// dump, error page including a config file).
var secretsCrypto = []secretPattern{
	{
		id:       "pem-private-key",
		label:    "PEM-encoded private key",
		severity: SeverityCritical,
		re:       regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`),
	},
	{
		id:       "jwt",
		label:    "JSON Web Token",
		severity: SeverityMedium,
		// A JWT is three base64url segments joined by dots. eyJ is the
		// base64url-encoded "{\"" prefix of every JWT header, which
		// makes it a near-unique structural anchor and avoids matching
		// unrelated dotted base64-ish strings.
		re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	},
}

// secretPatterns is the flat catalogue iterated at runtime. Order
// here only governs stable iteration for tests; findings are re-sorted
// by (severity desc, id) before they reach the report.
var secretPatterns = func() []secretPattern {
	groups := [][]secretPattern{
		secretsCloud,
		secretsVCS,
		secretsPackages,
		secretsPayments,
		secretsComms,
		secretsGoogle,
		secretsAI,
		secretsObservability,
		secretsSaaS,
		secretsCrypto,
	}
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	out := make([]secretPattern, 0, total)
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}()
