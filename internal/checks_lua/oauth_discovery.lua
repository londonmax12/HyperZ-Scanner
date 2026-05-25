-- oauth-discovery: Lua port of internal/checks/oauth_discovery.go.
--
-- Passive audit of the OAuth 2.0 Authorization Server Metadata
-- (RFC 8414) and OpenID Connect Discovery 1.0 documents an identity
-- provider publishes at well-known paths on its issuer host. The
-- documents declare which signing algorithms, client-auth methods,
-- PKCE methods, and response types the AS accepts; misconfigurations
-- in these advertised values produce real attacker primitives even
-- before any login flow is exercised.
--
-- One finding per detected weakness (alg=none, symmetric algs, only
-- token-auth=none, missing/plain-only PKCE, implicit-flow response
-- types, plain-HTTP endpoints). Per-host caching lives in Go on
-- ctx.oauth.discover so a 50-page crawl probes the well-known
-- endpoint once; the audit policy runs in Lua against the cached
-- facts and the finding catalog is composed here, so the rule's
-- prose / severity policy is editable without rebuilding Go.

local check = {
  name  = "oauth-discovery",
  level = "passive",
  scope = "host",
}

-- BODY_SNIPPET_CAP matches Go's snippetJSON cap (512 bytes) so the
-- finding evidence reads identically across implementations. The full
-- body lives in the Exchange field; this is only the inline snippet.
local BODY_SNIPPET_CAP = 512

local function snippet_json(body)
  if body == nil or body == "" then return "" end
  -- TrimSpace mirrors bytes.TrimSpace in the Go path so leading /
  -- trailing whitespace from the JSON envelope does not appear in
  -- the snippet.
  local trimmed = string.gsub(body, "^%s+", "")
  trimmed = string.gsub(trimmed, "%s+$", "")
  if #trimmed > BODY_SNIPPET_CAP then
    return string.sub(trimmed, 1, BODY_SNIPPET_CAP)
  end
  return trimmed
end

local function lower_set(arr)
  local out = {}
  if arr == nil then return out end
  for _, s in ipairs(arr) do
    local trimmed = string.gsub(s, "^%s+", "")
    trimmed = string.gsub(trimmed, "%s+$", "")
    out[string.lower(trimmed)] = true
  end
  return out
end

local function only_contains(set, want)
  local n = 0
  for k in pairs(set) do
    n = n + 1
    if k ~= want then return false end
  end
  return n > 0
end

local function symmetric_algs(algs)
  local out = {}
  for _, candidate in ipairs({"hs256", "hs384", "hs512"}) do
    if algs[candidate] then
      out[#out + 1] = string.upper(candidate)
    end
  end
  return out
end

local function pkce_weakness(methods)
  local n = 0
  for _ in pairs(methods) do n = n + 1 end
  if n == 0 then
    return "does not advertise code_challenge_methods_supported, so PKCE is not announced as a capability"
  end
  if methods["s256"] then return "" end
  if methods["plain"] then
    return 'advertises only "plain" in code_challenge_methods_supported, which provides no protection against a code interceptor'
  end
  return "advertises code_challenge_methods_supported without S256"
end

local function implicit_flow_types(types)
  local out = {}
  -- "code id_token" is a hybrid that includes the code path and is
  -- not strictly implicit, but the fragment leak applies whenever
  -- id_token rides in the URL response, so it gets flagged too. Mirrors
  -- the Go ordering verbatim so finding details render identically.
  for _, rt in ipairs({"token", "id_token", "id_token token", "token id_token"}) do
    if types[rt] then
      out[#out + 1] = rt
    end
  end
  return out
end

local function plain_http_endpoints(facts)
  local out = {}
  local function check_field(label, raw)
    if raw == nil or raw == "" then return end
    local u = ctx_url_parse_safe(raw)
    if u and string.lower(u.scheme) == "http" then
      out[#out + 1] = label .. "=" .. raw
    end
  end
  check_field("authorization_endpoint", facts.authorization_endpoint)
  check_field("token_endpoint",         facts.token_endpoint)
  check_field("userinfo_endpoint",      facts.userinfo_endpoint)
  check_field("jwks_uri",               facts.jwks_uri)
  check_field("introspection_endpoint", facts.introspection_endpoint)
  check_field("revocation_endpoint",    facts.revocation_endpoint)
  return out
end

-- ctx_url_parse_safe is filled in once we hold the ctx (we need its
-- helper table). Defined as a forward-declared local because the
-- plain-HTTP check above closes over it without an explicit ctx
-- parameter.
ctx_url_parse_safe = nil

-- format_string_array mirrors Go's `fmt.Sprintf("%v", []string{...})`
-- which produces "[a b c]" for the finding detail prose. The Go
-- check folds the advertised values straight into the Sprintf with
-- %v; we replicate that bracketed-space-joined form so the Lua
-- finding text byte-matches the Go one.
local function format_string_array(arr)
  if arr == nil or #arr == 0 then return "[]" end
  return "[" .. table.concat(arr, " ") .. "]"
end

local function build_evidence(ctx, facts)
  return ctx.evidence.build {
    method  = "GET",
    url     = facts.probe_url,
    status  = facts.status,
    body    = snippet_json(facts.body),
  }
end

local function finding_alg_none(ctx, facts)
  return {
    severity = ctx.severity.critical,
    target   = facts.probe_url,
    url      = facts.probe_url,
    title    = "OAuth/OIDC discovery advertises alg=none for id_token",
    detail   = string.format(
      'The authorization server at %s lists "none" in id_token_signing_alg_values_supported '
        .. '(values: %s). An RP that pins acceptable algorithms against the advertised set will accept '
        .. 'unsigned id_tokens, letting any caller forge claims by sending an alg=none token with an empty '
        .. 'signature. The vulnerability lives in every RP that trusts this AS, not just one client.',
      facts.issuer, format_string_array(facts.id_token_signing_alg_values_supported)),
    cwe         = "CWE-327",
    owasp       = "A02:2021 Cryptographic Failures",
    remediation = 'Remove "none" from id_token_signing_alg_values_supported. There is no production use case '
      .. 'for unsigned id_tokens; an unsigned token provides no integrity guarantee and an attacker can substitute '
      .. 'arbitrary claims. Configure the AS to advertise only asymmetric algorithms (RS256, ES256, EdDSA) and '
      .. 'reissue rotated keys via jwks_uri.',
    evidence    = build_evidence(ctx, facts),
    dedupe_key  = ctx.dedupe.key {
      check  = check.name,
      scope  = "host",
      target = facts.probe_url,
      parts  = { "alg-none" },
    },
  }
end

local function finding_symmetric_alg(ctx, facts, sym_algs)
  return {
    severity = ctx.severity.medium,
    target   = facts.probe_url,
    url      = facts.probe_url,
    title    = "OAuth/OIDC discovery advertises symmetric id_token signing",
    detail   = string.format(
      'The authorization server at %s advertises symmetric id_token signing algorithms (%s) in '
        .. 'id_token_signing_alg_values_supported. Symmetric algorithms require the AS and every relying party '
        .. 'to share the same secret to verify tokens, so one RP\'s secret compromise lets that RP forge tokens '
        .. 'any other RP will accept. The OIDC core spec deprecated HS* outside narrow same-trust-domain '
        .. 'deployments for this reason.',
      facts.issuer, format_string_array(sym_algs)),
    cwe         = "CWE-327",
    owasp       = "A02:2021 Cryptographic Failures",
    remediation = 'Migrate to asymmetric id_token signing (RS256, ES256, EdDSA). Publish the public key via '
      .. 'jwks_uri so RPs verify against a key only the AS holds the private half of. If a symmetric algorithm '
      .. 'must remain for a legacy client, advertise it only for that client\'s audience rather than as a server-'
      .. 'wide capability.',
    evidence    = build_evidence(ctx, facts),
    dedupe_key  = ctx.dedupe.key {
      check  = check.name,
      scope  = "host",
      target = facts.probe_url,
      parts  = { "symmetric-alg" },
    },
  }
end

local function finding_token_endpoint_auth_none(ctx, facts)
  return {
    severity = ctx.severity.high,
    target   = facts.probe_url,
    url      = facts.probe_url,
    title    = "OAuth/OIDC token endpoint accepts only unauthenticated clients",
    detail   = string.format(
      'The authorization server at %s advertises only "none" in token_endpoint_auth_methods_supported. '
        .. 'That means the token endpoint will mint tokens for any caller presenting a valid authorization code '
        .. 'without verifying client identity, so an attacker who intercepts a code can trade it for tokens '
        .. 'indistinguishably from the legitimate client. Confidential clients become impossible against this AS.',
      facts.issuer),
    cwe         = "CWE-287",
    owasp       = "A07:2021 Identification and Authentication Failures",
    remediation = 'Configure the AS to support a real client-auth method for confidential clients '
      .. '(client_secret_basic, client_secret_post, private_key_jwt). Reserve token_endpoint_auth_method=none '
      .. 'for public clients (SPAs, native apps) that pair it with PKCE; even then, confidential clients should '
      .. 'have a stronger option available.',
    evidence    = build_evidence(ctx, facts),
    dedupe_key  = ctx.dedupe.key {
      check  = check.name,
      scope  = "host",
      target = facts.probe_url,
      parts  = { "token-auth-none" },
    },
  }
end

local function finding_pkce_weak(ctx, facts, weakness)
  return {
    severity = ctx.severity.medium,
    target   = facts.probe_url,
    url      = facts.probe_url,
    title    = "OAuth/OIDC discovery advertises weak or absent PKCE support",
    detail   = string.format(
      'The authorization server at %s %s. PKCE binds an authorization code to the client that requested it, '
        .. 'preventing an interceptor of the code from trading it for tokens. Without S256 enforcement, public '
        .. 'clients (SPAs, native apps) fall back to bearer-style code exchange and any party who reads the '
        .. 'redirect URL can complete the flow.',
      facts.issuer, weakness),
    cwe         = "CWE-287",
    owasp       = "A07:2021 Identification and Authentication Failures",
    remediation = 'Advertise S256 in code_challenge_methods_supported and reject authorization requests without '
      .. 'a code_challenge parameter for public clients. OAuth 2.1 and FAPI 2.0 mandate PKCE with S256; legacy '
      .. '"plain" support should be removed since it provides no protection against a code interceptor.',
    evidence    = build_evidence(ctx, facts),
    dedupe_key  = ctx.dedupe.key {
      check  = check.name,
      scope  = "host",
      target = facts.probe_url,
      parts  = { "pkce-weak" },
    },
  }
end

local function finding_implicit_flow(ctx, facts, types)
  return {
    severity = ctx.severity.low,
    target   = facts.probe_url,
    url      = facts.probe_url,
    title    = "OAuth/OIDC discovery advertises deprecated implicit flow",
    detail   = string.format(
      'The authorization server at %s advertises implicit-flow response types (%s) in '
        .. 'response_types_supported. The implicit flow lands access tokens (and sometimes id_tokens) in the '
        .. 'URL fragment, where they leak through browser history, server access logs, the Referer header, and '
        .. 'document.location. OAuth 2.1 and the OIDC "implicit considered harmful" guidance recommend the '
        .. 'authorization code flow with PKCE for every client shape that previously used implicit.',
      facts.issuer, format_string_array(types)),
    cwe         = "CWE-598",
    owasp       = "A04:2021 Insecure Design",
    remediation = 'Stop advertising implicit response types. Migrate SPA / native clients to authorization code '
      .. 'flow with PKCE, which keeps tokens out of the URL and supports refresh tokens. If a client cannot be '
      .. 'migrated immediately, scope the deprecation to that client\'s metadata rather than as a server-wide '
      .. 'capability.',
    evidence    = build_evidence(ctx, facts),
    dedupe_key  = ctx.dedupe.key {
      check  = check.name,
      scope  = "host",
      target = facts.probe_url,
      parts  = { "implicit-flow" },
    },
  }
end

local function finding_plain_http_endpoint(ctx, facts, endpoints)
  return {
    severity = ctx.severity.high,
    target   = facts.probe_url,
    url      = facts.probe_url,
    title    = "OAuth/OIDC discovery advertises endpoints over plain HTTP",
    detail   = string.format(
      'The authorization server at %s advertises one or more endpoints over plain HTTP (%s). Any caller '
        .. 'on the network between the user agent and the AS can read or rewrite the authorization request, '
        .. 'the code exchange, or the userinfo response. OAuth 2.0 (RFC 6749) and OIDC core both require TLS '
        .. 'on every endpoint in the flow.',
      facts.issuer, format_string_array(endpoints)),
    cwe         = "CWE-319",
    owasp       = "A02:2021 Cryptographic Failures",
    remediation = 'Serve every OAuth / OIDC endpoint over HTTPS and update the discovery document so the '
      .. 'published URLs match. If the AS is behind a TLS-terminating proxy, ensure the metadata advertises the '
      .. 'external HTTPS URL rather than the internal HTTP one.',
    evidence    = build_evidence(ctx, facts),
    dedupe_key  = ctx.dedupe.key {
      check  = check.name,
      scope  = "host",
      target = facts.probe_url,
      parts  = { "plain-http" },
    },
  }
end

-- restamp_to_page mirrors the Go restampFindings pass: the audit
-- builds each finding against the discovery probe URL (so the dedupe
-- key keys off the canonical resource) but we re-stamp Target / URL
-- to the current page so the report ties to a URL the operator saw.
local function restamp_to_page(findings, page_url)
  for _, f in ipairs(findings) do
    f.target = page_url
    f.url    = page_url
  end
end

function check.run(ctx)
  ctx_url_parse_safe = function(raw)
    local u, _ = ctx.url.parse(raw)
    return u
  end

  local facts, err = ctx.oauth.discover(ctx.page.url)
  if err then
    ctx:report("oauth-discovery: " .. err)
    return nil
  end
  if facts == nil then return nil end

  local findings = {}

  local algs = lower_set(facts.id_token_signing_alg_values_supported)
  if algs["none"] then
    findings[#findings + 1] = finding_alg_none(ctx, facts)
  end
  local sym = symmetric_algs(algs)
  if #sym > 0 then
    findings[#findings + 1] = finding_symmetric_alg(ctx, facts, sym)
  end

  local auth_methods = lower_set(facts.token_endpoint_auth_methods_supported)
  if only_contains(auth_methods, "none") then
    findings[#findings + 1] = finding_token_endpoint_auth_none(ctx, facts)
  end

  local pkce_methods = lower_set(facts.code_challenge_methods_supported)
  local pkce_weak = pkce_weakness(pkce_methods)
  if pkce_weak ~= "" then
    findings[#findings + 1] = finding_pkce_weak(ctx, facts, pkce_weak)
  end

  local resp_types = lower_set(facts.response_types_supported)
  local implicit = implicit_flow_types(resp_types)
  if #implicit > 0 then
    findings[#findings + 1] = finding_implicit_flow(ctx, facts, implicit)
  end

  local plain = plain_http_endpoints(facts)
  if #plain > 0 then
    findings[#findings + 1] = finding_plain_http_endpoint(ctx, facts, plain)
  end

  if #findings == 0 then return nil end
  restamp_to_page(findings, ctx.page.url)
  return findings
end

return check
