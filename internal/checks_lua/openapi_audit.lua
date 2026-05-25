-- openapi-audit: Lua port of internal/checks/openapi_audit.go.
--
-- Discovers OpenAPI / Swagger documents at well-known per-host paths
-- and audits the document itself for three classes of exposure that
-- ship in the spec long before any request hits a real endpoint:
--
--   1. Embedded credentials. Every secrets_in_body pattern fires
--      against the spec body; specs are published alongside the code
--      that consumes them so any example/default value is a public
--      disclosure of every literal it carries.
--   2. Example authorization headers. Authorization-shaped values
--      sitting next to example/default/value blocks leak signing-algo
--      / claim-shape (JWTs) or username (Basic) even when fully
--      synthetic; accidental real credentials get flagged here too.
--   3. Auth-less operations. When the spec declares an auth scheme
--      via components.securitySchemes (OAS3) or securityDefinitions
--      (Swagger 2) but operations carry no security requirement and
--      inherit no global default, those operations are publicly
--      reachable.
--
-- Per-host caching of the probe + parsed body lives in Go via
-- ctx.openapi.discover (one fetch per host per scan); the audit
-- policy runs in Lua against the cached facts and composes the
-- finding catalog here so prose / severity / dedupe shape is editable
-- without rebuilding Go.

local check = {
  name  = "openapi-audit",
  level = "passive",
  scope = "host",
}

-- BODY_SNIPPET_CAP matches Go's snippetJSON cap (512 bytes) so the
-- finding evidence reads identically across implementations.
local BODY_SNIPPET_CAP = 512

local function snippet_json(body)
  if body == nil or body == "" then return "" end
  local trimmed = string.gsub(body, "^%s+", "")
  trimmed = string.gsub(trimmed, "%s+$", "")
  if #trimmed > BODY_SNIPPET_CAP then
    return string.sub(trimmed, 1, BODY_SNIPPET_CAP)
  end
  return trimmed
end

local SEVERITY_RANK = { info = 0, low = 1, medium = 2, high = 3, critical = 4 }

local function build_evidence(ctx, facts)
  return ctx.evidence.build {
    method  = "GET",
    url     = facts.probe_url,
    status  = facts.status,
    snippet = snippet_json(facts.body),
  }
end

-- finding_embedded_credentials reuses ctx.body.find_secrets so the
-- Lua port runs the same pattern catalogue, applies the same nearby-
-- context filter, and gets back the same (id, label, severity, raw,
-- redacted, count) hit shape the secrets_in_body port consumes. The
-- audit-side composition (sort by severity desc / id / redacted,
-- max-severity, dedupe parts) lives here.
local function finding_embedded_credentials(ctx, facts)
  local hits = ctx.body.find_secrets(facts.body)
  if #hits == 0 then return nil end

  -- find_secrets already returns hits sorted (severity desc, id asc,
  -- redacted asc) - mirrors the Go check's sort.SliceStable shape
  -- verbatim so the first hit's label feeds the single-hit title.

  local max_sev = "info"
  local details = {}
  local id_parts = {}
  for _, h in ipairs(hits) do
    if SEVERITY_RANK[h.severity] > SEVERITY_RANK[max_sev] then
      max_sev = h.severity
    end
    local occ = ""
    if h.count > 1 then
      occ = string.format(" (%d occurrences)", h.count)
    end
    details[#details + 1] = string.format("%s [%s]: %s%s", h.label, h.severity, h.redacted, occ)
    id_parts[#id_parts + 1] = h.id .. ":" .. h.redacted
  end

  local title
  if #hits == 1 then
    title = "OpenAPI spec embeds a credential (" .. hits[1].label .. ")"
  else
    title = string.format("OpenAPI spec embeds %d distinct credentials", #hits)
  end

  local detail = string.format(
    "The OpenAPI / Swagger document at %s contains values matching known credential patterns. "
      .. "Specs are frequently published alongside the code that consumes them, so any credential value "
      .. "baked into an example or default ships to every reader of the document. "
      .. "Treat each entry as compromised the moment the spec was served.",
    facts.probe_url)

  local remediation = "Remove the embedded credential from the spec and rotate the value immediately - "
    .. "publication of a spec is a public disclosure of every literal value it carries. "
    .. "Audit access logs for the affected key during the exposure window. "
    .. "Replace any example or default that needs to demonstrate the shape of an authorized request with "
    .. "an obviously-fake placeholder (e.g. `xxxxxxxxxxxx`) and document elsewhere how a reader can obtain "
    .. "real credentials. "
    .. "For specs generated from source annotations, scrub the upstream annotations so the next "
    .. "regeneration does not reintroduce the leak."

  local parts = { "embedded-credentials" }
  for _, p in ipairs(id_parts) do parts[#parts + 1] = p end

  return {
    severity    = ctx.severity[max_sev],
    target      = facts.probe_url,
    url         = facts.probe_url,
    title       = title,
    detail      = detail,
    details     = details,
    cwe         = "CWE-200, CWE-798",
    owasp       = "A02:2021 Cryptographic Failures",
    remediation = remediation,
    evidence    = build_evidence(ctx, facts),
    dedupe_key  = ctx.dedupe.key {
      check  = check.name,
      scope  = "host",
      target = facts.probe_url,
      parts  = parts,
    },
  }
end

-- finding_example_auth_tokens consumes the raw regex hits from
-- ctx.openapi.scan_example_auth_matches and applies the audit policy
-- (dedup by scheme+redacted, sort by scheme asc / redacted asc). The
-- regex + nearby-context filter live in Go for re2 power; everything
-- else lives here.
local function finding_example_auth_tokens(ctx, facts)
  local raw = ctx.openapi.scan_example_auth_matches(facts.body)
  if #raw == 0 then return nil end

  local seen = {}
  local hits = {}
  for _, h in ipairs(raw) do
    local key = h.scheme .. ":" .. h.redacted
    if not seen[key] then
      seen[key] = true
      hits[#hits + 1] = { scheme = h.scheme, redacted = h.redacted }
    end
  end
  if #hits == 0 then return nil end

  table.sort(hits, function(a, b)
    if a.scheme ~= b.scheme then return a.scheme < b.scheme end
    return a.redacted < b.redacted
  end)

  local details = {}
  local id_parts = {}
  for _, h in ipairs(hits) do
    details[#details + 1] = string.format("%s example: %s", h.scheme, h.redacted)
    id_parts[#id_parts + 1] = h.scheme .. ":" .. h.redacted
  end

  local detail = string.format(
    "The OpenAPI / Swagger document at %s carries Authorization-header values inside example / default / "
      .. "value blocks. Even fully-synthetic examples leak the signing algorithm and claim shape (for JWTs) "
      .. "or the username portion before the colon (for Basic) to every reader of the spec; an example "
      .. "accidentally populated with a real test-account credential is publicly disclosed.",
    facts.probe_url)

  local remediation = "Replace example Authorization values with obviously-fake placeholders that still "
    .. "demonstrate the wire format (e.g. `Bearer <token>` or `Basic dXNlcjpwYXNz` containing only "
    .. "synthetic data). "
    .. "For JWT examples, generate a token with random keys at documentation-build time rather than "
    .. "copying a real one from a development environment. "
    .. "For Basic examples, never use a real account's username even if the password portion is fake - "
    .. "the username alone is enough to enumerate the directory."

  local parts = { "example-auth-tokens" }
  for _, p in ipairs(id_parts) do parts[#parts + 1] = p end

  return {
    severity    = ctx.severity.low,
    target      = facts.probe_url,
    url         = facts.probe_url,
    title       = "OpenAPI spec carries example Authorization tokens",
    detail      = detail,
    details     = details,
    cwe         = "CWE-200",
    owasp       = "A05:2021 Security Misconfiguration",
    remediation = remediation,
    evidence    = build_evidence(ctx, facts),
    dedupe_key  = ctx.dedupe.key {
      check  = check.name,
      scope  = "host",
      target = facts.probe_url,
      parts  = parts,
    },
  }
end

-- requirement_is_authenticated mirrors the Go helper of the same
-- name. An entry like { OAuth2 = {"read"} } means "auth required";
-- {} or an entry whose only key is empty/whitespace means "no auth".
local function requirement_is_authenticated(req)
  if req == nil then return false end
  for _, entry in ipairs(req) do
    if type(entry) == "table" then
      for name, _ in pairs(entry) do
        if type(name) == "string" then
          local trimmed = name:gsub("^%s+", ""):gsub("%s+$", "")
          if trimmed ~= "" then return true end
        end
      end
    end
  end
  return false
end

-- operation_is_authenticated returns true when op enforces auth. An
-- op with no `security:` key inherits global_required; an op that
-- declares `security: []` overrides global to "no auth" - the
-- canonical way to mark a deliberately-public op under a secured API.
local function operation_is_authenticated(op_security, op_has_security, global_required)
  if not op_has_security then return global_required end
  return requirement_is_authenticated(op_security)
end

local AUTHLESS_METHODS = { "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS" }

-- finding_authless_operations parses the spec body as JSON and reports
-- operations that carry no security requirement when the spec declares
-- at least one security scheme. JSON-only (Go check is the same); a
-- spec served as YAML skips this pass but still gets the other two.
local function finding_authless_operations(ctx, facts)
  local body = facts.body
  if body == nil or body == "" then return nil end
  -- Mirrors Go's trimmed[0] != '{' gate - only run on JSON objects.
  local trimmed = body:gsub("^%s+", "")
  if trimmed:sub(1, 1) ~= "{" then return nil end

  local doc, err = ctx.json.decode(body)
  if err ~= nil or type(doc) ~= "table" then return nil end

  local schemes_oas3 = (doc.components and doc.components.securitySchemes) or nil
  local schemes_swagger2 = doc.securityDefinitions or nil
  local declares = false
  if type(schemes_oas3) == "table" then
    for _ in pairs(schemes_oas3) do declares = true; break end
  end
  if not declares and type(schemes_swagger2) == "table" then
    for _ in pairs(schemes_swagger2) do declares = true; break end
  end
  if not declares then return nil end

  local global_required = requirement_is_authenticated(doc.security)

  local paths = doc.paths
  if type(paths) ~= "table" then return nil end

  local unauth = {}
  for path, item in pairs(paths) do
    if type(path) == "string" and path:sub(1, 1) == "/" and type(item) == "table" then
      for _, method in ipairs(AUTHLESS_METHODS) do
        local op = item[method:lower()]
        if type(op) == "table" then
          local op_security = op.security
          local op_has_security = (op_security ~= nil)
          if not operation_is_authenticated(op_security, op_has_security, global_required) then
            unauth[#unauth + 1] = { method = method, path = path }
          end
        end
      end
    end
  end

  if #unauth == 0 then return nil end

  table.sort(unauth, function(a, b)
    if a.path ~= b.path then return a.path < b.path end
    return a.method < b.method
  end)

  local details = {}
  local id_parts = {}
  for _, e in ipairs(unauth) do
    details[#details + 1] = e.method .. " " .. e.path
    id_parts[#id_parts + 1] = e.method .. " " .. e.path
  end

  local detail = string.format(
    "The OpenAPI / Swagger document at %s declares an authentication scheme "
      .. "(components.securitySchemes / securityDefinitions) but %d operation(s) carry no security "
      .. "requirement and inherit no global default. Those operations are reachable without credentials.",
    facts.probe_url, #unauth)

  local remediation = "Add an explicit `security:` block to every operation that should require "
    .. "authentication, or set a global `security:` default at the document root that those operations "
    .. "inherit. "
    .. "For operations that are genuinely meant to be public (a health probe, a login endpoint), document "
    .. "the intent with `security: []` so the reader can tell at a glance that the empty requirement is "
    .. "deliberate rather than an oversight. "
    .. "Audit the listed operations against the application's authentication middleware - the spec and "
    .. "the runtime can diverge, and either side of the divergence is a finding."

  local parts = { "authless-operations" }
  for _, p in ipairs(id_parts) do parts[#parts + 1] = p end

  return {
    severity    = ctx.severity.medium,
    target      = facts.probe_url,
    url         = facts.probe_url,
    title       = "OpenAPI spec declares auth schemes but exposes unauthenticated operations",
    detail      = detail,
    details     = details,
    cwe         = "CWE-306",
    owasp       = "A01:2021 Broken Access Control",
    remediation = remediation,
    evidence    = build_evidence(ctx, facts),
    dedupe_key  = ctx.dedupe.key {
      check  = check.name,
      scope  = "host",
      target = facts.probe_url,
      parts  = parts,
    },
  }
end

-- restamp_to_page mirrors Go's restampFindings: the audit builds each
-- finding against the discovery probe URL (so the dedupe key keys off
-- the canonical resource) but we re-stamp Target / URL to the current
-- page so the report ties to a URL the operator visited.
local function restamp_to_page(findings, page_url)
  for _, f in ipairs(findings) do
    f.target = page_url
    f.url    = page_url
  end
end

function check.run(ctx)
  local facts, err = ctx.openapi.discover(ctx.page.url)
  if err then
    ctx:report("openapi-audit: " .. err)
    return nil
  end
  if facts == nil then return nil end

  local findings = {}
  local f1 = finding_embedded_credentials(ctx, facts)
  if f1 then findings[#findings + 1] = f1 end
  local f2 = finding_example_auth_tokens(ctx, facts)
  if f2 then findings[#findings + 1] = f2 end
  local f3 = finding_authless_operations(ctx, facts)
  if f3 then findings[#findings + 1] = f3 end

  if #findings == 0 then return nil end
  restamp_to_page(findings, ctx.page.url)
  return findings
end

return check
