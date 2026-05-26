-- graphql-audit: Lua port of internal/checks/graphql_audit.go.
--
-- Two probe families per discovered GraphQL endpoint:
--
-- Configuration exposures (LevelDefault):
--   1. Introspection enabled (Medium): __schema query returns the full
--      type system, every resolver name, every argument shape.
--   2. Field suggestions enabled (Low): mistyped fields surface
--      "Did you mean..." hints that leak schema piecemeal.
--   3. Query batching accepted (Medium): JSON array of operations
--      executes per-element, bypassing per-request rate limits.
--   4. Alias amplification (Medium): one query calls the same field
--      N times via aliases; same lever as batching inside one op.
--
-- Active exploitation probes (LevelAggressive; each lands in the
-- target's auth / DoS-mitigation logs as a real attack):
--   5. Alias-based auth bypass (High): N aliases of the credential-
--      check mutation in one HTTP request.
--   6. Batched mutations (High): HTTP-level array of mutation ops
--      processed per-element.
--   7. Query-depth limit not enforced (Medium): depth-8 nested
--      introspection chain resolves without rejection.
--
-- Gate: already-fetched body / response-header GraphQL fingerprint, OR
-- path-keyword match + a one-shot discovery POST. Pages that match
-- neither cost zero requests.

local check = {
  name  = "graphql-audit",
  level = "default",
  scope = "page",
}

local BODY_CAP = 64 * 1024
local ALIAS_COUNT = 10
local ALIAS_AUTH_COUNT = 5
local BATCH_MUTATION_COUNT = 3
local DEPTH_LEVELS = 8

local LOGIN_MUTATION_CANDIDATES = {
  "login", "signIn", "authenticate", "loginUser", "userLogin",
  "signin", "logIn", "verifyOtp", "requestPasswordReset",
}

local GRAPHQL_PATHS = {
  "/graphql", "/graphiql", "/playground", "/altair",
  "/api/graphql", "/v1/graphql", "/v2/graphql",
  "/api/v1/graphql", "/api/v2/graphql",
}

local GRAPHQL_BODY_MARKERS = {
  "graphiql", "apollo sandbox", "embeddable-explorer", "embeddable-sandbox",
  "graphql playground", "prisma-cloud", "yoga graphql", "graphql-yoga",
  "altair graphql", "must provide query", "must provide a query",
  "must provide an operation",
}

-- looks_graphql_path returns true when path matches one of the
-- canonical GraphQL conventions, case-insensitive, accepting suffix or
-- mid-path segment match.
local function looks_graphql_path(path)
  local low = path:lower()
  for _, suffix in ipairs(GRAPHQL_PATHS) do
    if low == suffix
       or low:sub(-#suffix) == suffix
       or low:find(suffix .. "/", 1, true) ~= nil then
      return true
    end
  end
  return false
end

-- page_body_looks_graphql case-insensitively scans the first 64 KiB of
-- body for one of the GraphiQL / Apollo / Yoga / Playground / error-
-- envelope phrases that uniquely identify a GraphQL endpoint.
local function page_body_looks_graphql(body)
  if body == nil or body == "" then return false end
  local scan = body
  if #scan > BODY_CAP then scan = scan:sub(1, BODY_CAP) end
  local low = scan:lower()
  for _, m in ipairs(GRAPHQL_BODY_MARKERS) do
    if low:find(m, 1, true) ~= nil then return true end
  end
  return false
end

-- page_headers_look_graphql returns true when any header name starts
-- with `x-hasura-`. Headers userdata exposes :names() so the prefix
-- scan walks the canonical names net/http already produced.
local function page_headers_look_graphql(headers)
  if headers == nil then return false end
  for _, name in ipairs(headers:names()) do
    if name:lower():sub(1, 9) == "x-hasura-" then return true end
  end
  return false
end

-- post_json POSTs payload (encoded via ctx.json.encode) and returns
-- (body_string, status, request, response, truncated, err). Response
-- body capped at BODY_CAP so a chatty introspection doesn't pin the
-- worker.
local function post_json(ctx, target, payload)
  local raw, jerr = ctx.json.encode(payload)
  if jerr then return nil, 0, nil, nil, false, jerr end
  local req, mut_err = ctx.client:new_request {
    method = "POST",
    url    = target,
    body   = raw,
    headers = {
      ["Content-Type"] = "application/json",
      ["Accept"]       = "application/json",
    },
  }
  if mut_err then return nil, 0, nil, nil, false, mut_err end
  local resp, do_err = ctx.client["do"](ctx.client, req)
  if do_err then return nil, 0, req, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return nil, 0, req, resp, false, rerr end
  return body, resp:status(), req, resp, truncated, nil
end

-- snippet_json returns a trimmed-and-capped rendering of body for
-- finding evidence. Matches the Go check's 512-byte cap so report
-- text byte-aligns across implementations.
local function snippet_json(body)
  if body == nil then return "" end
  local out = body:gsub("^%s+", ""):gsub("%s+$", "")
  if #out > 512 then out = out:sub(1, 512) end
  return out
end

-- graphql_shape_matches returns true when body parses as a JSON
-- object carrying "data" or "errors" at the top level. Used by
-- discovery to confirm we reached a GraphQL parser.
local function graphql_shape_matches(ctx, body)
  local doc = ctx.json.decode(body)
  if type(doc) ~= "table" then return false end
  return doc.data ~= nil or doc.errors ~= nil
end

-- introspection_enabled reports whether body carries
-- data.__schema = <non-null object>. A null data.__schema (the server
-- accepted the envelope but rejected the query) is not a hit.
local function introspection_enabled(ctx, body)
  local doc = ctx.json.decode(body)
  if type(doc) ~= "table" then return false end
  local data = doc.data
  if type(data) ~= "table" then return false end
  return type(data.__schema) == "table"
end

-- suggestions_leaked returns true when body contains "did you mean"
-- in any case.
local function suggestions_leaked(body)
  if body == nil then return false end
  return body:lower():find("did you mean", 1, true) ~= nil
end

-- is_json_array distinguishes a sequence-shape table (JSON array)
-- from a string-keyed table (JSON object) after ctx.json.decode.
-- The # operator returns 0 on string-keyed tables and is undefined
-- on tables with holes, so callers that need to walk an array must
-- gate on this before trusting #t. Probing arr[1] is enough because
-- the json decoder writes contiguous keys starting at 1 for arrays.
local function is_json_array(t)
  return type(t) == "table" and t[1] ~= nil
end

-- batch_accepted returns true when body is a JSON array of >= 2
-- elements where every element carries "data" or "errors".
local function batch_accepted(ctx, body)
  local arr = ctx.json.decode(body)
  if not is_json_array(arr) then return false end
  local n = #arr
  if n < 2 then return false end
  for i = 1, n do
    local elem = arr[i]
    if type(elem) ~= "table" then return false end
    if elem.data == nil and elem.errors == nil then return false end
  end
  return true
end

-- alias_response_count returns the number of distinct alias keys
-- present in response.data, or 0 when the doc is malformed.
local function alias_response_count(ctx, body)
  local doc = ctx.json.decode(body)
  if type(doc) ~= "table" then return 0 end
  local data = doc.data
  if type(data) ~= "table" then return 0 end
  local n = 0
  for _ in pairs(data) do n = n + 1 end
  return n
end

-- per_alias_resolve_count counts data keys first, then falls back to
-- counting unique leading errors[].path segments. Mirrors the Go
-- perAliasResolveCount: a single global validation error has empty
-- path and does not count.
local function per_alias_resolve_count(ctx, body)
  local doc = ctx.json.decode(body)
  if type(doc) ~= "table" then return 0 end
  local data = doc.data
  if type(data) == "table" then
    local n = 0
    for _ in pairs(data) do n = n + 1 end
    if n > 0 then return n end
  end
  local errs = doc.errors
  if type(errs) ~= "table" then return 0 end
  local seen = {}
  for i = 1, #errs do
    local e = errs[i]
    if type(e) == "table" and type(e.path) == "table" and #e.path > 0 then
      seen[tostring(e.path[1])] = true
    end
  end
  local m = 0
  for _ in pairs(seen) do m = m + 1 end
  return m
end

-- element_references_field returns true when a per-batch response
-- element shows evidence the server invoked field for that element:
-- either data is a non-null object containing field as a key, or
-- errors[].path[0] equals field.
local function element_references_field(elem, field)
  if type(elem) ~= "table" then return false end
  if type(elem.data) == "table" then
    if elem.data[field] ~= nil then return true end
  end
  if type(elem.errors) == "table" then
    for i = 1, #elem.errors do
      local e = elem.errors[i]
      if type(e) == "table" and type(e.path) == "table" then
        for j = 1, #e.path do
          if tostring(e.path[j]) == field then return true end
        end
      end
    end
  end
  return false
end

-- batch_mutations_executed mirrors the Go batchMutationsExecuted:
-- array of >= 2 elements where every elem has data / errors AND >= 2
-- reference field by data key or errors[].path.
local function batch_mutations_executed(ctx, body, field)
  local arr = ctx.json.decode(body)
  if not is_json_array(arr) or #arr < 2 then return false end
  local executed = 0
  for i = 1, #arr do
    local elem = arr[i]
    if type(elem) ~= "table" then return false end
    if elem.data == nil and elem.errors == nil then return false end
    if element_references_field(elem, field) then
      executed = executed + 1
    end
  end
  return executed >= 2
end

-- depth_resolved returns true when the response carries evidence the
-- server actually traversed the nested ofType chain to the requested
-- depth, and no error message names depth / complexity rejection or
-- "introspection disabled".
local function depth_resolved(ctx, body, requested)
  local doc = ctx.json.decode(body)
  if type(doc) == "table" and type(doc.errors) == "table" then
    for i = 1, #doc.errors do
      local e = doc.errors[i]
      if type(e) == "table" and type(e.message) == "string" then
        local low = e.message:lower()
        if low:find("depth", 1, true) or low:find("too deep", 1, true)
           or low:find("complexity", 1, true) or low:find("exceeds", 1, true)
           or low:find("introspection", 1, true) then
          return false
        end
      end
    end
  end
  -- Count "oftype" occurrences in the lowercased body.
  local low = body:lower()
  local count = 0
  local pos = 1
  while true do
    local i = low:find("oftype", pos, true)
    if i == nil then break end
    count = count + 1
    pos = i + 6
  end
  return count >= requested
end

-- build_alias_auth_query mirrors checks.buildAliasAuthQuery: a mutation
-- that aliases count calls of field with a __typename sub-selection
-- (works for both object-return and scalar-return resolvers).
local function build_alias_auth_query(field, count)
  local parts = { "mutation AuthBypass {" }
  for i = 0, count - 1 do
    if i > 0 then parts[#parts + 1] = " " end
    parts[#parts + 1] = string.format(
      ' a%d: %s(email:"probe%d@hyperz.invalid", password:"hyperz-probe") { __typename }',
      i, field, i)
  end
  parts[#parts + 1] = " }"
  return table.concat(parts)
end

-- build_mutation_batch returns the JSON-array body for the batched
-- mutation probe.
local function build_mutation_batch(field, count)
  local out = {}
  for i = 0, count - 1 do
    local q = string.format(
      'mutation { %s(email:"batch%d@hyperz.invalid", password:"hyperz-probe") { __typename } }',
      field, i)
    out[#out + 1] = { query = q }
  end
  return out
end

-- build_depth_query nests `levels` ofType selections through the
-- universally-available __schema -> types -> fields -> type chain.
local function build_depth_query(levels)
  local parts = { "query DepthProbe { __schema { types { fields { type" }
  for _ = 1, levels do parts[#parts + 1] = " { ofType" end
  parts[#parts + 1] = " { name }"
  for _ = 1, levels do parts[#parts + 1] = " }" end
  parts[#parts + 1] = " } } } }"
  return table.concat(parts)
end

-- discover sends `{__typename}` and returns true when the response
-- looks like a GraphQL reply (data or errors at top level). One probe.
local function discover(ctx, target)
  local body, status = post_json(ctx, target, { query = "{__typename}" })
  if body == nil or status == 0 then return false end
  return graphql_shape_matches(ctx, body)
end

-- evidence_for builds the evidence userdata for a finding from a
-- request/response/body triple plus an explicit snippet.
local function evidence_for(ctx, req, resp, body)
  return ctx.evidence.from_exchange {
    request  = req,
    response = resp,
    body     = body,
    snippet  = snippet_json(body),
  }
end

local function probe_introspection(ctx, target)
  local query = 'query IntrospectionQuery { __schema { queryType { name } types { name kind } } }'
  local body, status, req, resp, _, err = post_json(ctx, target, { query = query })
  if err then return nil, err end
  if not introspection_enabled(ctx, body) then return nil end
  return {
    severity = ctx.severity.medium,
    target   = target,
    url      = target,
    title    = "GraphQL introspection enabled",
    detail   = "The endpoint responded to a __schema introspection query with the full type system. "
      .. "An attacker can enumerate every resolver name, argument shape, and return type without authentication, "
      .. "dramatically lowering the bar for finding privileged mutations, hidden fields, and injection-prone arguments. "
      .. "Introspection is a development convenience; production gateways should disable it.",
    cwe   = "CWE-200",
    owasp = "A05:2021 Security Misconfiguration",
    remediation = "Disable introspection on production GraphQL endpoints. Apollo Server: set introspection: false. "
      .. "GraphQL Yoga: pass disableIntrospection or the graphql-armor plugin. Hot Chocolate (.NET): RemoveAllowedDefinitions or "
      .. "the AddIntrospectionAllowedFor configuration. If a tooling client legitimately needs the schema, ship a static "
      .. "schema.graphql artifact rather than exposing live introspection.",
    evidence = evidence_for(ctx, req, resp, body),
    dedupe_parts = { "introspection" },
    _status = status,
  }
end

local function probe_suggestions(ctx, target)
  local body, status, req, resp, _, err = post_json(ctx, target, { query = '{ usre { id } }' })
  if err then return nil, err end
  if not suggestions_leaked(body) then return nil end
  return {
    severity = ctx.severity.low,
    target   = target,
    url      = target,
    title    = "GraphQL field suggestions enabled",
    detail   = "The endpoint returned 'Did you mean ...' suggestions for a mistyped field. "
      .. "Field suggestions reveal real schema names piecemeal even when introspection is disabled - an attacker can "
      .. "reconstruct the schema by querying near-miss names. Suggestions exist for developer ergonomics; production "
      .. "endpoints should suppress them so the introspection-off configuration is not undermined.",
    cwe   = "CWE-200",
    owasp = "A05:2021 Security Misconfiguration",
    remediation = "Disable field suggestions on production. Apollo Server v4: use the NoSuggestionsValidationRule from "
      .. "graphql-armor or configure the GraphQL validation pipeline to strip the FieldsOnCorrectType message. "
      .. "For other servers, configure the validation layer to suppress 'Did you mean ...' hints in non-development environments.",
    evidence = evidence_for(ctx, req, resp, body),
    dedupe_parts = { "suggestions" },
    _status = status,
  }
end

local function probe_batch(ctx, target)
  local payload = {
    { query = "{__typename}" },
    { query = "{__typename}" },
  }
  local body, status, req, resp, _, err = post_json(ctx, target, payload)
  if err then return nil, err end
  if not batch_accepted(ctx, body) then return nil end
  return {
    severity = ctx.severity.medium,
    target   = target,
    url      = target,
    title    = "GraphQL query batching accepted",
    detail   = "The endpoint accepted a batched array of two operations and returned an array of responses. "
      .. "Unrestricted batching lets a caller multiply server-side work without paying for distinct HTTP round trips, "
      .. "undermines per-request rate limiting, and amplifies any expensive resolver. When combined with aliasing it "
      .. "becomes a practical denial-of-service lever.",
    cwe   = "CWE-770",
    owasp = "A04:2021 Insecure Design",
    remediation = "Disable batching unless required, or cap the array length and reject oversize batches at the parser. "
      .. "Apollo Server: set allowBatchedHttpRequests: false (v4) or configure the BatchHttpLink rejection on the gateway. "
      .. "Yoga / Helix: configure the batching plugin to enforce a maxBatchSize. Combine with query-complexity limits so "
      .. "a small batch cannot still amplify expensive resolvers.",
    evidence = evidence_for(ctx, req, resp, body),
    dedupe_parts = { "batch" },
    _status = status,
  }
end

local function probe_alias(ctx, target)
  local parts = { "{" }
  for i = 0, ALIAS_COUNT - 1 do
    if i > 0 then parts[#parts + 1] = " " end
    parts[#parts + 1] = string.format("a%d:__typename", i)
  end
  parts[#parts + 1] = "}"
  local query = table.concat(parts)
  local body, status, req, resp, _, err = post_json(ctx, target, { query = query })
  if err then return nil, err end
  local got = alias_response_count(ctx, body)
  if got < ALIAS_COUNT then return nil end
  return {
    severity = ctx.severity.medium,
    target   = target,
    url      = target,
    title    = string.format("GraphQL alias amplification accepted (%d aliases per query)", got),
    detail   = string.format(
      "The endpoint resolved a query containing %d alias calls of the same field in one operation. "
        .. "Aliases let a caller execute the same resolver many times inside a single HTTP request, "
        .. "amplifying expensive operations and bypassing per-field rate limits. On login or token "
        .. "endpoints this turns into password / OTP brute-forcing at the alias-per-request rate; on "
        .. "data-heavy resolvers it is a denial-of-service lever.", got),
    cwe   = "CWE-770",
    owasp = "A04:2021 Insecure Design",
    remediation = "Cap the alias count per operation at the GraphQL gateway. graphql-armor's MaxAliasesRule sets a hard limit; "
      .. "Apollo and Yoga can install a custom validation rule that walks the AST and rejects operations exceeding the cap. "
      .. "Combine with query-complexity limits and per-resolver rate limits so the cap is enforced even when one alias still "
      .. "reaches an expensive field.",
    evidence = evidence_for(ctx, req, resp, body),
    dedupe_parts = { "alias" },
    _status = status,
  }
end

local function probe_alias_auth_bypass(ctx, target)
  for _, field in ipairs(LOGIN_MUTATION_CANDIDATES) do
    local query = build_alias_auth_query(field, ALIAS_AUTH_COUNT)
    local body, status, req, resp, _, err = post_json(ctx, target, { query = query })
    if err then return nil, err end
    local got = per_alias_resolve_count(ctx, body)
    if got >= ALIAS_AUTH_COUNT then
      return {
        severity = ctx.severity.high,
        target   = target,
        url      = target,
        title    = string.format(
          "GraphQL alias-based auth bypass on %s (%d resolver invocations per HTTP request)", field, got),
        detail = string.format(
          "A single mutation aliasing %d calls of %s was resolved %d times in one HTTP request. "
            .. "Rate limits that count HTTP requests on the credential-check mutation do not bound the number of "
            .. "actual credential checks the server performs, so an attacker can multiply password / OTP attempts by "
            .. "the alias count without sending additional requests. This is the canonical lever used to defeat "
            .. "'N attempts per minute' policies on login, password-reset, and MFA-verification mutations.",
          ALIAS_AUTH_COUNT, field, got),
        cwe   = "CWE-307",
        owasp = "A07:2021 Identification and Authentication Failures",
        remediation = "Enforce credential-check rate limits at the resolver layer, not at the HTTP request boundary. "
          .. "Install a validation rule that caps aliases per operation (graphql-armor's MaxAliasesRule, or a custom rule "
          .. "that walks the AST and rejects more than one alias for sensitive mutations - login, signIn, authenticate, "
          .. "requestPasswordReset, verifyOtp, charge). For Apollo Server v4 the rule plugs into the validationRules array; "
          .. "Yoga / Helix expose the same hook on the schema construction.",
        evidence = evidence_for(ctx, req, resp, body),
        dedupe_parts = { "alias-auth-bypass", field },
        _status = status,
      }
    end
  end
  return nil
end

local function probe_batch_mutations(ctx, target)
  for _, field in ipairs(LOGIN_MUTATION_CANDIDATES) do
    local payload = build_mutation_batch(field, BATCH_MUTATION_COUNT)
    local body, status, req, resp, _, err = post_json(ctx, target, payload)
    if err then return nil, err end
    if batch_mutations_executed(ctx, body, field) then
      return {
        severity = ctx.severity.high,
        target   = target,
        url      = target,
        title    = string.format("GraphQL batched mutations accepted (%s)", field),
        detail = string.format(
          "An HTTP-level batch array of %d %s mutations was processed and returned an array of independent "
            .. "per-element responses. Batched mutations bypass any rate limit that counts HTTP requests on state-"
            .. "changing operations: one POST equals N credential checks, N account creations, N payment attempts, "
            .. "or N of whatever the mutation does. When combined with the alias-based auth-bypass lever the "
            .. "amplification compounds (N batch entries * M aliases per entry = N*M attempts per request).",
          BATCH_MUTATION_COUNT, field),
        cwe   = "CWE-770",
        owasp = "A04:2021 Insecure Design",
        remediation = "Reject HTTP-level batching for mutation operations. Apollo Server v4: set allowBatchedHttpRequests: "
          .. "false to disable batching wholesale, or wrap the gateway with a filter that rejects array-shaped POST bodies "
          .. "whose elements include a mutation operation. For servers that legitimately batch queries, gate mutations at "
          .. "the resolver layer with a per-resolver rate counter so the limit is independent of the HTTP boundary. Pair "
          .. "with graphql-armor's MaxAliasesRule so the alias-amplification path stays closed.",
        evidence = evidence_for(ctx, req, resp, body),
        dedupe_parts = { "batch-mutations", field },
        _status = status,
      }
    end
  end
  return nil
end

local function probe_depth(ctx, target)
  local query = build_depth_query(DEPTH_LEVELS)
  local body, status, req, resp, _, err = post_json(ctx, target, { query = query })
  if err then return nil, err end
  if not depth_resolved(ctx, body, DEPTH_LEVELS) then return nil end
  return {
    severity = ctx.severity.medium,
    target   = target,
    url      = target,
    title    = string.format("GraphQL query-depth limit not enforced (depth %d resolved)", DEPTH_LEVELS),
    detail = string.format(
      "A query nested %d levels deep through the introspection ofType chain resolved without rejection. "
        .. "GraphQL has no inherent depth cap; on schemas with self-referential connections (User.friends.friends, "
        .. "Post.comments.author.posts, organisation.members.organisation.members...) an attacker can craft a query "
        .. "whose resolver count grows geometrically with depth, which is the canonical CPU / database-burn lever. "
        .. "Combined with field aliasing the cost compounds: a depth-D query with K aliases at each level invokes "
        .. "O(K^D) resolvers from one HTTP request.", DEPTH_LEVELS),
    cwe   = "CWE-770",
    owasp = "A04:2021 Insecure Design",
    remediation = "Configure a maximum query depth at the gateway. graphql-armor's MaxDepthRule and the standalone "
      .. "graphql-depth-limit package both expose a hard cap (a typical safe range is 5-10, depending on how deep "
      .. "legitimate clients legitimately nest). Pair with a query-complexity scoring rule (graphql-armor's CostLimitRule, "
      .. "graphql-cost-analysis) so a shallow query that fans out via aliases or large list arguments is still rejected "
      .. "on cost grounds even when its depth is in bounds.",
    evidence = evidence_for(ctx, req, resp, body),
    dedupe_parts = { "depth" },
    _status = status,
  }
end

-- run_probe wraps a probe function with the report-on-error pattern
-- the Go check uses. Returns the finding table (with _status stripped)
-- or nil; errors get reported via ctx:report rather than propagated.
local function run_probe(ctx, target, name, fn, findings)
  local f, err = fn(ctx, target)
  if err then
    ctx:report(string.format("graphql-audit %s %s: %s", name, target, err))
    return
  end
  if f == nil then return end
  f._status = nil
  findings[#findings + 1] = f
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or u == nil or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  -- Two-tier gate: body / header fingerprint wins zero-cost; otherwise
  -- path heuristic + discovery POST.
  local page_evidence = page_body_looks_graphql(ctx.page.body)
                        or page_headers_look_graphql(ctx.page.headers)
  if not page_evidence then
    if not looks_graphql_path(u.path) then return nil end
    if not discover(ctx, ctx.page.url) then return nil end
  end

  local findings = {}
  run_probe(ctx, ctx.page.url, "introspection",    probe_introspection,    findings)
  run_probe(ctx, ctx.page.url, "suggestions",      probe_suggestions,      findings)
  run_probe(ctx, ctx.page.url, "batch",            probe_batch,            findings)
  run_probe(ctx, ctx.page.url, "alias",            probe_alias,            findings)

  if not ctx:level_at_least("aggressive") then
    if #findings == 0 then return nil end
    return findings
  end

  run_probe(ctx, ctx.page.url, "alias-auth-bypass", probe_alias_auth_bypass, findings)
  run_probe(ctx, ctx.page.url, "batch-mutations",   probe_batch_mutations,   findings)
  run_probe(ctx, ctx.page.url, "depth",             probe_depth,             findings)

  if #findings == 0 then return nil end
  return findings
end

return check
