-- race-condition: probes idempotency-sensitive endpoints for time-
-- of-check / time-of-use bugs by firing N HTTP/1.1 requests through
-- separate TCP connections that all release their final body byte at
-- the same instant. Variance in the resulting HTTP status histogram
-- (>=2 distinct status codes with at least one 2xx) is the racy half
-- of a check-then-act split.
--
-- The scan algorithm (raw-socket dial, single-packet barrier, status
-- capture) lives behind ctx.race.scan, which returns a list of raw
-- facts; this file iterates the facts, decides which represent a
-- race signal, composes the finding text, and shapes the dedupe key.
--
-- Level: Aggressive; loads only when the operator opts in via
-- --pollute. The probe issues N parallel state-mutating requests
-- against the target, which by construction is noisy and leaves N
-- side effects on a vulnerable endpoint.

local check = {
  name        = "race-condition",
  level       = "aggressive",
  scope       = "page",
  cwe         = "CWE-362",
  owasp       = "A04:2021 Insecure Design",
  remediation = "Wrap the racy operation in a transaction with a unique constraint or row-level lock so the "
    .. "check-then-act window cannot interleave. For coupon / voucher / one-shot resources, store a 'consumed' "
    .. "marker on the resource and use an atomic compare-and-set ('UPDATE ... WHERE consumed=0' returning the "
    .. "row count) instead of a SELECT-then-UPDATE. For vote / like / follow toggles, enforce uniqueness with "
    .. "a (user_id, target_id) unique index and treat duplicate-key errors as the idempotent 'already done' "
    .. "response. For account-creation flows, lean on the database's uniqueness constraint rather than an "
    .. "application-level SELECT-then-INSERT.",
  budget_seconds = 300,
  pollute = true,
}

-- title_path returns a short path label for the finding title. The
-- Detail field carries the full URL; the title only needs enough
-- path to disambiguate one endpoint from another on the same host.
local function title_path(ctx, raw_url)
  local u, err = ctx.url.parse(raw_url)
  if err or not u then return raw_url end
  if u.path == "" then return "/" end
  return u.path
end

-- histogram_string renders a status-count map as "200x7 409x3"
-- sorted by status code for readability.
local function histogram_string(counts)
  -- counts is a table indexed by status (number). Lua's ipairs would
  -- skip non-contiguous numeric keys, so iterate via pairs and sort
  -- the keys ourselves.
  local keys = {}
  for k in pairs(counts) do keys[#keys + 1] = k end
  if #keys == 0 then return "(no responses)" end
  table.sort(keys)
  local parts = {}
  for _, k in ipairs(keys) do
    parts[#parts + 1] = string.format("%dx%d", k, counts[k])
  end
  return table.concat(parts, " ")
end

-- evaluate_fact applies the race oracle to the raw per-target probe
-- data. Returns (vulnerable, status_counts, body_variety, failures,
-- reason). Three gates fire:
--
--   1. At least 2 probes must have completed (Status != 0, no Err).
--   2. The completed set must show >= 2 distinct status codes.
--   3. At least one status in the set must be 2xx (a no-2xx batch
--      points at a uniform rejection, not a racy success path).
--
-- Reason is human-readable so the per-finding bullets can quote it
-- either way.
local function evaluate_fact(fact)
  local counts = {}
  local bodies = {}
  local body_variety = 0
  local complete = 0
  local failures = 0
  local has_success = false
  for _, p in ipairs(fact.probes) do
    if p.err ~= "" then
      failures = failures + 1
    elseif p.status > 0 then
      complete = complete + 1
      counts[p.status] = (counts[p.status] or 0) + 1
      if p.body_hash ~= "" and not bodies[p.body_hash] then
        bodies[p.body_hash] = true
        body_variety = body_variety + 1
      end
      if p.status >= 200 and p.status < 300 then
        has_success = true
      end
    end
  end

  local distinct = 0
  for _ in pairs(counts) do distinct = distinct + 1 end

  if complete < 2 then
    return false, counts, body_variety, failures,
      string.format("only %d/%d probes completed", complete, #fact.probes)
  end
  if distinct < 2 then
    local sole
    for k in pairs(counts) do sole = k end
    return false, counts, body_variety, failures,
      string.format("all %d probes returned status %d (no variance)", complete, sole)
  end
  if not has_success then
    return false, counts, body_variety, failures,
      "status variance present but no 2xx response in the batch"
  end
  return true, counts, body_variety, failures,
    string.format("baseline status=%d; parallel batch produced %d distinct status codes",
      fact.baseline_status, distinct)
end

-- compose_finding lifts a vulnerable fact into the finding shape.
local function compose_finding(ctx, fact, counts, body_variety, failures)
  local stat_list = histogram_string(counts)
  local title = string.format("Race condition signal in %s %s",
    fact.method, title_path(ctx, fact.url))
  local detail = string.format(
    "The endpoint at %s %s produced different HTTP status codes when %d identical requests were "
    .. "landed within a sub-millisecond arrival window via a single-packet attack (status histogram: %s; "
    .. "baseline status=%d; %d connections failed to participate). A properly idempotent endpoint returns "
    .. "the same status for every duplicate (cached result or a consistent 'already done' error); status "
    .. "variance under parallel pressure is the racy half of a check-then-act split.\n\n"
    .. "Severity is fixed at Medium because the business impact (double-redeem, double-spend, vote stuffing, "
    .. "duplicate account creation) depends on what the endpoint does - confirm impact manually and grade "
    .. "the finding higher when the racy operation moves money or violates a uniqueness constraint.",
    fact.method, fact.url, #fact.probes - failures, stat_list, fact.baseline_status, failures)
  local details = {
    "target source: " .. fact.source,
    string.format("baseline response status: %d", fact.baseline_status),
    string.format("parallel batch size: %d (failures: %d)", #fact.probes, failures),
    "status histogram: " .. stat_list,
    string.format("response-body variety: %d distinct response hashes", body_variety),
    "reproduce with Burp's Repeater + Send group in parallel (single-packet attack), or any HTTP/2 client that supports parallel streams on one connection",
  }
  return {
    severity     = ctx.severity.medium,
    target       = ctx.page.url,
    url          = fact.url,
    title        = title,
    detail       = detail,
    details      = details,
    evidence     = ctx.evidence.build {
      method  = fact.method,
      url     = fact.url,
      status  = fact.baseline_status,
      snippet = stat_list,
    },
    -- Method tag + body-hash key so the same target across crawled
    -- pages collapses, but a different body on the same URL fires its
    -- own finding.
    dedupe_parts = {
      "method:" .. fact.method,
      "body:"   .. fact.target_key,
    },
  }
end

function check.run(ctx)
  local facts, err = ctx.race.scan()
  if err then return nil, err end
  if facts == nil or #facts == 0 then return nil end

  local findings = {}
  for _, fact in ipairs(facts) do
    local vulnerable, counts, body_variety, failures = evaluate_fact(fact)
    if vulnerable then
      findings[#findings + 1] = compose_finding(ctx, fact, counts, body_variety, failures)
    end
  end
  return findings
end

return check
