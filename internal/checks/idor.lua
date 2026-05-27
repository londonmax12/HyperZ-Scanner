-- idor: probes identifier-shaped sinks for Insecure Direct Object
-- Reference flaws by tampering with values whose shape suggests a
-- resource reference (numeric, UUID, mongoid, slug, email, username,
-- hex, base64ish, or a learned cross-scan shape) and watching for a
-- response divergence that survives the false-positive backstop.
--
-- Per sink, three probes in series:
--
--   1. Baseline: the request as the crawler observed it. Must return
--      a 2xx body of at least MIN_BASELINE_BODY bytes; otherwise the
--      sink is skipped (no content to compare against).
--   2. Control: same request with a guaranteed-garbage value of the
--      same shape (ctx.idor.control_payload). The false-positive
--      backstop - if the app returns ~baseline for any garbage ID,
--      the endpoint either ignores the parameter or rendered a SPA
--      shell, and ctx.idor.judge suppresses.
--   3. Tampered: up to MAX_TAMPERED_PROBES candidates from
--      corpus:generate. First payload to trigger a Vulnerable
--      verdict ends the sink's probe loop.
--
-- The corpus is scan-lifetime: ctx.idor.corpus() returns the same
-- instance for every Run on this LuaCheck so one Corpus stays alive
-- across the whole scan. Pages ingest their values before any probe
-- runs so the page's own values are available as tampering
-- candidates for sibling sinks on the same page.
--
-- All findings ship at Severity High - cross-tenant confirmation
-- requires a second authenticated context which hyperz doesn't have
-- today, so the check tops out below Critical.

local check = {
  name        = "idor",
  level       = "aggressive",
  scope       = "param",
  cwe         = "CWE-639",
  owasp       = "A01:2021 Broken Access Control",
  remediation = "Enforce object-level authorization on every request: verify the requesting principal owns or is "
                .. "otherwise permitted to access the identified resource before returning it. Prefer indirect references "
                .. "(per-session opaque tokens) or scoped lookups (`WHERE owner_id = current_user`) over trusting client-"
                .. "supplied IDs. Add automated tests that swap identifiers across users in CI so regressions cannot reach "
                .. "production unnoticed.",
  budget_seconds = 180,
  consumes    = {"page", "param"},
}

local BODY_CAP = 64 * 1024
local MAX_TAMPERED_PROBES = 3
local MAX_SINKS_PER_PAGE = 8
local MIN_BASELINE_BODY = 64

-- Params that look identifier-shaped on the wire but never carry
-- resource references.
local PARAM_DENYLIST = {
  q = true, query = true, search = true, s = true,
  page = true, limit = true, offset = true, count = true, size = true, per_page = true,
  sort = true, order = true, filter = true,
  lang = true, locale = true, format = true,
  csrf = true, _csrf = true, token = true, _token = true,
  hash = true, sig = true, signature = true, nonce = true,
  ["_"] = true, v = true, version = true, t = true, timestamp = true,
  callback = true, jsonp = true,
}

-- Only path-classifiable patterns are worth probing as path segments.
-- Email / username / slug in a path are usually SEO-friendly URLs
-- whose real ID lives in the query string.
local PATH_PATTERNS = {
  numeric = true, uuid = true, mongoid = true, hex = true,
}

local function is_2xx(status)
  return status >= 200 and status < 300
end

-- send issues one probe and returns request, snapshot {status,body},
-- response handle, body string, truncated bool. The response handle
-- is kept so the caller can pass it to ctx.evidence.from_exchange.
local function send(ctx, sink, payload)
  local req, mut_err = sink:mutate_request(payload)
  if mut_err then return nil, nil, nil, nil, false, mut_err end
  local resp, do_err = ctx.client["do"](ctx.client, req)
  if do_err then return req, nil, nil, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, nil, resp, nil, false, rerr end
  return req, { status = resp:status(), body = body }, resp, body, truncated, nil
end

-- candidate_for evaluates a sink against the corpus and returns a
-- candidate descriptor or nil. Header/cookie sinks are skipped (not
-- yet covered); denylist and pattern classification gate everything
-- else.
local function candidate_for(corpus, sink)
  if sink.loc == "header" or sink.loc == "cookie" then return nil end
  if PARAM_DENYLIST[string.lower(sink.name)] then return nil end
  local pat = corpus:classify(sink.name, sink.value)
  if not pat then return nil end
  return {
    sink         = sink,
    pattern_name = pat.name,
    precedence   = pat.precedence,
    learned      = pat.learned,
    path_segment = nil,
  }
end

-- collect_candidates returns the ordered, capped candidate list a
-- single Run probes. Sort precedence-desc, name-asc so cap-trim drops
-- the lowest-value candidates first.
local function collect_candidates(ctx, corpus)
  local out = {}
  for _, sink in ipairs(ctx.sinks.for_page{}) do
    local cand = candidate_for(corpus, sink)
    if cand then out[#out + 1] = cand end
  end
  for _, entry in ipairs(ctx.idor.path_sinks(ctx.page.url)) do
    out[#out + 1] = {
      sink         = entry.sink,
      pattern_name = entry.pattern,
      precedence   = entry.precedence,
      learned      = entry.learned,
      path_segment = string.format("path segment %d", entry.segment_index),
    }
  end
  table.sort(out, function(a, b)
    if a.precedence ~= b.precedence then return a.precedence > b.precedence end
    return a.sink.name < b.sink.name
  end)
  return out
end

local function loc_label(cand)
  if cand.path_segment then return cand.path_segment end
  return cand.sink.loc
end

local function pattern_label(cand)
  if cand.learned then return cand.pattern_name .. " (learned shape)" end
  return cand.pattern_name
end

local function tampered_bullet(payload, status, verdict, control_status)
  local s = string.format('tampered payload %q: status=%d sim-vs-baseline=%.3f',
    payload, status, verdict.tampered_sim)
  if is_2xx(control_status) then
    s = s .. string.format(' sim-vs-control=%.3f', verdict.tampered_control_sim)
  end
  return s
end

-- probe_sink runs the baseline / control / tampered triple. Returns
-- a finding table on a confirmed verdict, nil otherwise. Sub-probe
-- errors are reported but never short-circuit the sink loop;
-- transient single-probe failures must not silently disqualify the
-- whole candidate.
local function probe_sink(ctx, corpus, cand)
  local sink = cand.sink
  local seed = sink.value

  local _, base_snap, _, _, _, base_err = send(ctx, sink, seed)
  if base_err then
    ctx:report(string.format("idor baseline %s %s=%s: %s", sink.method, sink.name, seed, base_err))
    return nil
  end
  if not base_snap then return nil end
  if not is_2xx(base_snap.status) or #base_snap.body < MIN_BASELINE_BODY then return nil end

  local control_payload = ctx.idor.control_payload(cand.pattern_name, seed)
  local _, control_snap, _, _, _, ctrl_err = send(ctx, sink, control_payload)
  if ctrl_err then
    ctx:report(string.format("idor control %s %s=%s: %s", sink.method, sink.name, control_payload, ctrl_err))
    return nil
  end

  local tampered = corpus:generate(cand.pattern_name, seed, MAX_TAMPERED_PROBES)
  for _, payload in ipairs(tampered) do
    if payload ~= seed and payload ~= control_payload then
      local req, tamp_snap, tamp_resp, tamp_body, tamp_trunc, tamp_err = send(ctx, sink, payload)
      if tamp_err then
        ctx:report(string.format("idor tampered %s %s=%s: %s", sink.method, sink.name, payload, tamp_err))
      else
        local verdict = ctx.idor.judge(base_snap, tamp_snap, control_snap)
        if verdict.vulnerable then
          local loc = loc_label(cand)
          local title = string.format('Possible IDOR on %s parameter %q', loc, sink.name)
          local detail = string.format(
            'Tampering the %s value (classified as %s) altered the response in a way consistent with broken authorization: %s',
            loc, pattern_label(cand), verdict.detail)
          local details = {
            string.format('baseline: status=%d body=%dB', base_snap.status, #base_snap.body),
            string.format('control payload %q: status=%d sim-vs-baseline=%.3f',
              control_payload, control_snap.status, verdict.control_sim),
            tampered_bullet(payload, tamp_snap.status, verdict, control_snap.status),
            'confidence: ' .. verdict.confidence,
          }
          for _, hint in ipairs(verdict.pii_hints) do
            details[#details + 1] = 'tampered body PII marker: ' .. hint
          end
          local evidence = ctx.evidence.from_exchange {
            request   = req,
            response  = tamp_resp,
            body      = tamp_body,
            truncated = tamp_trunc,
          }
          return {
            severity     = ctx.severity.high,
            target       = ctx.page.url,
            url          = ctx.page.url,
            title        = title,
            detail       = detail,
            details      = details,
            evidence     = evidence,
            dedupe_parts = { sink.loc, sink.name },
          }
        end
      end
    end
  end
  return nil
end

function check.run(ctx)
  local corpus = ctx.idor.corpus()
  corpus:ingest_page()

  local candidates = collect_candidates(ctx, corpus)
  if #candidates == 0 then return nil end
  if #candidates > MAX_SINKS_PER_PAGE then
    ctx:report(string.format("idor: page %s exposed %d identifier sinks; capping at %d",
      ctx.page.url, #candidates, MAX_SINKS_PER_PAGE))
    local trimmed = {}
    for i = 1, MAX_SINKS_PER_PAGE do trimmed[i] = candidates[i] end
    candidates = trimmed
  end

  local findings = {}
  for _, cand in ipairs(candidates) do
    local f = probe_sink(ctx, corpus, cand)
    if f then findings[#findings + 1] = f end
  end
  return findings
end

return check
