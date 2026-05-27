-- proto-pollution: probes server-side prototype pollution in JS backends. Per
-- probable sink a bundled pollution payload installs three gadgets
-- (json-spaces, status, canary echo) on Object.prototype, then a clean
-- observer GET against the page URL witnesses any side effect. After
-- every probe a best-effort cleanup payload overwrites the gadget
-- values with neutral ones, regardless of detection outcome - the
-- pollution persists on the target's process and we want to minimize
-- its blast radius even on a no-signal probe.
--
-- Wire shapes:
--   * LocJSON: nested `{"__proto__":{...},"constructor":{"prototype":{...}}}`.
--   * LocQuery / LocForm: bracket-notation (`__proto__[json spaces]=7`,
--     `constructor[prototype][...]=...`) so qs / body-parser stacks
--     expand the payload into the same nested object on the backend.
--
-- Header / cookie / path sinks are not probed: their values are taken
-- as opaque strings and never reach a parser that expands brackets.
--
-- Verdict order (decreasing specificity): status -> json spaces ->
-- canary echo. Every gadget requires baseline absence so endpoints
-- that legitimately emit 510 / pretty-print at 7 spaces / echo the
-- canary cannot fire on their own behaviour.

local check = {
  name        = "proto-pollution",
  level       = "aggressive",
  scope       = "param",
  cwe         = "CWE-1321",
  owasp       = "A03:2021 Injection",
  remediation = "Reject or strip dangerous keys (`__proto__`, `constructor`, `prototype`) at the JSON / "
                .. "body / query parser boundary. Prefer `Object.create(null)` for any object that will be merged "
                .. "with user input. Avoid recursive-merge utilities (`lodash.merge`, hand-rolled deep-assign) on "
                .. "untrusted payloads; use schema-validated DTOs instead. As a defense in depth, freeze "
                .. "`Object.prototype` at process start with `Object.freeze(Object.prototype)` so even a missed "
                .. "sanitization step cannot mutate the shared prototype.",
  tier     = "active",
  consumes = {"page", "param"},
  pollute = true,
}

local BODY_CAP = 32 * 1024
local PROTO_JSON_SPACES = 7
local PROTO_STATUS = 510
local CLEANUP_TIMEOUT = 5

local function new_canary()
  local hex = "0123456789abcdef"
  local out = { "hpzc" }
  for _ = 1, 12 do
    local r = math.random(1, 16)
    out[#out + 1] = string.sub(hex, r, r)
  end
  return table.concat(out)
end

-- sink_probable: query / form / json are the only locs whose values
-- reach a bracket-expanding parser. Header / cookie / path values are
-- taken as opaque strings by every common framework.
local function sink_probable(sink, locs)
  return sink.loc == locs.query or sink.loc == locs.form or sink.loc == locs.json
end

-- observe issues a clean GET against pageURL and captures the slice
-- the verdict needs: status, content-type, body. No probe payload
-- rides on this request so the gadget hit cannot be confused with a
-- reflection of the pollution probe.
local function observe(ctx, target)
  local req, err = ctx.client:new_request{ method = "GET", url = target }
  if err then return nil, err end
  local resp, derr = ctx.client["do"](ctx.client, req)
  if derr then return nil, derr end
  local body, _, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return nil, rerr end
  return {
    status       = resp:status(),
    content_type = resp:headers():get("Content-Type"),
    body         = body,
  }, nil
end

-- pp_judge compares pre-pollution observer (baseline) against post-
-- pollution observer and decides whether any of the three gadgets
-- fired. Returns a verdict table with hit, gadget, detail, needle
-- fields; hit=false on no signal.
local function pp_judge(ctx, baseline, observer, canary_val)
  if observer.status == PROTO_STATUS and baseline.status ~= PROTO_STATUS then
    return {
      hit    = true,
      gadget = "status",
      detail = string.format(
        "clean observer GET returned status %d after pollution (baseline was %d); the polluted "
          .. "Object.prototype.status leaked into the response status default",
        observer.status, baseline.status),
      needle = tostring(PROTO_STATUS),
    }
  end

  if ctx.body.is_json_response(observer.content_type or "", observer.body) then
    local base_indent = ctx.body.json_indent_width(baseline.body)
    local obs_indent = ctx.body.json_indent_width(observer.body)
    if obs_indent == PROTO_JSON_SPACES and base_indent ~= PROTO_JSON_SPACES then
      return {
        hit    = true,
        gadget = "json spaces",
        detail = string.format(
          "clean observer GET returned JSON indented to %d spaces after pollution (baseline was %d); "
            .. "the polluted Object.prototype['json spaces'] is being read by res.json()",
          obs_indent, base_indent),
        needle = "\n" .. string.rep(" ", PROTO_JSON_SPACES),
      }
    end
  end

  if canary_val ~= ""
     and observer.body:find(canary_val, 1, true) ~= nil
     and baseline.body:find(canary_val, 1, true) == nil then
    return {
      hit    = true,
      gadget = "canary echo",
      detail = string.format(
        'clean observer GET body now contains the pollution canary %q (absent from baseline); '
          .. 'the polluted prototype property is being enumerated into the response',
        canary_val),
      needle = canary_val,
    }
  end

  return { hit = false }
end

-- build_bracket installs the bracket-notation gadgets onto a flat
-- name->string map. cleanup_mode switches the values to neutral
-- ("" for the canary, 0 for the integers) so a follow-up POST
-- overwrites the gadgets we just installed.
local function build_bracket(canary_key, canary_val, cleanup_mode)
  local val = canary_val
  local spaces = tostring(PROTO_JSON_SPACES)
  local status = tostring(PROTO_STATUS)
  if cleanup_mode then val = ""; spaces = "0"; status = "0" end
  local t = {}
  t["__proto__[" .. canary_key .. "]"] = val
  t["__proto__[json spaces]"] = spaces
  t["__proto__[status]"] = status
  t["constructor[prototype][" .. canary_key .. "]"] = val
  t["constructor[prototype][json spaces]"] = spaces
  t["constructor[prototype][status]"] = status
  return t
end

-- build_json_body installs the same three gadgets as a nested JSON
-- object. The {{__proto__, constructor.prototype}} duplication is so
-- the parsing layer at the target may filter one and accept the other.
local function build_json_body(canary_key, canary_val, cleanup_mode)
  local inner_val = canary_val
  local inner_spaces = PROTO_JSON_SPACES
  local inner_status = PROTO_STATUS
  if cleanup_mode then inner_val = ""; inner_spaces = 0; inner_status = 0 end
  return {
    ["__proto__"] = {
      [canary_key]    = inner_val,
      ["json spaces"] = inner_spaces,
      ["status"]      = inner_status,
    },
    ["constructor"] = {
      ["prototype"] = {
        [canary_key]    = inner_val,
        ["json spaces"] = inner_spaces,
        ["status"]      = inner_status,
      },
    },
  }
end

-- compose_query_url merges extra params into url's existing query
-- string and returns the rebuilt absolute URL.
local function compose_query_url(ctx, url_str, extra)
  local u, err = ctx.url.parse(url_str)
  if err or u == nil then return nil end
  local existing = ctx.url.query(url_str)
  if existing == nil then existing = {} end
  for k, v in pairs(extra) do existing[k] = v end
  local enc = ctx.url.encode_values(existing)
  local out = u.scheme .. "://" .. u.host .. u.path
  if enc ~= "" then out = out .. "?" .. enc end
  return out
end

-- build_request constructs the per-sink pollution OR cleanup request.
-- cleanup_mode switches the payload values to neutral ones. Returns
-- (request_userdata, nil) or (nil, err).
local function build_request(ctx, sink, canary_key, canary_val, cleanup_mode)
  local method = sink.method:upper()
  if method == "" then method = "POST" end

  if sink.loc == ctx.locs.query then
    local extra = build_bracket(canary_key, canary_val, cleanup_mode)
    local new_url = compose_query_url(ctx, sink.url, extra)
    if new_url == nil then return nil, "parse url failed" end
    return ctx.client:new_request{ method = method, url = new_url }
  end

  if sink.loc == ctx.locs.form then
    local body = build_bracket(canary_key, canary_val, cleanup_mode)
    local enc = ctx.url.encode_values(body)
    return ctx.client:new_request{
      method = method,
      url = sink.url,
      body = enc,
      headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    }
  end

  if sink.loc == ctx.locs.json then
    local body = build_json_body(canary_key, canary_val, cleanup_mode)
    local enc, jerr = ctx.json.encode(body)
    if jerr then return nil, jerr end
    return ctx.client:new_request{
      method = method,
      url = sink.url,
      body = enc,
      headers = { ["Content-Type"] = "application/json" },
    }
  end

  return nil, "unsupported sink loc " .. tostring(sink.loc)
end

-- probe runs the pollute / observe / cleanup loop for one sink. The
-- cleanup runs on a detached context so a mid-probe cancel still gets
-- to overwrite the gadgets installed; without that, ctx.Err() != nil
-- at cleanup time would fail-fast the request and the pollution would
-- stick until the target process restarts.
local function probe(ctx, target, sink, base_obs)
  local canary_key = "pp" .. new_canary()
  local canary_val = new_canary()

  local pollute_req, pollute_err = build_request(ctx, sink, canary_key, canary_val, false)
  if pollute_err then return nil, pollute_err end
  local pollute_resp, do_err = ctx.client["do"](ctx.client, pollute_req)
  if do_err then return nil, "pollute: " .. do_err end
  -- The pollute response body is NOT read - the observer is what
  -- carries the signal; reading the pollute response wastes bandwidth.

  -- Cleanup runs after every probe to minimize the pollution's blast
  -- radius. Best-effort: errors are intentionally swallowed; if the
  -- cleanup transport failed we still installed the gadget.
  local cleanup_done = false
  local function run_cleanup()
    if cleanup_done then return end
    cleanup_done = true
    local cleanup_req, _ = build_request(ctx, sink, canary_key, canary_val, true)
    if cleanup_req == nil then return end
    ctx.client:do_detached(cleanup_req, CLEANUP_TIMEOUT)
  end

  local obs, obs_err = observe(ctx, target)
  if obs_err then
    run_cleanup()
    return nil, "post-pollution observer: " .. obs_err
  end

  local verdict = pp_judge(ctx, base_obs, obs, canary_val)
  if not verdict.hit then
    run_cleanup()
    return nil
  end

  local probe_url = pollute_req:url()
  local pollute_status = 0
  if pollute_resp ~= nil then pollute_status = pollute_resp:status() end
  local finding = {
    severity = ctx.severity.high,
    target   = target,
    url      = probe_url,
    title    = string.format("Server-side prototype pollution via %s parameter %q", sink.loc, sink.name),
    detail   = string.format(
      "Parameter %q (%s) reached an object-merge or bracket-expanding parser on the backend: "
        .. "a pollution payload set Object.prototype properties that altered a subsequent clean "
        .. "observer request against %s. %s. An attacker can poison shared object state to "
        .. "bypass authorization checks, manipulate response behavior, or - depending on the "
        .. "gadget surface - achieve remote code execution.",
      sink.name, sink.loc, target, verdict.detail),
    details = {
      string.format("gadget: %s", verdict.gadget),
      string.format("canary: %s=%s", canary_key, canary_val),
      string.format("baseline observer: status=%d body=%dB", base_obs.status, #base_obs.body),
      string.format("post-pollution observer: status=%d body=%dB", obs.status, #obs.body),
      "cleanup payload overwrote the gadget values; polluted properties remain on the prototype until process restart",
    },
    evidence = ctx.evidence.from_exchange {
      request  = pollute_req,
      response = pollute_resp,
      body     = obs.body,
      snippet  = obs.body,
    },
    dedupe_parts = { "loc:" .. sink.loc, "param:" .. sink.name },
  }
  run_cleanup()
  return finding
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or u == nil or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local sinks = ctx.sinks.for_page{}
  if #sinks == 0 then return nil end

  -- Baseline observer runs once per page. The polluted prototype
  -- affects every subsequent request to the same Node process, so
  -- the page URL is a fine witness regardless of which sink we probe.
  local base_obs, base_err = observe(ctx, ctx.page.url)
  if base_err then
    ctx:report(string.format("proto-pollution baseline observer %s: %s", ctx.page.url, base_err))
    return nil, base_err
  end

  local findings = {}
  local seen = {}
  local first_err
  local probed_any = false
  for _, sink in ipairs(sinks) do
    if sink_probable(sink, ctx.locs) and ctx.scope:allows(sink.url) then
      local f, err = probe(ctx, ctx.page.url, sink, base_obs)
      if err then
        ctx:report(string.format("proto-pollution %s %s=%s: %s",
          sink.loc, sink.name, sink.url, err))
        if first_err == nil then first_err = err end
      else
        probed_any = true
        if f ~= nil then
          local key = ctx.dedupe.key {
            check  = check.name,
            scope  = "param",
            target = ctx.page.url,
            parts  = f.dedupe_parts,
          }
          if not seen[key] then
            seen[key] = true
            findings[#findings + 1] = f
          end
        end
      end
    end
  end

  if not probed_any and first_err ~= nil then
    return nil, first_err
  end
  return findings
end

return check
