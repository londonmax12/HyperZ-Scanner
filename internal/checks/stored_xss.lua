-- stored-xss: two-phase persistent-XSS check. Phase 1 plants a fixed family of
-- payloads (each carrying a fresh canary) into every Sink on every
-- in-scope page; phase 2 re-fetches every URL in visited+DetectURLs
-- and fires a High finding when the plant's breakout bytes (canary
-- included) survived encoding and re-rendered intact in the body.
--
-- Phase 1 (Plant): for every Sink discovered on the page, dedupe
-- against the cross-page sink set held in stored_xss state, mint
-- three payloads covering the dominant storage contexts (HTML text,
-- double-quoted attribute, JS double-quoted string), send each, and
-- record (canary -> plant record) so phase 2 can rebuild the
-- finding from a canary echo. Plant responses are mined for same-
-- origin URLs (Location header + body links) that the crawler
-- might not have seen, so a "view your post" redirect target
-- reachable only after submission still gets a phase-2 re-fetch.
--
-- Phase 2 (Detect): the scanner re-fetches every URL in the union
-- of visited and DetectURLs(); for each body, the Lua side extracts
-- every canary-shaped match, looks each one up in the planted map,
-- and fires when the full payload bytes (not just the canary)
-- survived intact. A canary alone without its surrounding breakout
-- means the application stored the input but encoded it correctly;
-- intentionally silent here (same exploitability bar
-- reflected-xss uses).
--
-- This is a state-mutating check: plants persist on the target
-- until the operator removes them. Loads only when the scanner
-- ships with --pollute set, same gate ProtoPollution sits behind.

local check = {
  name        = "stored-xss",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-79",
  owasp       = "A03:2021 Injection",
  remediation = "Apply context-aware output encoding at the rendering boundary, not just at the storage one: "
                .. "HTML-encode user input rendered into HTML text, attribute-encode for values placed in tag attributes, "
                .. "and JavaScript-encode (or hand off via JSON) for values placed inside <script>. "
                .. "Storing the raw user input is fine when every read path is guaranteed to escape - audit every template that renders this field.",
  budget_seconds = 90,
  phase = "two-phase",
  pollute = true,
}

local BODY_CAP = 256 * 1024

-- The per-context payload family. Three covers HTML text, double-
-- quoted attribute, and double-quoted JS string - the three
-- contexts ~95% of real storage reads land in. Each payload
-- includes the canary inside the breakout bytes so matching the
-- breakout in a re-fetched body means the application stored the
-- value AND failed to encode the outer markup.
local PAYLOADS = {
  { name = "html-text-svg",          ctx = "HTML text",                template = '<svg onload=alert(1)>{{TOKEN}}</svg>' },
  { name = "attr-double-break",      ctx = "double-quoted attribute",  template = '"><svg onload=alert(1)>{{TOKEN}}</svg>' },
  { name = "js-string-double-break", ctx = "JS double-quoted string",  template = '";alert(1);//{{TOKEN}}' },
}

local function render(template, token)
  return (string.gsub(template, "{{TOKEN}}", token))
end

local function contains(haystack, needle)
  if haystack == nil or needle == nil or needle == "" then return false end
  return string.find(haystack, needle, 1, true) ~= nil
end

-- snippet returns a short window around the first occurrence of
-- needle in body, suitable for an evidence snippet.
local function snippet(body, needle)
  if body == nil or needle == nil or needle == "" then return "" end
  local s = string.find(body, needle, 1, true)
  if not s then return "" end
  local pre = math.max(1, s - 80)
  local post = math.min(#body, s + #needle + 80)
  return string.sub(body, pre, post)
end

-- send issues one plant request through the sink's MutateRequest
-- and reads the response up to BODY_CAP. Returns (request,
-- response, body, truncated) or nil + err. The caller invokes
-- ctx:report on transient failures rather than short-circuiting the
-- sink fanout - one flaky probe must not silently disqualify
-- every other payload + sink on the page.
local function send(ctx, sink, payload)
  local req, mut_err = sink:mutate_request(payload)
  if mut_err then return nil, nil, nil, false, mut_err end
  local resp, do_err = ctx.client["do"](ctx.client, req)
  if do_err then return req, nil, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, rerr end
  return req, resp, body, truncated, nil
end

-- header_value reads name from response headers regardless of case.
-- gopher-lua's string.lower is not multibyte-aware but ASCII names
-- are what we deal with on the wire.
local function header_value(resp, name)
  if resp == nil then return "" end
  local headers = resp:headers()
  if headers == nil then return "" end
  return headers:get(name) or ""
end

function check.plant(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or not u or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local sinks = ctx.sinks.for_page{}
  if #sinks == 0 then return nil end

  local state = ctx.stored_xss.state()

  for _, sink in ipairs(sinks) do
    if ctx.scope:allows(sink.url) then
      if state:plant_once(sink.method, sink.url, sink.loc, sink.name) then
        for _, pl in ipairs(PAYLOADS) do
          local token = ctx.stored_xss.new_canary()
          local rendered = render(pl.template, token)
          local req, resp, body, _, send_err = send(ctx, sink, rendered)
          if send_err then
            ctx:report(string.format("plant %s %s=%s payload=%s: %s",
              sink.loc, sink.name, sink.url, pl.name, send_err))
          else
            local plant_url = req and req:url() or sink.url
            state:record_canary(token, {
              method       = sink.method,
              url          = sink.url,
              loc          = sink.loc,
              name         = sink.name,
              value        = sink.value,
              payload      = rendered,
              payload_name = pl.name,
              payload_ctx  = pl.ctx,
              plant_url    = plant_url,
            })
            if resp ~= nil then
              state:absorb_detect_urls(plant_url, header_value(resp, "Location"), body or "")
            end
          end
        end
      end
    end
  end
  return nil
end

function check.detect(ctx)
  if ctx.page.body == nil or #ctx.page.body == 0 then return nil end
  local state = ctx.stored_xss.state()
  local matches = state:find_canaries(ctx.page.body)
  if #matches == 0 then return nil end

  local findings = {}
  local seen_locally = {}
  for _, token in ipairs(matches) do
    local plant = state:lookup_canary(token)
    if plant then
      local sk = string.format("%s|%s|%s|%s", plant.method, plant.url, plant.loc, plant.name)
      if not seen_locally[sk] then
        if not contains(ctx.page.body, plant.payload) then
          -- Canary alone, no breakout - the app stored the input but
          -- encoded its outer markup. Not exploitable as stored-xss;
          -- intentionally silent (matches reflected-xss's bar).
        else
          if state:detect_fire_once(plant.method, plant.url, plant.loc, plant.name) then
            seen_locally[sk] = true
            local title = string.format("Stored XSS in %s parameter %q", plant.loc, plant.name)
            local detail = string.format(
              "Parameter %q (%s) submitted to %s is stored server-side and rendered unescaped at %s (%s context). "
                .. "Payload xss/%s round-tripped intact across the storage boundary - an attacker can plant script that fires for every visitor of the detect page.",
              plant.name, plant.loc, plant.plant_url, ctx.page.url, plant.payload_ctx, plant.payload_name)
            findings[#findings + 1] = {
              severity     = ctx.severity.high,
              target       = plant.plant_url,
              url          = ctx.page.url,
              title        = title,
              detail       = detail,
              evidence     = ctx.evidence.build {
                method  = "GET",
                url     = ctx.page.url,
                status  = ctx.page.status,
                snippet = snippet(ctx.page.body, plant.payload),
              },
              dedupe_parts = { "loc:" .. plant.loc, "param:" .. plant.name },
            }
          else
            -- Another detect page already fired this sink's finding
            -- earlier in phase 2; skip silently so the operator sees
            -- one finding per sink, not one per detect URL.
            seen_locally[sk] = true
          end
        end
      end
    end
  end
  return findings
end

-- check.run is the single-phase fallback the scanner calls when
-- phase-2 orchestration is disabled (older code paths, dry runs).
-- Returns no findings: plants without detect would double the
-- request count without producing any report.
function check.run(ctx)
  return nil
end

return check
