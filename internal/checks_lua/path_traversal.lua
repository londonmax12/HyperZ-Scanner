-- path-traversal: Lua port of internal/checks/path_traversal.go.
--
-- Per sink: baseline probe (with a fresh canary) to record the marker
-- hits already present on the page, then sweep the traversal payload
-- catalogue. A finding fires on the first payload whose response
-- introduces a TraversalMarkers substring (root:x:0:0:, the Windows
-- hosts header) the baseline did not already carry. Baseline
-- subtraction lives in Go (ctx.body.traversal_new_markers) so the
-- marker list stays a single source of truth.
--
-- Sweep gating: at LevelDefault only path-ish sinks are probed
-- (name matches one of the keywords; or value carries a path-shaped
-- character). ctx.body.path_sink_candidate evaluates the same
-- heuristic the Go check uses. LevelAggressive lifts the gate and
-- probes every sink.

local check = {
  name        = "path-traversal",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-22",
  owasp       = "A01:2021 Broken Access Control",
  remediation = "Resolve user-supplied paths against a fixed root and reject any result that escapes it "
                .. "(filepath.Clean + prefix check, or chroot-equivalent containment). Never pass raw user input to "
                .. "os.Open / fs.ReadFile - even after a regex filter, encoded variants (`..%2f`, `....//`) bypass naive "
                .. "defenses. Prefer opaque IDs that map to allowlisted filenames server-side.",
}

local BODY_CAP = 32 * 1024

local function send(ctx, sink, wire)
  local req, mut_err = sink:mutate_request(wire)
  if mut_err then return nil, nil, nil, false, mut_err end
  local resp, do_err = ctx.client["do"](ctx.client, req)
  if do_err then return req, nil, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, rerr end
  return req, resp, body, truncated, nil
end

local function probe(ctx, sink)
  -- Baseline: a benign canary establishes which marker substrings the
  -- page already carries (a docs page mentioning /etc/passwd, an admin
  -- help screen). The Go-side subtractor drops these from later hits.
  local canary = "hpzc" .. string.format("%012x", math.random(0, 0xffffff) * 0x1000000 + math.random(0, 0xffffff))
  local _, _, baseline_body, _, base_err = send(ctx, sink, canary)
  if base_err then return nil, base_err end

  for _, payload in ipairs(ctx.payloads.traversal()) do
    -- Traversal payloads must replace the value entirely - prepending
    -- the original ("42../../../../etc/passwd") doesn't traverse on
    -- any backend that joins inputs as a path component.
    local req, resp, body, truncated, err = send(ctx, sink, payload.template)
    if err then
      ctx:report(string.format("path-traversal payload %s %s=%s pl=%s: %s",
        sink.loc, sink.name, sink.url, payload.name, err))
    else
      local new_hits = ctx.body.traversal_new_markers(body, baseline_body)
      if #new_hits > 0 then
        local probe_url = req:url()
        return {
          severity = ctx.severity.high,
          url      = probe_url,
          title    = string.format('Path traversal in %s parameter "%s"', sink.loc, sink.name),
          detail   = string.format(
            'Parameter %q (%s) is concatenated into a filesystem path: payload path-traversal/%s '
              .. '(wire value %q) caused the response to disclose %q - a sensitive system file. '
              .. 'An attacker can read arbitrary files reachable by the server process.',
            sink.name, sink.loc, payload.name, payload.template, new_hits[1]),
          evidence = ctx.evidence.from_exchange {
            request   = req,
            response  = resp,
            body      = body,
            truncated = truncated,
          },
          dedupe_parts = { "loc:" .. sink.loc, "param:" .. sink.name },
        }
      end
    end
  end
  return nil
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or not u or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local sinks = ctx.sinks.for_page{}
  if #sinks == 0 then return nil end

  local sweep_all = ctx:level_at_least("aggressive")
  local findings = {}
  local seen = {}
  local first_err
  local probed_any = false
  for _, sink in ipairs(sinks) do
    if (sweep_all or ctx.body.path_sink_candidate(sink)) and ctx.scope:allows(sink.url) then
      local f, err = probe(ctx, sink)
      if err then
        ctx:report(string.format("probe %s %s=%s: %s", sink.loc, sink.name, sink.url, err))
        if not first_err then first_err = err end
      else
        probed_any = true
        if f then
          local key = "loc:" .. sink.loc .. "|param:" .. sink.name
          if not seen[key] then
            seen[key] = true
            findings[#findings + 1] = f
          end
        end
      end
    end
  end

  if not probed_any and first_err then return nil, first_err end
  return findings
end

return check
