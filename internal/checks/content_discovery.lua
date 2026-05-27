-- content-discovery: probes a curated wordlist of high-signal paths
-- against the target host. The wordlist lives behind
-- ctx.discovery.entries so catalog edits land once.
--
-- Per-host once: ctx.host.claim_once enforces a single sweep per
-- (scheme://host, check) tuple regardless of how many pages on this
-- host the crawler hands the check.
--
-- Two waves:
--  1. Main sweep dispatches the curated catalog (filtered by level
--     and detected stack) plus host-named backup synthetics.
--  2. Follow-up wave triggers when any main-wave hit names a path in
--     a configured group (e.g. /.git/HEAD enables /.git/* probes).
--
-- False-positive defense: two random canary probes per host establish
-- the soft-404 signature (status, body length, body hash, content
-- type, redirect target). A candidate that looks shape-equivalent to
-- the baseline is silently dropped.

local check = {
  name        = "content-discovery",
  level       = "default",
  scope       = "host",
  cwe         = "CWE-538",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Restrict admin / debug / VCS metadata paths at the web server or CDN layer; "
                .. "produce deploy artifacts that exclude editor backups, lockfiles, and VCS dirs.",
  tier        = "discovery",
}

local function get_status(resp)
  if resp == nil then return 0 end
  return resp:status()
end

local function fetch(ctx, target)
  local req, mut_err = ctx.client:new_request{ method = "GET", url = target }
  if mut_err then return nil, "", "", "", mut_err end
  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return nil, "", "", "", do_err end
  local body, _, rerr = resp:read_body_capped(ctx.discovery.body_cap())
  if rerr then return resp, "", "", "", rerr end
  local ct = resp:headers():get("Content-Type")
  local loc = resp:headers():get("Location")
  return resp, body, ct, loc, nil
end

-- baseline_for_host sends two canary probes and accumulates the
-- distinct response shapes the host produces for known-missing paths.
-- content_type and location are last-write-wins.
local function baseline_for_host(ctx, host_root)
  local b = {
    statuses     = {},
    body_hashes  = {},
    body_lens    = {},
    content_type = "",
    location     = "",
  }
  local probes = ctx.discovery.baseline_probes()
  for i = 1, probes do
    local path = ctx.discovery.canary_path()
    local target = host_root .. path
    local resp, body, ct, loc, err = fetch(ctx, target)
    if err then
      if i > 1 then break end
      return nil, err
    end
    b.statuses[resp:status()] = true
    b.body_hashes[ctx.discovery.body_hash_prefix(body)] = true
    b.body_lens[#b.body_lens + 1] = #body
    local family = ctx.discovery.content_type_family(ct)
    if family ~= "" then b.content_type = family end
    if loc ~= "" then b.location = loc end
  end
  return b, nil
end

-- looks_like_miss returns true when the response shape matches the
-- baseline: same status AND ( 3xx => same Location | 2xx => body
-- hash match OR (same CT family AND body length close to one of the
-- baselines) | 4xx/5xx => status match alone ).
local function looks_like_miss(ctx, b, status, body, ct, loc)
  if b.statuses[status] == nil then return false end
  if status >= 300 and status < 400 then
    if loc == "" or b.location == "" then return false end
    return loc:lower() == b.location:lower()
  end
  if status >= 200 and status < 300 then
    if b.body_hashes[ctx.discovery.body_hash_prefix(body)] ~= nil then
      return true
    end
    if ct ~= "" and b.content_type ~= ""
       and ctx.discovery.content_type_family(ct) == b.content_type then
      for _, bl in ipairs(b.body_lens) do
        if ctx.discovery.length_close_to(#body, bl) then return true end
      end
    end
    return false
  end
  return true
end

-- discovery_snippet renders the body excerpt for a finding's evidence.
-- Marker-bearing entries center the window on the first marker hit;
-- markerless entries return the leading bytes.
local function discovery_snippet(body, marker)
  if marker ~= nil and marker ~= "" then
    local i = body:find(marker, 1, true)
    if i == nil then return marker end
    local start = i - 120
    if start < 1 then start = 1 end
    local stop = i + #marker + 120
    if stop > #body then stop = #body end
    return (body:sub(start, stop):gsub("^%s+", ""):gsub("%s+$", ""))
  end
  if #body > 512 then body = body:sub(1, 512) end
  return (body:gsub("^%s+", ""):gsub("%s+$", ""))
end

-- classify_response returns (verdict, evidence_line, severity) on a
-- hit, or ("", "", "") on a non-hit.
local function classify_response(ctx, entry, baseline, status, body, ct, loc)
  if status == 401 or status == 403 then
    return "auth-gated",
      string.format("Server returned %d, confirming the resource exists behind an authentication check.", status),
      entry.severity
  end
  if status >= 200 and status < 300 then
    if entry.marker ~= "" then
      if body:find(entry.marker, 1, true) ~= nil then
        return "marker-match",
          string.format('Response body contains %q - confirms the file is the genuine artifact, not a catch-all page.', entry.marker),
          entry.severity
      end
      return "", "", ""
    end
    if looks_like_miss(ctx, baseline, status, body, ct, loc) then return "", "", "" end
    if not ctx.discovery.content_type_family_allowed(ct, entry.expected_content_types) then
      return "", "", ""
    end
    return "200-distinct",
      string.format("Server returned %d with a response distinct from the soft-404 baseline (body length %d).",
        status, #body),
      entry.severity
  end
  if status >= 300 and status < 400 then
    if looks_like_miss(ctx, baseline, status, body, ct, loc) then return "", "", "" end
    return "redirects",
      string.format("Server returned %d Location: %s - distinct from the soft-404 baseline.", status, loc),
      entry.severity
  end
  return "", "", ""
end

-- probe issues a GET against the entry path and folds the verdict
-- into a finding (or nil on non-hit / error). When the entry is
-- flagged emit=true (admin panels, GraphQL endpoints, management
-- consoles - interactive surfaces worth further probing), the hit
-- also fans out as a new KindPage scan target via ctx:discover so
-- downstream checks (XSS, SQLi, IDOR, ...) run against the freshly-
-- found URL. File-disclosure entries (env files, VCS metadata, info
-- pages) leave emit=false: the response IS the finding and there is
-- nothing useful to hand an active checker.
local function probe(ctx, host_root, baseline, entry, probe_url)
  local resp, body, ct, loc, err = fetch(ctx, probe_url)
  if err then return nil, err end
  local verdict, evidence_line, severity = classify_response(ctx, entry, baseline, resp:status(), body, ct, loc)
  if verdict == "" then return nil end

  if entry.emit then
    ctx:discover{ kind = "page", url = probe_url }
  end

  local detail = entry.detail
  if evidence_line ~= "" then detail = (entry.detail .. " " .. evidence_line):gsub("^%s+", ""):gsub("%s+$", "") end

  return {
    severity    = ctx.severity[severity],
    target      = host_root,
    url         = probe_url,
    title       = string.format("%s (%s)", entry.title, verdict),
    detail      = detail,
    cwe         = entry.cwe,
    owasp       = entry.owasp,
    remediation = entry.remediation,
    evidence = ctx.evidence.build {
      method  = "GET",
      url     = probe_url,
      status  = resp:status(),
      headers = resp:headers(),
      body    = discovery_snippet(body, entry.marker),
    },
    dedupe_parts = { "path:" .. entry.path },
  }
end

-- run_probes dispatches entries sequentially. probed is mutated in
-- place so a second call with the follow-up wave skips paths the main
-- wave already covered. Failures report via ctx:report and do not
-- abort the sweep.
local function run_probes(ctx, host_root, baseline, entries, probed)
  local findings = {}
  local seen = {}
  for _, entry in ipairs(entries) do
    if probed[entry.path] == nil then
      probed[entry.path] = true
      local probe_url = host_root .. entry.path
      if ctx.scope:allows(probe_url) then
        local f, err = probe(ctx, host_root, baseline, entry, probe_url)
        if err then
          ctx:report(string.format("content-discovery probe %s: %s", entry.path, err))
        elseif f ~= nil and seen[entry.path] == nil then
          seen[entry.path] = true
          findings[#findings + 1] = f
        end
      end
    end
  end
  return findings
end

-- hit_paths extracts the path component out of each finding URL so
-- the follow-up trigger lookup matches the configured groups (whose
-- triggers are absolute paths like "/.git/HEAD").
local function hit_paths(findings)
  local out = {}
  for _, f in ipairs(findings) do
    local url = f.url
    local i = url:find("://", 1, true)
    if i ~= nil then
      local rest = url:sub(i + 3)
      local j = rest:find("/", 1, true)
      if j ~= nil then out[rest:sub(j)] = true end
    end
  end
  return out
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or u == nil or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end
  local host_root = u.scheme .. "://" .. u.host
  if not ctx.host.claim_once(host_root) then return nil end

  local baseline, base_err = baseline_for_host(ctx, host_root)
  if base_err then return nil, "content-discovery baseline: " .. base_err end
  if next(baseline.statuses) == nil then return nil end

  local aggressive = ctx:level_at_least("aggressive")
  local hostname = u.hostname or ""
  local main_entries = ctx.discovery.entries("common", aggressive, hostname)

  local probed = {}
  local findings = run_probes(ctx, host_root, baseline, main_entries, probed)

  -- Second wave: expand on any hit whose path triggers a follow-up
  -- group. Skipping when nothing fired keeps the cost zero on hosts
  -- where the curated catalog drew a blank.
  if #findings > 0 then
    local hits = hit_paths(findings)
    if next(hits) ~= nil then
      local follow_ups = ctx.discovery.follow_ups("common", hostname, hits, probed)
      if #follow_ups > 0 then
        local extra = run_probes(ctx, host_root, baseline, follow_ups, probed)
        local seen = {}
        for _, f in ipairs(findings) do seen[f.url] = true end
        for _, f in ipairs(extra) do
          if seen[f.url] == nil then
            seen[f.url] = true
            findings[#findings + 1] = f
          end
        end
      end
    end
  end

  if #findings == 0 then return nil end
  return findings
end

return check
