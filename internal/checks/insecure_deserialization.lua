-- insecure-deserialization: Lua port of internal/checks/insecure_deserialization.go.
--
-- Two complementary arms:
--   1. Fingerprint (passive). Scans Set-Cookie / query / form-input
--      values for on-the-wire signatures of Java ObjectInputStream,
--      .NET BinaryFormatter, Python pickle, Ruby Marshal, PHP
--      serialize, node-serialize, and YAML unsafe-load. Body scan
--      runs at LevelAggressive only.
--   2. Active probe. For each sink, sends a baseline canary then
--      iterates the format catalogue dispatching malformed-but-
--      format-valid payloads that trip the deserializer's parser
--      without invoking any constructor.
--
-- Pattern catalogue + classifier + error matchers live in Go via
-- ctx.deserial.{formats,classify,match_all,match_format,body_marker}.
-- The .lua port owns dedupe, finding shape, and arm orchestration.

local check = {
  name        = "insecure-deserialization",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-502",
  owasp       = "A08:2021 Software and Data Integrity Failures",
  remediation = "Replace format-native deserialization (Java ObjectInputStream, .NET BinaryFormatter/LosFormatter, "
                .. "PHP unserialize, pickle.loads, Marshal.load, node-serialize) with a data-only format such as "
                .. "JSON or Protocol Buffers validated against a schema. When format-native deserialization is "
                .. "unavoidable, sign the blob with a server-side key (HMAC) and verify the MAC before "
                .. "deserializing, and restrict the deserializer's type allowlist (Java: ObjectInputFilter; "
                .. ".NET: ISerializationBinder; Python: a RestrictedUnpickler).",
}

local FINGERPRINT_PREVIEW_CAP = 80

local function new_canary()
  -- 12 hex chars for parity with checks.NewCanary's bit count.
  local hex = "0123456789abcdef"
  local out = { "hpzc" }
  for _ = 1, 12 do
    local r = math.random(1, 16)
    out[#out + 1] = string.sub(hex, r, r)
  end
  return table.concat(out)
end

local function preview(value)
  if #value > FINGERPRINT_PREVIEW_CAP then
    return string.sub(value, 1, FINGERPRINT_PREVIEW_CAP) .. "..."
  end
  return value
end

-- fingerprint_finding builds a "Serialized X data carried in Y"
-- finding. severity is the caller-chosen severity (high for round-
-- trip surfaces, medium for body-only leakage). The dedupe key shape
-- matches the Go check's MakeKey(name, ScopePage, target,
-- "fingerprint", "format:"+name, "location:"+location).
local function fingerprint_finding(ctx, target, location, fmt_name, fmt_label, value, severity)
  local prev = preview(value)
  return {
    severity = ctx.severity[severity],
    target   = target,
    url      = target,
    title    = string.format("Serialized %s data carried in %s", fmt_label, location),
    detail   = string.format(
      "%s carries a value matching the on-the-wire shape of %s (sample: %q). When the server reads this "
        .. "value back through a format-native deserializer the request is one crafted gadget chain away "
        .. "from remote code execution. Insecure deserialization (CWE-502) is exploitable regardless of "
        .. "whether a usable gadget is known today; the architectural defect is feeding attacker-influenced "
        .. "bytes to a polymorphic deserializer.",
      location, fmt_label, prev),
    remediation = "Stop round-tripping serialized objects through the client. Replace the carrier with an opaque "
      .. "server-side session ID and keep the deserialized state in server memory or a trusted store. When "
      .. "the round-trip is unavoidable, sign the blob with a server-side key (HMAC) and verify the MAC "
      .. "before deserializing. Restrict the deserializer's type allowlist (Java: ObjectInputFilter; "
      .. ".NET: ISerializationBinder; Python: a RestrictedUnpickler).",
    evidence = ctx.evidence.build {
      method  = "GET",
      url     = target,
      snippet = string.format("%s value: %s", location, prev),
    },
    dedupe_key = ctx.dedupe.key {
      check  = check.name,
      scope  = "page",
      target = target,
      parts  = { "fingerprint", "format:" .. fmt_name, "location:" .. location },
    },
  }
end

-- body_marker_finding renders a finding for a body-only deserialization
-- leak (no proven round-trip). Severity medium.
local function body_marker_finding(ctx, target, marker)
  return {
    severity = ctx.severity.medium,
    target   = target,
    url      = target,
    title    = string.format("Serialized object exposed in response body (%s)", marker),
    detail   = string.format(
      "The response body contains the on-the-wire shape of %s. This is leakage rather than a "
        .. "proven round-trip sink: the server is emitting a serialized blob into the rendered "
        .. "output, which is harmless on its own but suggests format-native serialization is used "
        .. "somewhere in the request lifecycle. Investigate whether the same blob is accepted back "
        .. "from the client (cookie, hidden field, query parameter) and fed to a deserializer.",
      marker),
    remediation = "Audit whether a server-side deserializer reads any user-influenced value. If so, replace "
      .. "format-native deserialization (Java ObjectInputStream, .NET BinaryFormatter/LosFormatter, "
      .. "PHP unserialize, pickle.loads, Marshal.load, node-serialize) with a data-only format such "
      .. "as JSON or Protocol Buffers and validate against a schema. When format-native deserialization "
      .. "is unavoidable, sign the blob with a server-side key and verify the MAC before deserializing.",
    dedupe_key = ctx.dedupe.key {
      check  = check.name,
      scope  = "page",
      target = target,
      parts  = { "body-fingerprint:" .. marker },
    },
  }
end

-- url_query_pairs extracts the parsed query parameters from raw as
-- an iterable list of {name, value}. ctx.url.query already returns a
-- map; we walk it deterministically (Lua tables iterate in arbitrary
-- order, but the Go side iterates u.Query() which is also arbitrary
-- and the parity test compares dedupe keys after sort).
local function url_query_pairs(ctx, raw)
  local out = {}
  local q = ctx.url.query(raw)
  if q == nil then return out end
  for k, v in pairs(q) do
    if type(v) == "string" then
      out[#out + 1] = { name = k, value = v }
    elseif type(v) == "table" then
      for _, vv in ipairs(v) do
        out[#out + 1] = { name = k, value = vv }
      end
    end
  end
  return out
end

-- scan_fingerprints walks the baseline snapshot for serialized data
-- in surfaces that round-trip back to a server-side deserializer:
-- Set-Cookie values, URL query parameters, and form input defaults.
-- Body scan runs at LevelAggressive only and fires at medium since
-- the round-trip isn't proven.
local function scan_fingerprints(ctx, target, snap, seen, findings)
  -- Set-Cookie: server-set cookies that round-trip on every request.
  if snap.headers ~= nil then
    for _, cookie in ipairs(ctx.cookies.from_headers(snap.headers)) do
      if cookie.value ~= "" then
        local fmt_name, fmt_label = ctx.deserial.classify("http_body", cookie.value)
        if fmt_name ~= "" then
          local f = fingerprint_finding(ctx, target, "Set-Cookie " .. cookie.name,
            fmt_name, fmt_label, cookie.value, "high")
          if not seen[f.dedupe_key] then
            seen[f.dedupe_key] = true
            findings[#findings + 1] = f
          end
        end
      end
    end
  end

  -- URL query parameters present at crawl time.
  for _, pair in ipairs(url_query_pairs(ctx, target)) do
    local fmt_name, fmt_label = ctx.deserial.classify("http_body", pair.value)
    if fmt_name ~= "" then
      local f = fingerprint_finding(ctx, target, "query parameter " .. pair.name,
        fmt_name, fmt_label, pair.value, "high")
      if not seen[f.dedupe_key] then
        seen[f.dedupe_key] = true
        findings[#findings + 1] = f
      end
    end
  end

  -- Form input default values - hidden inputs carrying serialized
  -- state are the canonical __VIEWSTATE pattern.
  for _, form in ipairs(ctx.page.forms or {}) do
    for _, input in ipairs(form.inputs or {}) do
      if input.value ~= nil and input.value ~= "" then
        local fmt_name, fmt_label = ctx.deserial.classify("http_body", input.value)
        if fmt_name ~= "" then
          local f = fingerprint_finding(ctx, target, "form input " .. input.name,
            fmt_name, fmt_label, input.value, "high")
          if not seen[f.dedupe_key] then
            seen[f.dedupe_key] = true
            findings[#findings + 1] = f
          end
        end
      end
    end
  end

  -- Body scan at LevelAggressive: text-form markers in rendered HTML.
  if ctx:level_at_least("aggressive") and snap.body ~= nil and snap.body ~= "" then
    local marker = ctx.deserial.body_marker(snap.body)
    if marker ~= "" then
      local f = body_marker_finding(ctx, target, marker)
      if not seen[f.dedupe_key] then
        seen[f.dedupe_key] = true
        findings[#findings + 1] = f
      end
    end
  end
end

-- subtract_patterns returns the elements of hits not present in
-- baseline. Used per-format probe to suppress patterns the response
-- already carried before the malformed payload landed.
local function subtract_patterns(hits, baseline)
  local seen_baseline = {}
  for _, p in ipairs(baseline) do seen_baseline[p] = true end
  local out = {}
  for _, p in ipairs(hits) do
    if not seen_baseline[p] then
      out[#out + 1] = p
    end
  end
  return out
end

-- probe_sink runs the baseline + per-format payload sweep for one
-- sink. Returns the first finding observed; dedupe collapses any
-- subsequent hits on the same (loc, param) so continuing burns
-- requests without changing the report.
local function probe_sink(ctx, target, sink)
  local canary = new_canary()

  local base_req, base_mut_err = sink:mutate_request(canary)
  if base_mut_err then return nil, base_mut_err end
  local base_resp, base_do_err = ctx.client:do_no_follow(base_req)
  if base_do_err then return nil, base_do_err end
  local base_body, _, base_rerr = base_resp:read_body_capped(32 * 1024)
  if base_rerr then return nil, base_rerr end

  local baseline_hits = ctx.deserial.match_all("http_body", base_body)

  for _, fmt in ipairs(ctx.deserial.formats("http_body")) do
    local req, mut_err = sink:mutate_request(fmt.probe_payload)
    if mut_err then return nil, mut_err end
    local resp, do_err = ctx.client:do_no_follow(req)
    if do_err then return nil, do_err end
    local body, truncated, rerr = resp:read_body_capped(32 * 1024)
    if rerr then return nil, rerr end

    local hits = ctx.deserial.match_format("http_body", body, fmt.name)
    local new_hits = subtract_patterns(hits, baseline_hits)
    if #new_hits > 0 then
      local probe_url = req:url()
      return {
        severity = ctx.severity.high,
        target   = target,
        url      = probe_url,
        title    = string.format("Insecure deserialization (%s) in %s parameter %q",
          fmt.label, sink.loc, sink.name),
        detail   = string.format(
          'Parameter %q (%s) is fed to a %s deserializer: payload insecure-deserialization/%s '
            .. '(wire value %q) provoked deserializer error signature %q in the response. If an attacker '
            .. 'can construct a gadget chain whose constructor or readObject hook has side-effects, this '
            .. 'primitive lifts to remote code execution.',
          sink.name, sink.loc, fmt.label, fmt.name, fmt.probe_payload, new_hits[1]),
        evidence = ctx.evidence.from_exchange {
          request   = req,
          response  = resp,
          body      = body,
          truncated = truncated,
        },
        dedupe_key = ctx.dedupe.key {
          check  = check.name,
          scope  = "param",
          target = target,
          parts  = { "loc:" .. sink.loc, "param:" .. sink.name },
        },
      }
    end
  end
  return nil
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or u == nil or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local findings = {}
  local seen = {}
  local first_err

  -- Fingerprint arm: reuses the baseline snapshot, costs zero extras.
  local snap, snap_err = ctx:ensure_response { max_body = 32 * 1024 }
  if snap_err == nil and snap ~= nil and snap.headers ~= nil then
    scan_fingerprints(ctx, ctx.page.url, snap, seen, findings)
  end

  -- Probe arm: per-sink malformed-payload sweep.
  local sinks = ctx.sinks.for_page{}
  for _, sink in ipairs(sinks) do
    if ctx.scope:allows(sink.url) then
      local f, err = probe_sink(ctx, ctx.page.url, sink)
      if err then
        ctx:report(string.format("insecure-deserialization probe %s %s=%s: %s",
          sink.loc, sink.name, sink.url, err))
        if first_err == nil then first_err = err end
      elseif f ~= nil and not seen[f.dedupe_key] then
        seen[f.dedupe_key] = true
        findings[#findings + 1] = f
      end
    end
  end

  if first_err and #findings == 0 then return nil, first_err end
  return findings
end

return check
