// vuln-node: Express + a deliberately-vulnerable recursive merge so
// __proto__ keys in a POST body pollute Object.prototype. The
// scanner's proto-pollution check posts a payload of shape
//   {"__proto__":{"json spaces":7,"status":510}}
// then GETs the observer and confirms the pollution surfaced (either
// via `res.json` re-indenting to 7 spaces, since Express reads the
// `json spaces` app setting from Object.prototype on a polluted
// object, or via the new `status` becoming the default response code).

const express = require("express");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json({ type: "*/*", limit: "256kb" }));

function vulnerableMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (
      typeof source[key] === "object" &&
      source[key] !== null &&
      typeof target[key] === "object" &&
      target[key] !== null
    ) {
      vulnerableMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// In CVE-style merges, the target object itself is dereferenced to
// __proto__ when the source key is "__proto__". We mirror that
// vulnerability by NOT skipping the dunder key.
function reallyVulnerableMerge(target, source) {
  for (const key of Object.keys(source)) {
    const src = source[key];
    if (src && typeof src === "object" && !Array.isArray(src)) {
      if (target[key] === undefined) target[key] = {};
      reallyVulnerableMerge(target[key], src);
    } else {
      target[key] = src;
    }
  }
  return target;
}

app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<title>vuln-node</title>
<a href="/merge">merge sink</a>
<a href="/state">observer</a>
<a href="/openapi.json">openapi</a>`);
});

// OpenAPI spec so the crawler discovers /merge as a JSON-body sink the
// proto-pollution check can fuzz. Omits servers so the spec's origin
// (the mapped container port) is used as the base URL automatically.
app.get("/openapi.json", (_req, res) => {
  res.json({
    openapi: "3.0.0",
    info: { title: "vuln-node", version: "1.0" },
    paths: {
      "/merge": {
        post: {
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: { name: { type: "string" } },
                },
              },
            },
          },
          responses: { 200: { description: "ok" } },
        },
      },
    },
  });
});

app.post("/merge", (req, res) => {
  const settings = {};
  reallyVulnerableMerge(settings, req.body || {});
  res.json({ ok: true, settings });
});

// GET on the sink URL exists so proto-pollution's clean observer (which
// re-fetches the page URL via GET) lands on a res.json() response. The
// polluted Object.prototype["json spaces"] then leaks through the
// observer's indentation, which is what the check witnesses.
app.get("/merge", (_req, res) => {
  res.json({ hint: "POST __proto__ keys here" });
});

// Observer endpoint: any JSON write here uses res.json, which honors
// the polluted "json spaces" setting and the polluted default status
// code. A clean process returns 200 + compact JSON; a polluted process
// returns whatever the attacker injected.
app.get("/state", (req, res) => {
  res.json({ user: "alice", role: "guest" });
});

app.listen(8082, "0.0.0.0", () => {
  console.log("vuln-node listening on :8082");
});
