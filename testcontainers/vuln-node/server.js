// vuln-node: Express + a deliberately-vulnerable recursive merge so
// __proto__ keys in a POST body pollute Object.prototype. The
// scanner's proto-pollution check posts a payload of shape
//   {"__proto__":{"json spaces":7,"status":510}}
// then GETs the observer (the same /merge URL the openapi spec
// declares). The observer renders its response through a fresh
// `const opts = {}` defaults pattern, so a polluted prototype's
// `status` and `json spaces` keys surface as own properties of opts
// via the prototype chain - HTTP 510 and a 7-space-indented body
// are what the check witnesses.
//
// Note that Express's app.set/get walker (see express 4.x
// application.js) explicitly stops at Object.prototype, so
// res.json() does NOT honor the polluted "json spaces" setting on
// its own; the observable gadget has to be a code path the fixture
// owns. The `opts || {}` defaults pattern below is the canonical
// CVE-style consumer of a polluted prototype.

const express = require("express");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json({ type: "*/*", limit: "256kb" }));

// In CVE-style merges, target[key] for key="__proto__" dereferences
// to target's prototype rather than an own property, so the recursion
// walks into Object.prototype and assigns the inner keys there.
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

// respondWithGadgets renders payload through response options pulled
// off a fresh `{}` default - the classic post-pollution gadget
// surface. After a successful pollution, opts.status reads
// Object.prototype["status"] = 510 and opts["json spaces"] reads
// Object.prototype["json spaces"] = 7. The for-in walk echoes any
// other polluted key (the scanner's per-probe canary) as an extra
// field on the response so the canary-echo gadget can fire too.
function respondWithGadgets(res, payload) {
  const opts = {};
  const status = opts.status || 200;
  const spaces = opts["json spaces"] || 0;
  const out = Object.assign({}, payload);
  for (const k in opts) {
    if (k === "status" || k === "json spaces") continue;
    out[k] = opts[k];
  }
  res.status(status).type("application/json").send(JSON.stringify(out, null, spaces));
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
  respondWithGadgets(res, { ok: true });
});

// GET on the sink URL is the observer the proto-pollution check
// re-fetches between its baseline and post-pollution probe.
app.get("/merge", (_req, res) => {
  respondWithGadgets(res, { hint: "POST __proto__ keys here" });
});

// Sibling observer for symmetry with the openapi-declared sink. Same
// gadget surface, useful if the check's page-emission heuristics
// shift to a non-sink URL.
app.get("/state", (_req, res) => {
  respondWithGadgets(res, { user: "alice", role: "guest" });
});

app.listen(8082, "0.0.0.0", () => {
  console.log("vuln-node listening on :8082");
});
