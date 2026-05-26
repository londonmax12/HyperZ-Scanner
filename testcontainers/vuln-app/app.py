"""
vuln-app: deliberately broken Flask app. One file, one container, one
endpoint per active web-app probe the scanner ships. Endpoints exist
to be detected by hyperz - none are safe to leave reachable.

Layout: index discovers every endpoint by linking and form-posting to
them so the crawler enqueues them, then each handler implements the
vulnerability the corresponding check looks for. Trigger conditions
are documented inline above each handler and were derived from the
.lua check sources in internal/checks/.
"""

import json
import os
import pickle
import socket
import subprocess
import time
import urllib.request
import urllib.error
from base64 import b64decode

import jwt
from flask import Flask, Response, jsonify, redirect, request, stream_with_context
from jinja2 import Template
from lxml import etree

app = Flask(__name__)
JWT_SECRET = "secret"  # weak symmetric key - hyperz jwt-vulns will brute-force


# --- discovery: hyperz crawler walks links and forms from / ----------------
@app.route("/")
def index():
    return """<!doctype html>
<html>
<head><title>vuln-app</title></head>
<body>
<h1>vuln-app discovery</h1>

<!-- crawler enqueues each href -->
<ul>
  <li><a href="/redirect?u=https://example.com/next">open-redirect</a></li>
  <li><a href="/host">host-header reflect</a></li>
  <li><a href="/poison">cache-poison candidate</a></li>
  <li><a href="/crlf?next=ok">crlf</a></li>
  <li><a href="/fetch?url=http://example.com">ssrf</a></li>
  <li><a href="/search?q=hello">reflected-xss + sqli</a></li>
  <li><a href="/dom-xss">dom-xss</a></li>
  <li><a href="/find?q=alice">nosqli</a></li>
  <li><a href="/dir?cn=admin">ldap injection</a></li>
  <li><a href="/file?name=hello.txt">path traversal</a></li>
  <li><a href="/run?ip=127.0.0.1">cmd injection (in-band)</a></li>
  <li><a href="/ping?host=example.com">cmd-injection blind</a></li>
  <li><a href="/render?name=guest">ssti</a></li>
  <li><a href="/user/1">idor</a></li>
  <li><a href="/jwt-login">jwt issue</a></li>
  <li><a href="/jwt-me">jwt validate</a></li>
  <li><a href="/graphql">graphql endpoint</a></li>
  <li><a href="/sse">sse stream</a></li>
  <li><a href="/comments">stored-xss surface</a></li>
  <li><a href="/xml-form">xxe form</a></li>
</ul>

<!-- pollute=false form: visible text input keeps the crawler from
     POSTing automatically, but it leaves the endpoint discoverable. -->
<form action="/comments" method="post">
  <input type="text" name="body" placeholder="comment">
  <button type="submit">post</button>
</form>

<form action="/deserialize" method="post">
  <!-- pickle bytes carried in cookie; insecure-deserialization scans
       Set-Cookie / request param values for serializer fingerprints. -->
  <input type="hidden" name="payload" value="gASVDAAAAAAAAAB9lIwBYZRLAXMu">
  <button type="submit">deser</button>
</form>
</body></html>"""


# --- open-redirect ---------------------------------------------------------
# Trigger: query/form param whose value is reflected verbatim into the
# Location header on a 30x. Hyperz substitutes a canary external URL
# and confirms by inspecting Location.
@app.route("/redirect")
def open_redirect():
    return redirect(request.args.get("u", "/"), code=302)


# --- host-header-injection -------------------------------------------------
# Trigger: response body reflects the Host header verbatim.
@app.route("/host")
def host_reflect():
    host = request.headers.get("Host", "")
    return f"<!doctype html><body>You reached: {host}</body>"


# --- cache-poisoning -------------------------------------------------------
# Trigger: response reflects an unkeyed header (X-Forwarded-Host) AND
# carries a cacheable Cache-Control without a Vary on that header.
@app.route("/poison")
def poison():
    xfh = request.headers.get("X-Forwarded-Host", "default.example")
    body = (
        "<!doctype html><html><body>"
        f"<base href=\"https://{xfh}/\">"
        f"<p>greeting from {xfh}</p>"
        "</body></html>"
    )
    resp = Response(body, mimetype="text/html")
    resp.headers["Cache-Control"] = "public, max-age=300"
    # deliberately no Vary - that's the bug
    return resp


# --- crlf-injection --------------------------------------------------------
# Trigger: request param is dropped into a response header (here:
# Location) without CR/LF sanitization, so an injected %0d%0a payload
# splits the response.
@app.route("/crlf")
def crlf():
    nxt = request.args.get("next", "/")
    resp = Response("", status=302)
    # Raw insert; Flask/Werkzeug normally would scrub, so write via
    # status_line workaround:
    resp.headers["Location"] = nxt
    return resp


# --- ssrf ------------------------------------------------------------------
# Trigger: URL-bearing param ('url', 'fetch', 'webhook', ...) whose
# value the server fetches. The scanner replaces with an oob canary;
# even without OOB it confirms when the response body contains the
# scanner's canary URL or a fetch error referencing it.
@app.route("/fetch")
def ssrf():
    target = request.args.get("url", "")
    if not target:
        return "missing url", 400
    try:
        with urllib.request.urlopen(target, timeout=3) as r:
            body = r.read(4096)
        return Response(f"fetched {target} -> {len(body)} bytes\n\n" + body.decode("utf-8", "replace"))
    except Exception as e:
        # Including the URL in the error message helps the in-band
        # oracle confirm without needing OOB.
        return f"fetch error for {target}: {e}", 502


# --- reflected-xss + sqli (error/boolean/time) -----------------------------
# Trigger: ?q= is reflected unescaped (xss) AND is appended to a fake
# SQL string used for the response shape. We simulate:
#   - quote in q -> SQL syntax error in body (sqli-error)
#   - "' OR 1=1--" -> long list (sqli-boolean truthy)
#   - "' AND 1=2--" -> empty list (sqli-boolean falsy)
#   - contains SLEEP() -> sleeps before responding (sqli-time)
@app.route("/search")
def search():
    q = request.args.get("q", "")
    body = [f"<p>You searched for: {q}</p>"]  # reflected-xss

    qlow = q.lower()
    if "sleep(" in qlow:
        # time-based: hyperz looks for response latency clearly above
        # baseline. 6s is well above the default 2s threshold.
        time.sleep(6)
    if "'" in q and " or " not in qlow and " and " not in qlow:
        # error-based: emit an unmistakable MySQL syntax error
        # (sqli-error matches a curated list of driver signatures).
        body.append("<pre>You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MySQL "
                    "server version for the right syntax to use near "
                    f"'{q}' at line 1</pre>")
        return Response("".join(body), status=500)
    if "1=1" in qlow:
        body.append("<ul>" + "".join(f"<li>row {i}</li>" for i in range(20)) + "</ul>")
    elif "1=2" in qlow:
        body.append("<ul></ul>")
    else:
        body.append(f"<ul><li>match for {q}</li></ul>")
    return "".join(body)


# --- dom-xss ---------------------------------------------------------------
# Trigger: page contains JS that reads location.hash / location.search
# / document.write etc. and writes into the DOM without escaping.
# hyperz dom-xss runs in chromedp with --js.
@app.route("/dom-xss")
def dom_xss():
    return """<!doctype html><html><body>
<div id="out"></div>
<script>
  var hash = decodeURIComponent(location.hash.substr(1));
  document.getElementById("out").innerHTML = hash;
</script>
</body></html>"""


# --- nosqli ----------------------------------------------------------------
# Trigger: param accepts mongo-style operator dicts. Hyperz rewrites
# q -> q[$eq]=... or JSON body to {"q":{"$eq":...}} and looks for a
# divergent boolean response between truthy/falsy.
@app.route("/find")
def nosql():
    q = request.args.get("q", "")
    # truthy operator (anything with $) collapses to "match all"; a
    # canary plain string returns "no match" - boolean divergence.
    if "$" in q or "[$" in request.query_string.decode("latin1"):
        return jsonify({"users": [{"name": "alice"}, {"name": "bob"}]})
    if q == "alice":
        return jsonify({"users": [{"name": "alice"}]})
    return jsonify({"users": []})


# --- ldap-injection --------------------------------------------------------
# Same shape as nosqli's boolean oracle: truthy *) payload collapses
# to "all users"; falsy returns "no match".
@app.route("/dir")
def ldap_dir():
    cn = request.args.get("cn", "")
    if "*)" in cn or "*)" in request.query_string.decode("latin1"):
        return jsonify({"matched": ["admin", "alice", "bob", "carol"]})
    # Trigger a recognized LDAP driver error on quote injection so
    # ldap-injection's error-signature path also fires.
    if "(" in cn and ")" not in cn:
        return "ldap_search_ext: Bad search filter (87)", 500
    if cn == "admin":
        return jsonify({"matched": ["admin"]})
    return jsonify({"matched": []})


# --- path-traversal --------------------------------------------------------
# Trigger: param value joined into a filesystem path. ../../etc/passwd
# returns recognizable /etc/passwd content.
@app.route("/file")
def file_read():
    name = request.args.get("name", "")
    base = "/app/files"
    full = os.path.join(base, name)  # no normalization on purpose
    try:
        with open(full, "rb") as f:
            return Response(f.read(), mimetype="text/plain")
    except FileNotFoundError:
        # Fallback: if path escaped /app/files, read directly so a
        # ../etc/passwd probe still returns the system file.
        try:
            with open(name if name.startswith("/") else "/" + name, "rb") as f:
                return Response(f.read(), mimetype="text/plain")
        except Exception as e:
            return f"err: {e}", 404


# --- cmd-injection (in-band) ----------------------------------------------
# Trigger: param interpolated into a shell command and the command's
# stdout is returned. The recognized canary signature ('echo
# <canary>') makes the in-band oracle fire.
@app.route("/run")
def cmd_in_band():
    ip = request.args.get("ip", "127.0.0.1")
    # shell=True + raw interpolation = command injection
    try:
        out = subprocess.check_output(
            f"ping -c1 -W1 {ip}", shell=True, stderr=subprocess.STDOUT, timeout=8
        )
    except subprocess.CalledProcessError as e:
        out = e.output
    return Response(out, mimetype="text/plain")


# --- cmd-injection-blind ---------------------------------------------------
# Trigger: command is run but output is NOT returned. The check
# confirms via OOB callback (curl/wget the canary URL) or via a
# time-delay (sleep). Both paths are supported here.
@app.route("/ping")
def cmd_blind():
    host = request.args.get("host", "127.0.0.1")
    try:
        subprocess.check_output(
            f"echo hello && {host}", shell=True, stderr=subprocess.DEVNULL, timeout=12
        )
    except subprocess.CalledProcessError:
        pass
    return "ok"  # body intentionally tells nothing


# --- ssti ------------------------------------------------------------------
# Trigger: param fed into render_template_string-equivalent so
# {{7*7}} evaluates to 49 in the response. Jinja2 is the canonical
# Python target for the {{ }} dialect.
@app.route("/render")
def ssti():
    name = request.args.get("name", "guest")
    return Template("Hello " + name).render()


# --- idor ------------------------------------------------------------------
# Trigger: numeric-id path with divergent bodies. Hyperz idor walks
# variants and looks for boolean divergence vs baseline.
USERS = {
    "1": {"id": 1, "email": "alice@example.com", "balance": 100},
    "2": {"id": 2, "email": "bob@example.com",   "balance": 250},
    "3": {"id": 3, "email": "carol@example.com", "balance": 999},
}


@app.route("/user/<uid>")
def idor(uid):
    if uid in USERS:
        return jsonify(USERS[uid])
    return jsonify({"error": "not found"}), 404


# --- jwt-vulns -------------------------------------------------------------
# Trigger: JWT signed with weak HMAC secret AND a verifier that
# accepts alg=none. hyperz brute-forces the secret offline, forges
# alg=none tokens, and probes the verifier.
@app.route("/jwt-login")
def jwt_login():
    token = jwt.encode({"sub": "alice", "role": "user"}, JWT_SECRET, algorithm="HS256")
    resp = jsonify({"token": token})
    resp.set_cookie("jwt", token)
    return resp


@app.route("/jwt-me")
def jwt_me():
    auth = request.headers.get("Authorization", "") or request.cookies.get("jwt", "")
    raw = auth.removeprefix("Bearer ").strip()
    if not raw:
        return "no token", 401
    try:
        # Accept alg=none (bug) and also any HS256 token signed with
        # the weak secret. PyJWT 2.x requires algorithms list.
        claims = jwt.decode(
            raw, JWT_SECRET, algorithms=["HS256", "none"], options={"verify_signature": False}
        )
    except Exception as e:
        return f"invalid: {e}", 401
    return jsonify(claims)


# --- graphql-audit ---------------------------------------------------------
# Trigger: /graphql endpoint that supports introspection, batched
# queries, deep nesting, and "Did you mean" suggestion leakage.
SCHEMA_INTROSPECTION = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {"name": "Query", "fields": [{"name": "user"}, {"name": "secret"}]},
                {"name": "User",  "fields": [{"name": "id"}, {"name": "email"}, {"name": "password"}]},
            ],
        }
    }
}


@app.route("/graphql", methods=["GET", "POST"])
def graphql():
    if request.method == "GET":
        # Surface the playground keyword so graphql-audit's body
        # fingerprint identifies this endpoint as a GraphQL surface.
        return ("<!doctype html><body>"
                "<title>GraphiQL Playground</title>"
                "<p>Apollo Sandbox / graphql-yoga</p>"
                "</body>")
    try:
        payload = request.get_json(force=True, silent=True) or {}
    except Exception:
        payload = {}
    # batching: an array of operations
    if isinstance(payload, list):
        return jsonify([{"data": {"ok": True}} for _ in payload])
    q = (payload.get("query") or "").lower()
    if "__schema" in q or "__type" in q:
        return jsonify(SCHEMA_INTROSPECTION)
    if "useer" in q or "passwordd" in q:
        return jsonify({"errors": [{"message": "Cannot query field. Did you mean \"user\" or \"password\"?"}]})
    return jsonify({"data": {"__typename": "Query"}})


# --- sse-audit -------------------------------------------------------------
# Trigger: text/event-stream response that echoes Origin (or wildcards)
# with credentials.
@app.route("/sse")
def sse():
    origin = request.headers.get("Origin", "*")

    @stream_with_context
    def gen():
        yield "data: hello\n\n"

    resp = Response(gen(), mimetype="text/event-stream")
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# --- stored-xss (pollute-gated) -------------------------------------------
# Trigger: input survives past the storage boundary - hyperz plants a
# canary in phase 1 and rereads in phase 2.
COMMENTS = []


@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        body = request.form.get("body") or request.args.get("body", "")
        if body:
            COMMENTS.append(body)
        return redirect("/comments", code=303)
    html = ["<!doctype html><body><h1>comments</h1><ul>"]
    for c in COMMENTS[-50:]:
        html.append(f"<li>{c}</li>")  # raw write -> canary survives + executes
    html.append("</ul></body>")
    return "".join(html)


# --- xxe -------------------------------------------------------------------
# Trigger: POST application/xml body parsed with DTD entity resolution
# enabled. SYSTEM "file:///etc/passwd" returns the file content in
# the response.
@app.route("/xml-form")
def xml_form():
    return """<!doctype html><body>
<form action="/xml" method="post" enctype="text/xml">
  <textarea name="payload"><user><name>alice</name></user></textarea>
  <button>send</button>
</form>
</body>"""


@app.route("/xml", methods=["POST"])
def xml_parse():
    raw = request.get_data() or b""
    if not raw:
        return "empty body", 400
    parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
    try:
        doc = etree.fromstring(raw, parser=parser)
        return Response(etree.tostring(doc, pretty_print=True), mimetype="application/xml")
    except etree.XMLSyntaxError as e:
        return f"xml error: {e}", 400


# --- insecure-deserialization ---------------------------------------------
# Trigger: param value or cookie whose bytes match a serializer
# fingerprint (pickle 'gAS...', java 'rO0AB...', php 'O:...:{', ...).
# We accept a base64'd pickle and unpickle it.
@app.route("/deserialize", methods=["POST"])
def deserialize():
    payload = request.form.get("payload") or request.args.get("payload", "")
    try:
        raw = b64decode(payload, validate=True)
    except Exception:
        return "bad b64", 400
    try:
        obj = pickle.loads(raw)
    except Exception as e:
        # Recognized deserializer error strings let the probe path fire
        # too, not just the fingerprint path.
        return f"pickle: KeyError unpickling: {e}", 500
    return jsonify({"ok": True, "type": type(obj).__name__})


if __name__ == "__main__":
    os.makedirs("/app/files", exist_ok=True)
    with open("/app/files/hello.txt", "w") as f:
        f.write("hello from vuln-app\n")

    # SO_REUSEADDR for quick container restarts
    socket.setdefaulttimeout(30)
    app.run(host="0.0.0.0", port=8080, threaded=True, debug=False)
