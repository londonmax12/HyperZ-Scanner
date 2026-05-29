"""
vuln-sqli: real SQLite database reachable through a
concatenate-the-q handler. The handler builds
`SELECT name, role FROM users WHERE name = '{q}'` by string
interpolation and hands it to sqlite3.execute - SQLite parses the
resulting SQL with the same parser any real query goes through, so
boolean injections (`' AND '1'='1` / `' AND '1'='2`) reshape the
matched set and malformed quotes raise real
sqlite3.OperationalError. SLEEP is registered as a UDF so the
scanner's `' AND SLEEP(N)-- -` time-based payload resolves to a
real wall-clock delay through SQLite's expression evaluator; the
SQL injection itself is genuine - only the function body is Python
because SQLite has no built-in SLEEP (unlike MySQL / Postgres /
MSSQL, which the same payload set also targets).

Each Flask worker thread opens its own SQLite connection against a
shared in-memory database (cache=shared URI) so the SQLite per-
connection mutex doesn't serialise a time-based SLEEP probe against
concurrent boolean / error probes. With a single shared connection
the time-based check holds the connection mutex for the full SLEEP
duration and queues every other probe behind it past the scanner's
per-request timeout - a backend-pool-shaped artefact that doesn't
exist in real database-backed apps, which use per-request /
pooled connections. Per-thread connections + shared-cache URI is
the closest stand-in.
"""

import sqlite3
import threading
import time

from flask import Flask, Response, request


DB_URI = "file:vulnsqli?mode=memory&cache=shared"


def _sleep(secs):
    # Bounded to keep a misbehaving probe from pinning the worker for
    # hours; the scanner's default SLEEP placeholder resolves to 5s,
    # well inside this cap.
    capped = max(0.0, min(float(secs), 30.0))
    time.sleep(capped)
    # Returning None makes the AND clause NULL (falsy in SQL), so the
    # row is dropped from the result set after SLEEP has already
    # fired - the timing oracle keys on latency, not body content.
    return None


def _new_connection():
    conn = sqlite3.connect(DB_URI, uri=True, check_same_thread=False)
    conn.create_function("SLEEP", 1, _sleep)
    return conn


# Keeper connection holds the shared-cache in-memory database alive
# even when every per-thread connection is closed; without it SQLite
# tears the memdb down the moment the last connection closes. The
# keeper also seeds the read-only schema once so per-thread
# connections only need to attach.
_keeper = _new_connection()
_keeper.executescript("""
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT);
INSERT INTO users(name, role) VALUES ('alice', 'user');
INSERT INTO users(name, role) VALUES ('bob',   'user');
INSERT INTO users(name, role) VALUES ('carol', 'admin');
""")
_keeper.commit()


_thread_local = threading.local()


def _db():
    conn = getattr(_thread_local, "conn", None)
    if conn is None:
        conn = _new_connection()
        _thread_local.conn = conn
    return conn


app = Flask(__name__)


@app.route("/")
def index():
    # Seed link so the crawler enqueues /search?q=alice and the
    # scanner discovers the query param as a sink. Anchor value
    # `alice` matters: SQLite short-circuits AND per-row, so SLEEP
    # only fires when the equality is true for at least one row,
    # and alice is the row that matches.
    return '<!doctype html><body><a href="/search?q=alice">search</a></body>'


@app.route("/search")
def search():
    q = request.args.get("q", "")
    sql = "SELECT name, role FROM users WHERE name = '{}'".format(q)
    try:
        rows = _db().execute(sql).fetchall()
    except sqlite3.Error as e:
        # Re-emit the exception with the sqlite3.<class> prefix so the
        # response body carries the driver signature the scanner's
        # SQLErrorPatterns recognises (sqlite3.operationalerror,
        # unrecognized token:). The error itself was raised by real
        # SQLite parsing the malformed injected SQL - the prefix just
        # mirrors how a Python web framework's debug page reports it.
        return Response(
            "sqlite3.{}: {}".format(type(e).__name__, e),
            status=500,
            mimetype="text/plain",
        )
    body = ["<ul>"]
    for name, role in rows:
        body.append("<li>{} ({})</li>".format(name, role))
    body.append("</ul>")
    return "".join(body)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8093, threaded=True)
