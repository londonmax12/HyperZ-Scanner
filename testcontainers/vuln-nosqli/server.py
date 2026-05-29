"""
vuln-nosqli: real MongoDB-shaped backend (mongomock) reachable
through a deserialize-the-bracket-form handler. The handler takes
the request's query string apart, rebuilds the operator dict
(`q[$eq]=alice` -> {"$eq": "alice"}, `q[$in][0]=alice` ->
{"$in": ["alice"]}), and hands the dict to coll.find() unchanged.
mongomock evaluates $eq / $ne / $in / $gt with the same semantics
pymongo would, so the boolean oracle's truthy ~ baseline / falsy
!= baseline divergence is produced by real Mongo-style matching,
not a hand-rolled if/else.
"""

from flask import Flask, jsonify, request
import mongomock


mongo = mongomock.MongoClient()
coll = mongo["vuln"]["users"]
coll.insert_many([
    {"name": "alice", "role": "user"},
    {"name": "bob",   "role": "user"},
    {"name": "carol", "role": "admin"},
])


app = Flask(__name__)


@app.route("/")
def index():
    # Seed link so the crawler enqueues /find?q=alice and the scanner
    # discovers the query param as a sink.
    return '<!doctype html><body><a href="/find?q=alice">find</a></body>'


@app.route("/find")
def find():
    filter_ = _build_filter("q", "name")
    try:
        users = list(coll.find(filter_))
    except Exception as e:
        # mongomock surfaces real driver-shaped errors when given a
        # malformed operator dict. Prefix with the pymongo class path
        # so the response body carries a signature the nosqli error
        # oracle's mongoErrorPatterns recognises.
        return ("pymongo.errors.{}: {}".format(type(e).__name__, e), 500)
    return jsonify({"users": [{"name": u["name"]} for u in users]})


def _build_filter(src_name, dst_field):
    """Translate request.args into a Mongo-style filter dict.

    Plain `?q=alice`           -> {"name": "alice"}
    Operator `?q[$eq]=alice`   -> {"name": {"$eq": "alice"}}
    Array op `?q[$in][0]=al`   -> {"name": {"$in": ["al"]}}
    Multiple `?q[$in][0]=a&q[$in][1]=b` -> {"name": {"$in": ["a","b"]}}
    """
    plain = request.args.get(src_name)
    if plain is not None and not any(k.startswith(src_name + "[") for k in request.args.keys()):
        return {dst_field: plain}

    nested = {}
    for key in request.args.keys():
        if not key.startswith(src_name + "["):
            continue
        path = _parse_bracket_path(key[len(src_name):])
        if not path:
            continue
        for val in request.args.getlist(key):
            _assign_path(nested, path, val)
    if not nested:
        return {dst_field: ""}
    return {dst_field: nested}


def _parse_bracket_path(rest):
    parts = []
    i = 0
    while i < len(rest):
        if rest[i] != "[":
            return []
        end = rest.find("]", i)
        if end == -1:
            return []
        parts.append(rest[i + 1:end])
        i = end + 1
    return parts


def _assign_path(target, path, value):
    """Walk path into target, creating nested dicts; the final
    segment is set to value (or appended into a list when the
    segment is numeric)."""
    cur = target
    for seg in path[:-1]:
        nxt = cur.get(seg)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[seg] = nxt
        cur = nxt
    last = path[-1]
    if last.isdigit():
        # `$in[0]=x` -> list slot. Promote the parent so the operator
        # carries a list value (mongomock requires $in's RHS to be a
        # sequence).
        # The parent for the last segment is `cur`; we need to find
        # the operator segment that wraps this list. Re-walk: the
        # immediate container at `cur` should become a list keyed by
        # the prior segment. Simpler: rebuild as list when numeric
        # final segment is detected.
        if len(path) < 2:
            cur[last] = value
            return
        # cur is the operator dict (e.g. {"$in": ?}); promote that
        # value into a list and place at index.
        parent_chain = path[:-1]
        # Re-walk to find the grandparent and the operator key.
        gp = target
        for seg in parent_chain[:-1]:
            gp = gp[seg]
        op_key = parent_chain[-1]
        lst = gp.get(op_key)
        if not isinstance(lst, list):
            lst = []
            gp[op_key] = lst
        idx = int(last)
        while len(lst) <= idx:
            lst.append(None)
        lst[idx] = value
        return
    cur[last] = value


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8091, threaded=True)
