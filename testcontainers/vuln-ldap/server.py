"""
vuln-ldap: real ldap3 MOCK_SYNC directory reachable through a
concatenate-the-cn handler. The handler builds `(&(cn={cn})
(objectClass=person))` by string interpolation and hands it to
ldap3.Connection.search; ldap3 parses the resulting filter with
the same RFC 4515 parser the network strategy uses, so injected
operators (`)(|(objectClass=*` truthy, `)(&(objectClass=<canary>`
falsy) actually reshape the matched set, and malformed filters
(unbalanced parens, lone backslash) raise real
LDAPInvalidFilterError. MOCK_SYNC keeps the directory in-process
- no slapd sidecar - while still exercising the real parser.
"""

from flask import Flask, jsonify, request
from ldap3 import Server, Connection, MOCK_SYNC, OFFLINE_AD_2012_R2
from ldap3.core.exceptions import LDAPInvalidFilterError, LDAPException


_BASE_DN = "dc=vuln,dc=local"


def _build_connection():
    server = Server("vuln.ldap", get_info=OFFLINE_AD_2012_R2)
    conn = Connection(
        server,
        user="cn=admin,{}".format(_BASE_DN),
        password="admin",
        client_strategy=MOCK_SYNC,
    )
    for cn, sn in (("admin", "Admin"), ("alice", "Anderson"),
                   ("bob", "Brown"), ("carol", "Carter")):
        conn.strategy.add_entry("cn={},{}".format(cn, _BASE_DN), {
            "objectClass": ["person"],
            "cn": cn,
            "sn": sn,
        })
    conn.bind()
    return conn


CONN = _build_connection()


app = Flask(__name__)


@app.route("/")
def index():
    # Seed link so the crawler enqueues /dir?cn=admin and the scanner
    # discovers the query param as a sink.
    return '<!doctype html><body><a href="/dir?cn=admin">directory</a></body>'


@app.route("/dir")
def dir_lookup():
    cn = request.args.get("cn", "")
    # The bug: cn is concatenated into the LDAP filter with no
    # RFC 4515 escaping. The surrounding AND template is what
    # makes the boolean injection cleanly reshape the matched
    # set instead of producing a syntax error.
    flt = "(&(cn={})(objectClass=person))".format(cn)
    try:
        CONN.search(_BASE_DN, flt, attributes=["cn"])
    except LDAPInvalidFilterError as e:
        # Surface the real ldap3 invalid-filter exception with a
        # phrase the scanner's ldapErrorPatterns recognises
        # ("invalid filter syntax" is in the curated list).
        return ("LDAP invalid filter syntax: {}".format(e), 500)
    except LDAPException as e:
        return ("LDAP error code: {}".format(e), 500)
    matched = [str(entry.cn) for entry in CONN.entries]
    return jsonify({"matched": matched})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8092, threaded=True)
