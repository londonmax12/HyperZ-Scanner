"""
vuln-graphql: a real GraphQL endpoint backed by graphene. Every
graphql-audit probe the scanner ships (introspection, suggestions,
batching, alias amplification, alias-based auth bypass, batched
mutations, depth) resolves against actual graphql-core machinery -
no canned fingerprint responses. The "vulnerability" is the
default-permissive configuration: introspection on, field
suggestions on, no alias/batch/depth limits, and a login mutation
that returns success without consulting any credential store so
alias-bypass reflects N resolves per HTTP request.
"""

from flask import Flask, Response, jsonify, request
import graphene


# --- schema ----------------------------------------------------------------
class User(graphene.ObjectType):
    id = graphene.ID()
    email = graphene.String()
    # `password` is intentionally exposed by the schema so introspection
    # surfaces a privileged field name, which is the canonical "schema
    # disclosure leaks dangerous resolvers" pattern graphql-audit warns
    # about. No actual sensitive data is returned.
    password = graphene.String()


USERS = [
    {"id": "1", "email": "alice@example.com", "password": "hunter2"},
    {"id": "2", "email": "bob@example.com",   "password": "letmein"},
]


class Query(graphene.ObjectType):
    user = graphene.Field(User, id=graphene.ID(required=True))
    secret = graphene.String()

    def resolve_user(root, info, id):
        for u in USERS:
            if u["id"] == id:
                return User(**u)
        return None

    def resolve_secret(root, info):
        return "top-secret-value"


class LoginPayload(graphene.ObjectType):
    token = graphene.String()
    success = graphene.Boolean()


class Login(graphene.Mutation):
    class Arguments:
        email = graphene.String(required=True)
        password = graphene.String(required=True)

    Output = LoginPayload

    def mutate(root, info, email, password):
        # No credential lookup; every invocation produces a fresh
        # resolve. The alias-based auth-bypass and batched-mutations
        # probes both rely on the server actually invoking the
        # resolver N times per HTTP request, which only happens
        # because there's no rate gate on this mutation at any
        # layer.
        return LoginPayload(token="t-{}".format(email), success=False)


class Mutations(graphene.ObjectType):
    login = Login.Field()


schema = graphene.Schema(query=Query, mutation=Mutations)


# --- transport -------------------------------------------------------------
app = Flask(__name__)


@app.route("/")
def index():
    # Linked from the root so the crawler enqueues /graphql.
    return '<!doctype html><body><a href="/graphql">graphql endpoint</a></body>'


@app.route("/graphql", methods=["GET", "POST"])
def graphql_view():
    if request.method == "GET":
        # GraphiQL-shaped HTML so graphql-audit's body fingerprint
        # identifies this endpoint without paying for the discovery
        # POST. The phrases below are matched verbatim by
        # GRAPHQL_BODY_MARKERS in internal/checks/platform/graphql.
        return ("<!doctype html><html><body>"
                "<title>GraphiQL Playground</title>"
                "<p>graphql-yoga / Apollo Sandbox</p>"
                "</body></html>")
    payload = request.get_json(force=True, silent=True)
    if isinstance(payload, list):
        # HTTP-level batching: per-element execution returns an
        # array, which the scanner's probe_batch asserts on.
        return jsonify([_run_one(item) for item in payload])
    return jsonify(_run_one(payload or {}))


def _run_one(item):
    if not isinstance(item, dict):
        item = {}
    query = item.get("query") or ""
    variables = item.get("variables") or {}
    operation_name = item.get("operationName")
    result = schema.execute(query, variables=variables, operation_name=operation_name)
    out = {"data": result.data}
    if result.errors:
        out["errors"] = [_format_error(e) for e in result.errors]
    return out


def _format_error(err):
    # graphql-core's error objects carry .message and .path; the
    # scanner's batch_mutations_executed inspects path[0] to confirm
    # the server actually attempted each batched mutation, so the
    # path must round-trip.
    out = {"message": getattr(err, "message", None) or str(err)}
    path = getattr(err, "path", None)
    if path:
        out["path"] = list(path)
    return out


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, threaded=True)
