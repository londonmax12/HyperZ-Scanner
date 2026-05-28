package crypto

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// critProbeExtensionName is the synthetic critical extension we plant
// in the crit list. The "x-hyperz-" prefix guarantees it cannot
// collide with a real extension a validator would recognise (the
// JOSE IANA registry has no entries under that prefix). A spec-
// compliant validator MUST reject any JWT whose crit list contains
// a name it does not understand (RFC 7515 §4.1.11), so acceptance
// of this header by itself is the bug.
const critProbeExtensionName = "x-hyperz-unrecognized"

// probeCritAbuse forges a JWT whose JOSE header declares a synthetic
// extension as critical via the crit list, and includes the
// extension itself so the token is structurally valid. RFC 7515
// requires the validator to reject the token unless it understands
// every name listed in crit; a validator that ignores crit accepts
// the forgery and is exposed to any future critical security
// extension a token might assert.
//
// Two sign paths exist depending on what earlier probes proved
// about this token:
//
//  1. weakSecretFound: the offline crack recovered the HMAC
//     secret. Re-sign with HS256 + crit, send, oracle-compare.
//  2. algNoneAccepted: alg=none was already proven to work. Re-send
//     with crit added to the alg=none header. Acceptance here proves
//     the validator independently ignores crit (acceptance of
//     alg=none alone does not imply crit ignorance, so this is
//     additive).
//
// Without either sign path, the probe has no way to produce a
// token the validator would otherwise consider valid, so it backs
// off rather than emitting a spurious finding from a malformed-
// token rejection.
func (c *JWTVulns) probeCritAbuse(ctx context.Context, client *httpclient.Client, target string, src jwtSource, parsed *parsedJWT, oracle jwtOracle, weakSecret string, weakSecretFound, algNoneAccepted bool) *lua_engine.Finding {
	if weakSecretFound {
		if f := c.critAbuseSigned(ctx, client, target, src, parsed, oracle, weakSecret); f != nil {
			return f
		}
	}
	if algNoneAccepted {
		if f := c.critAbuseAlgNone(ctx, client, target, src, parsed, oracle); f != nil {
			return f
		}
	}
	return nil
}

// critAbuseSigned exercises the crit-ignored bug along the HS256
// branch: build a valid HS256 signature using the secret the
// offline brute recovered, with crit asserted. Acceptance proves
// the validator does not enforce crit even when the rest of the
// token validates cleanly.
func (c *JWTVulns) critAbuseSigned(ctx context.Context, client *httpclient.Client, target string, src jwtSource, parsed *parsedJWT, oracle jwtOracle, secret string) *lua_engine.Finding {
	hdr := cloneHeader(parsed.header)
	hdr["alg"] = "HS256"
	hdr["crit"] = []string{critProbeExtensionName}
	hdr[critProbeExtensionName] = "hyperz-probe"
	sig := hmacSign(sha256.New, []byte(secret), headerPayloadSigning(hdr, parsed.payloadRaw))
	token, err := assembleToken(hdr, parsed.payloadRaw, sig)
	if err != nil {
		return nil
	}
	probe, err := c.send(ctx, client, target, src, token)
	if err != nil {
		return nil
	}
	if !looksAccepted(probe, oracle) {
		return nil
	}
	return buildCritAbuseFinding(target, parsed, token, probe, oracle, "hs256-signed", "the validator accepted a fully-signed JWT whose JOSE crit list names an extension it cannot understand")
}

// critAbuseAlgNone exercises the crit-ignored bug along the alg=none
// branch. Only runs when alg=none was already proven to work; emits
// a finding when the validator additionally accepts the same token
// with a synthetic crit list, because a spec-compliant validator
// must reject on crit even when its alg gate is broken.
func (c *JWTVulns) critAbuseAlgNone(ctx context.Context, client *httpclient.Client, target string, src jwtSource, parsed *parsedJWT, oracle jwtOracle) *lua_engine.Finding {
	hdr := cloneHeader(parsed.header)
	hdr["alg"] = "none"
	hdr["crit"] = []string{critProbeExtensionName}
	hdr[critProbeExtensionName] = "hyperz-probe"
	delete(hdr, "kid")
	token, err := assembleToken(hdr, parsed.payloadRaw, nil)
	if err != nil {
		return nil
	}
	probe, err := c.send(ctx, client, target, src, token)
	if err != nil {
		return nil
	}
	if !looksAccepted(probe, oracle) {
		return nil
	}
	return buildCritAbuseFinding(target, parsed, token, probe, oracle, "alg-none-signed", "the validator accepted an alg=none JWT whose JOSE crit list names an extension it cannot understand")
}

// buildCritAbuseFinding renders the High-severity finding for a
// confirmed crit-ignore bug. Severity is High rather than Critical
// because the finding alone is a compliance defect (the validator
// will silently accept future security-critical extensions); the
// path-specific detail surfaces which signing channel proved the
// behaviour so the remediator can verify the fix end-to-end.
func buildCritAbuseFinding(target string, parsed *parsedJWT, token string, probe jwtSnapshot, oracle jwtOracle, variant, headline string) *lua_engine.Finding {
	originalAlg := asString(parsed.header["alg"])
	detail := fmt.Sprintf(
		"%s. Per RFC 7515 §4.1.11 the validator MUST reject any JWT whose crit list contains a header parameter name "+
			"it does not recognise; this validator silently ignored the assertion. The probe used %q as the synthetic "+
			"extension and re-signed via %s. Original token alg=%s. Forged token landed at the authenticated baseline "+
			"(status %d, similarity %.3f to auth / %.3f to no-auth). A future security-critical extension a token "+
			"asserts via crit will be ignored just as silently.",
		headline, critProbeExtensionName, variant, originalAlg,
		probe.status,
		lua_engine.Similarity(probe.body, oracle.auth.body),
		lua_engine.Similarity(probe.body, oracle.noAuth.body),
	)
	return &lua_engine.Finding{
		Check:    "jwt-vulns",
		Target:   target,
		URL:      target,
		Severity: lua_engine.SeverityHigh,
		Title:    "JWT validator ignores crit header (spec non-compliance)",
		Detail:   detail,
		CWE:      "CWE-347",
		OWASP:    "A02:2021 Cryptographic Failures",
		Remediation: "Enforce RFC 7515 §4.1.11 in the validator: walk the crit list and reject the token if any name is not " +
			"in the set of extensions the validator was configured to understand. Most JWT libraries expose a crit " +
			"handler or required-claims parameter; pass exactly the extension names your tokens use, and let the " +
			"library reject anything else. As defence in depth, log every rejected crit name during the rollout so a " +
			"production token using a legitimate extension you forgot to register fails loudly rather than silently.",
		Evidence: &lua_engine.Evidence{
			Method:     http.MethodGet,
			RequestURL: target,
			Status:     probe.status,
			Snippet: fmt.Sprintf(
				"Sign path: %s\nOriginal alg: %s\nCrit list: [%q]\nForged token: %s\nAuth baseline: status=%d\nNo-auth baseline: status=%d\nProbe response: status=%d\nSimilarity to auth: %.3f\nSimilarity to no-auth: %.3f",
				variant, originalAlg, critProbeExtensionName, redactToken(token),
				oracle.auth.status, oracle.noAuth.status, probe.status,
				lua_engine.Similarity(probe.body, oracle.auth.body),
				lua_engine.Similarity(probe.body, oracle.noAuth.body),
			),
		},
		DedupeKey: lua_engine.MakeKey("jwt-vulns", lua_engine.ScopeHost, target, "crit-abuse", variant),
	}
}
