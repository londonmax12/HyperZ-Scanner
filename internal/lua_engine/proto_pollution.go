package lua_engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
)

// ProtoPollution probes for server-side prototype pollution in
// JavaScript backends (Node / Express / Koa / Fastify) by sending a
// bundled pollution payload through each probable sink, then running
// a clean observer GET against the page URL to look for the
// side-effect of the pollution. Three gadgets ride in one probe so
// that one round-trip per sink is enough to disambiguate the verdict:
//
//  1. "json spaces" gadget: Express's res.json() reads
//     Object.prototype["json spaces"] when no explicit indent is
//     configured. After polluting it to a deliberately unusual value
//     (protoJSONSpaces), every subsequent JSON-emitting endpoint
//     pretty-prints with that indent. The observer's indentation
//     jumping from compact (or any other width) to protoJSONSpaces
//     after the probe is the canonical fingerprint.
//  2. "status" gadget: handlers that fall back to `this.status ||
//     default` pick up the polluted prototype value. An observer
//     status of protoStatusCode that did not appear in the baseline
//     observer confirms the gadget fired.
//  3. Canary echo: a uniquely-named property polluted onto
//     Object.prototype shows up in any response that serializes via
//     for-in / Object.keys patterns. The canary value is fresh per
//     probe so a hit can only be the polluted property echoing back.
//
// Sink wire shape:
//   - LocJSON: nested `{"__proto__":{...}, "constructor":{"prototype":{...}}}` body.
//   - LocQuery / LocForm: bracket notation (`__proto__[json spaces]=7`,
//     `constructor[prototype][...]=...`) - the form a qs / body-parser
//     stack expands into the same nested object on the backend.
//
// The pollution PERSISTS on the target's process - Object.prototype
// is shared across every request handled by the same Node process.
// After every probe the check sends a best-effort cleanup payload
// that overwrites the polluted properties with neutral values
// (`json spaces=0`, empty canary). This cannot DELETE a polluted
// property, only overwrite it, so a successful finding still implies
// a (now-neutralized) modification to the target's shared object
// state. Run accordingly.
//
// Header / cookie / path sinks are not probed: their values are
// taken as opaque strings by every common framework and never reach
// the bracket-expanding parser or merge utility that turns the
// payload into a nested object.
//
// This is an active (LevelAggressive) check.
type ProtoPollution struct{}

const (
	// protoPollutionBodyCap matches SSTI's cap. The observer's body
	// is scanned for JSON indentation and a canary substring; both
	// signals land in the first few hundred bytes of any pretty-
	// printed JSON, so a 32 KiB window is plenty without inflating
	// per-probe memory on pages that return large HTML bodies under
	// pollution conditions (e.g. an error template).
	protoPollutionBodyCap = 32 << 10

	// protoJSONSpaces is the indentation width the json-spaces gadget
	// installs onto Object.prototype. Chosen to be unusual: 2 and 4
	// are the dominant pretty-print widths (jq, Node REPL, browser
	// devtools, every JSON-pretty middleware default), so a response
	// suddenly indented to 7 spaces is overwhelmingly likely to be
	// our gadget rather than the app's own formatting.
	protoJSONSpaces = 7

	// protoStatusCode is the HTTP status the status gadget installs.
	// 510 ("Not Extended") is rarely returned by real applications -
	// it's an old extension-negotiation status no mainstream
	// framework defaults to - so an observer that flips from any
	// other status to 510 after the probe is a high-signal gadget
	// hit. Chosen over 511 (Network Authentication Required) which
	// proxies sometimes surface, and over 5xx generally because the
	// app itself may legitimately emit 500 under load.
	protoStatusCode = 510

	// protoCleanupTimeout caps the detached cleanup request that
	// runs after every probe. The cleanup uses a context detached
	// from the per-page ctx (see probe) so a user-initiated cancel
	// mid-probe still gets a fighting chance to overwrite the
	// gadgets we just installed. 5s is generous enough for one
	// round-trip on any reachable host without holding a worker
	// slot indefinitely on a stalled cleanup.
	protoCleanupTimeout = 5 * time.Second
)

// sinkProbable reports whether sink.Loc carries prototype-pollution
// risk. Query, form, and JSON body inputs all reach the bracket-
// notation parsers (qs, body-parser) or merge-style assemblers
// (lodash.merge, Object.assign) that are the classic SSPP entry
// points; header / cookie / path values are taken as opaque strings
// by every common framework and never reach the parser that turns
// `__proto__[x]` into a nested object.
func (ProtoPollution) sinkProbable(s Sink) bool {
	switch s.Loc {
	case LocQuery, LocForm, LocJSON:
		return true
	}
	return false
}

// ppObservation is the slice of an HTTP response the verdict needs:
// status (for the status gadget), headers (for content-type sniffing
// when deciding whether the json-spaces gadget can apply), and body
// (for both indentation and canary-echo scans).
type ppObservation struct {
	Status  int
	Headers http.Header
	Body    []byte
}

// observe issues a clean GET against pageURL and captures the
// response shape needed by the verdict. No probe payload rides on
// this request: the observer is meant to witness the pollution's
// side-effect on a request that itself does nothing suspicious, so
// the gadget hit cannot be confused with a reflection of the
// pollution probe.
func (ProtoPollution) observe(ctx context.Context, client *httpclient.Client, pageURL string) (ppObservation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return ppObservation{}, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return ppObservation{}, err
	}
	defer resp.Body.Close()
	body, _, err := httpclient.ReadBodyCapped(resp, protoPollutionBodyCap)
	if err != nil {
		return ppObservation{}, err
	}
	return ppObservation{
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
		Body:    body,
	}, nil
}

// probe runs one sink through the pollute / observe / cleanup loop
// and folds the verdict into a Finding when any gadget fires. The
// cleanup is deferred so the polluted prototype is overwritten with
// neutral values regardless of detection outcome - we still touched
// shared state even on a no-signal probe.
func (c ProtoPollution) probe(ctx context.Context, client *httpclient.Client, pageURL string, sink Sink, baseObs ppObservation) (*Finding, error) {
	canaryKey := "pp" + NewCanary()
	canaryVal := NewCanary()

	polluteReq, polluteResp, err := c.pollute(ctx, client, sink, canaryKey, canaryVal)
	if err != nil {
		return nil, fmt.Errorf("pollute: %w", err)
	}
	if polluteResp != nil {
		polluteResp.Body.Close()
	}
	// Cleanup runs after every probe to minimize the pollution's
	// blast radius on the target. Best-effort: we can overwrite the
	// gadgets we set, but not delete them - a polluted prototype
	// retains the property until the process restarts.
	//
	// The cleanup context is detached from ctx and given its own
	// short deadline so a user-initiated cancel mid-probe doesn't
	// strand the polluted state. Without this, ctx.Err() != nil at
	// defer time would cause http.NewRequestWithContext / client.Do
	// to fail immediately and the gadgets we just installed would
	// remain on the prototype until the target process restarts.
	defer func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), protoCleanupTimeout)
		defer cancelCleanup()
		c.cleanup(cleanupCtx, client, sink, canaryKey)
	}()

	obs, err := c.observe(ctx, client, pageURL)
	if err != nil {
		return nil, fmt.Errorf("post-pollution observer: %w", err)
	}

	verdict := ppJudge(baseObs, obs, canaryVal)
	if !verdict.Hit {
		return nil, nil
	}

	method, probeURL := requestIdentity(polluteReq)
	return &Finding{
		Check:    "proto-pollution",
		Target:   pageURL,
		URL:      probeURL,
		Severity: SeverityHigh,
		Title:    fmt.Sprintf("Server-side prototype pollution via %s parameter %q", sink.Loc, sink.Name),
		Detail: fmt.Sprintf(
			"Parameter %q (%s) reached an object-merge or bracket-expanding parser on the backend: "+
				"a pollution payload set Object.prototype properties that altered a subsequent clean "+
				"observer request against %s. %s. An attacker can poison shared object state to "+
				"bypass authorization checks, manipulate response behavior, or - depending on the "+
				"gadget surface - achieve remote code execution.",
			sink.Name, sink.Loc, pageURL, verdict.Detail),
		Details: []string{
			fmt.Sprintf("gadget: %s", verdict.Gadget),
			fmt.Sprintf("canary: %s=%s", canaryKey, canaryVal),
			fmt.Sprintf("baseline observer: status=%d body=%dB", baseObs.Status, len(baseObs.Body)),
			fmt.Sprintf("post-pollution observer: status=%d body=%dB", obs.Status, len(obs.Body)),
			"cleanup payload overwrote the gadget values; polluted properties remain on the prototype until process restart",
		},
		CWE:   "CWE-1321",
		OWASP: "A03:2021 Injection",
		Remediation: "Reject or strip dangerous keys (`__proto__`, `constructor`, `prototype`) at the JSON / " +
			"body / query parser boundary. Prefer `Object.create(null)` for any object that will be merged " +
			"with user input. Avoid recursive-merge utilities (`lodash.merge`, hand-rolled deep-assign) on " +
			"untrusted payloads; use schema-validated DTOs instead. As a defense in depth, freeze " +
			"`Object.prototype` at process start with `Object.freeze(Object.prototype)` so even a missed " +
			"sanitization step cannot mutate the shared prototype.",
		Evidence: &Evidence{
			Method:     method,
			RequestURL: probeURL,
			Status:     statusOf(polluteResp),
			Snippet:    snippet(obs.Body, []byte(verdict.Needle), false),
			Exchange:   RecordExchange(polluteReq, nil, false, polluteResp, nil, false),
		},
		DedupeKey: MakeKey("proto-pollution", ScopeParam, pageURL, "loc:"+string(sink.Loc), "param:"+sink.Name),
	}, nil
}

// pollute dispatches the bundled-gadget pollution payload to sink and
// returns the request / response pair for evidence. The pollute
// response body is not read - the observer is what carries the
// signal; reading the pollute response only wastes bandwidth.
func (c ProtoPollution) pollute(ctx context.Context, client *httpclient.Client, sink Sink, canaryKey, canaryVal string) (*http.Request, *http.Response, error) {
	req, err := c.buildPolluteRequest(ctx, sink, canaryKey, canaryVal)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, err
	}
	return req, resp, nil
}

// buildPolluteRequest constructs the per-sink pollution request. The
// payload bundles all three gadgets (canary echo, json-spaces,
// status) so one request per sink is enough to disambiguate the
// verdict on the observer side. Both `__proto__` and
// `constructor.prototype` paths are sent because the parsing layer
// at the target may filter one and accept the other.
func (c ProtoPollution) buildPolluteRequest(ctx context.Context, sink Sink, canaryKey, canaryVal string) (*http.Request, error) {
	method := strings.ToUpper(sink.Method)
	if method == "" {
		method = http.MethodPost
	}
	switch sink.Loc {
	case LocQuery:
		u, err := url.Parse(sink.URL)
		if err != nil {
			return nil, fmt.Errorf("parse url %q: %w", sink.URL, err)
		}
		q := u.Query()
		c.addBracketPollution(q, canaryKey, canaryVal)
		u.RawQuery = q.Encode()
		return http.NewRequestWithContext(ctx, method, u.String(), nil)
	case LocForm:
		body := url.Values{}
		c.addBracketPollution(body, canaryKey, canaryVal)
		req, err := http.NewRequestWithContext(ctx, method, sink.URL, strings.NewReader(body.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	case LocJSON:
		body := map[string]any{
			"__proto__": map[string]any{
				canaryKey:     canaryVal,
				"json spaces": protoJSONSpaces,
				"status":      protoStatusCode,
			},
			"constructor": map[string]any{
				"prototype": map[string]any{
					canaryKey:     canaryVal,
					"json spaces": protoJSONSpaces,
					"status":      protoStatusCode,
				},
			},
		}
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal pollution body: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, method, sink.URL, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}
	return nil, fmt.Errorf("proto-pollution: unsupported sink loc %q", sink.Loc)
}

// addBracketPollution installs the bracket-notation form of the three
// gadgets into v. Same key set as the LocJSON branch so the verdict
// can treat the wire shapes as interchangeable signals.
func (ProtoPollution) addBracketPollution(v url.Values, canaryKey, canaryVal string) {
	v.Set("__proto__["+canaryKey+"]", canaryVal)
	v.Set("__proto__[json spaces]", strconv.Itoa(protoJSONSpaces))
	v.Set("__proto__[status]", strconv.Itoa(protoStatusCode))
	v.Set("constructor[prototype]["+canaryKey+"]", canaryVal)
	v.Set("constructor[prototype][json spaces]", strconv.Itoa(protoJSONSpaces))
	v.Set("constructor[prototype][status]", strconv.Itoa(protoStatusCode))
}

// cleanup re-pollutes with neutral values to overwrite the gadgets
// the probe installed. The polluted properties remain on
// Object.prototype until the target process restarts - JavaScript
// has no protocol-level "delete prototype property" - so this only
// neutralizes the observable side-effects of the gadgets we set,
// not the pollution itself.
//
// Errors are intentionally swallowed: a transport failure here would
// only inflate noise in the report without changing the outcome (the
// pollution already happened; we just couldn't overwrite it). The
// finding text already calls out the persistence so the reviewer
// isn't surprised by the lingering state.
func (c ProtoPollution) cleanup(ctx context.Context, client *httpclient.Client, sink Sink, canaryKey string) {
	req, err := c.buildCleanupRequest(ctx, sink, canaryKey)
	if err != nil {
		return
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// buildCleanupRequest mirrors buildPolluteRequest's wire shape but
// substitutes neutral values: json-spaces back to 0 (compact, the
// Express default), the canary set to empty, and status to 0. JS
// treats 0 as falsy, so the canonical `res.status(this.status ||
// default).json(...)` gadget pattern falls through to its default
// status once the polluted value is 0. We cannot DELETE the
// prototype property over the wire, but a falsy overwrite restores
// the visible behaviour for any handler that gates on
// truthiness.
func (c ProtoPollution) buildCleanupRequest(ctx context.Context, sink Sink, canaryKey string) (*http.Request, error) {
	method := strings.ToUpper(sink.Method)
	if method == "" {
		method = http.MethodPost
	}
	switch sink.Loc {
	case LocQuery:
		u, err := url.Parse(sink.URL)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		c.addBracketCleanup(q, canaryKey)
		u.RawQuery = q.Encode()
		return http.NewRequestWithContext(ctx, method, u.String(), nil)
	case LocForm:
		body := url.Values{}
		c.addBracketCleanup(body, canaryKey)
		req, err := http.NewRequestWithContext(ctx, method, sink.URL, strings.NewReader(body.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	case LocJSON:
		body := map[string]any{
			"__proto__": map[string]any{
				canaryKey:     "",
				"json spaces": 0,
				"status":      0,
			},
			"constructor": map[string]any{
				"prototype": map[string]any{
					canaryKey:     "",
					"json spaces": 0,
					"status":      0,
				},
			},
		}
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, sink.URL, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}
	return nil, fmt.Errorf("proto-pollution: unsupported sink loc %q", sink.Loc)
}

func (ProtoPollution) addBracketCleanup(v url.Values, canaryKey string) {
	v.Set("__proto__["+canaryKey+"]", "")
	v.Set("__proto__[json spaces]", "0")
	v.Set("__proto__[status]", "0")
	v.Set("constructor[prototype]["+canaryKey+"]", "")
	v.Set("constructor[prototype][json spaces]", "0")
	v.Set("constructor[prototype][status]", "0")
}

// ppVerdict is ppJudge's structured return: Hit is the headline
// signal, Gadget names which of the three side-effects fired, Detail
// is the human-readable summary the finding folds into its Detail
// field, and Needle is the byte sequence the snippet helper anchors
// on so the evidence preserves whatever rendered the gadget hit.
type ppVerdict struct {
	Hit    bool
	Gadget string
	Detail string
	Needle string
}

// ppJudge compares the pre-pollution observer (baseline) against the
// post-pollution observer and decides whether any of the three
// gadgets fired. Gadgets are checked in order of decreasing
// specificity: the status gadget is the cleanest (a single integer
// shifted to an unusual value), json-spaces is mid-specificity (an
// unusual indent width on a JSON response), and canary echo is the
// most permissive (any presence of the canary value).
//
// Every gadget guards against pre-existing baseline state: a hit
// only counts when the side-effect was absent in the baseline
// observer, so an endpoint that always returns 510 (or pretty-prints
// at 7 spaces, or happens to echo the canary) cannot fire a false
// positive on its own behaviour.
func ppJudge(baseline, observer ppObservation, canaryVal string) ppVerdict {
	if observer.Status == protoStatusCode && baseline.Status != protoStatusCode {
		return ppVerdict{
			Hit:    true,
			Gadget: "status",
			Detail: fmt.Sprintf(
				"clean observer GET returned status %d after pollution (baseline was %d); the polluted "+
					"Object.prototype.status leaked into the response status default",
				observer.Status, baseline.Status),
			Needle: strconv.Itoa(protoStatusCode),
		}
	}

	if isJSONResponse(observer.Headers, observer.Body) {
		baseIndent := jsonIndentWidth(baseline.Body)
		obsIndent := jsonIndentWidth(observer.Body)
		if obsIndent == protoJSONSpaces && baseIndent != protoJSONSpaces {
			return ppVerdict{
				Hit:    true,
				Gadget: "json spaces",
				Detail: fmt.Sprintf(
					"clean observer GET returned JSON indented to %d spaces after pollution (baseline was %d); "+
						"the polluted Object.prototype['json spaces'] is being read by res.json()",
					obsIndent, baseIndent),
				Needle: "\n" + strings.Repeat(" ", protoJSONSpaces),
			}
		}
	}

	if len(canaryVal) > 0 &&
		bytes.Contains(observer.Body, []byte(canaryVal)) &&
		!bytes.Contains(baseline.Body, []byte(canaryVal)) {
		return ppVerdict{
			Hit:    true,
			Gadget: "canary echo",
			Detail: fmt.Sprintf(
				"clean observer GET body now contains the pollution canary %q (absent from baseline); "+
					"the polluted prototype property is being enumerated into the response",
				canaryVal),
			Needle: canaryVal,
		}
	}

	return ppVerdict{}
}

// isJSONResponse reports whether the observer response should be
// considered for the json-spaces gadget. Content-Type wins when
// present; otherwise a body that starts with `{` or `[` after
// whitespace stripping is treated as JSON (some APIs return correct
// JSON without setting the header).
func isJSONResponse(h http.Header, body []byte) bool {
	if h != nil {
		ct := strings.ToLower(h.Get("Content-Type"))
		if strings.Contains(ct, "application/json") || strings.Contains(ct, "+json") {
			return true
		}
	}
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}

// jsonIndentWidth returns the GCD of indent widths observed across
// every indented line in body, or 0 when no indentation is observed.
// Detection is the simple "newline followed by N spaces followed by
// a non-space non-newline byte" pattern - JSON.stringify(value,
// null, N) always produces exactly this shape for any nested
// object or array. Tabs are not treated as indentation: the
// json-spaces gadget configures a space count, never a tab count.
//
// GCD recovers the per-call indent unit regardless of which depth
// appears first in the body. JSON.stringify(value, null, 7) on a
// nested document produces 7-space (depth 1), 14-space (depth 2),
// 21-space (depth 3), ... prefixes; GCD(7, 14, 21, ...) = 7, which
// is what the gadget installed. A first-line-wins scan also lands
// on 7 in practice (depth 1 is emitted before depth 2), but GCD is
// robust to bodies where an HTTP / template preamble pushes the
// first indented run to an inner depth. On a body that mixes two
// genuinely independent indent units (e.g. an outer document at 2
// concatenated with an inner raw-JSON blob at 7) GCD collapses to
// 1, which deliberately suppresses a verdict the scanner cannot
// safely attribute.
func jsonIndentWidth(body []byte) int {
	gcd := 0
	for i := 0; i < len(body)-1; i++ {
		if body[i] != '\n' {
			continue
		}
		count := 0
		j := i + 1
		for j < len(body) && body[j] == ' ' {
			count++
			j++
		}
		if count == 0 || j >= len(body) || body[j] == '\n' || body[j] == ' ' {
			continue
		}
		if gcd == 0 {
			gcd = count
			continue
		}
		gcd = intGCD(gcd, count)
		if gcd == 1 {
			return 1
		}
	}
	return gcd
}

func intGCD(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
