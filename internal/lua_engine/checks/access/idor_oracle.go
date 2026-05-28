package access

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// idorVerdict is what idorJudge returns. Vulnerable is the headline
// signal; Confidence escalates a vulnerable verdict from low (control
// also returned 200, harder to distinguish from per-record content)
// through medium (control rejected, no PII in tampered body) up to
// high (control rejected AND tampered body contains user-data markers).
//
// Detail is a one-line summary the IDOR check folds into the finding's
// Detail field. TamperedSim is exposed so the finding's bullet list
// can show the reader the divergence score that triggered the verdict.
type idorVerdict struct {
	Vulnerable         bool
	Confidence         string
	Detail             string
	TamperedSim        float64
	ControlSim         float64
	TamperedControlSim float64
	PIIHints           []string
}

const (
	idorConfidenceLow    = "low"
	idorConfidenceMedium = "medium"
	idorConfidenceHigh   = "high"

	// idorMaxSim is the upper bound on baseline~tampered similarity
	// that counts as "different content" for the IDOR oracle. Matches
	// lua_engine.SimilarityThreshold so the cutoff is consistent with the boolean
	// SQLi oracle - templated pages with header / footer cruft cluster
	// near 0.99 when content is the same, drop below 0.97 when the
	// middle (the user record) actually changed.
	idorMaxSim = lua_engine.SimilarityThreshold
)

// idorJudge compares baseline (untampered request), tampered (request
// with a different identifier), and control (request with garbage of
// the same shape) snapshots and decides whether the result is
// consistent with IDOR.
//
// The verdict is positive when:
//   - baseline status is 2xx (there's content to compare)
//   - tampered status is 2xx (the app accepted the swapped ID)
//   - baseline and tampered bodies diverge below idorMaxSim (the
//     response actually changed)
//   - control either rejected (non-2xx) OR diverged from tampered (so
//     we're not just seeing the same "any ID accepts" SPA fallback)
//
// Confidence rises when the control rejected (the app validates IDs
// in general - the tampered probe getting through is meaningful) and
// rises further when the tampered body contains markers that look
// like another user's data (emails, name pairs, distinct identifiers
// of the same shape).
func idorJudge(baseline, tampered, control lua_engine.Snapshot) idorVerdict {
	res := idorVerdict{}
	if !is2xx(baseline.Status) || !is2xx(tampered.Status) {
		res.Detail = fmt.Sprintf(
			"baseline/tampered statuses %d/%d - not a 2xx pair, no IDOR signal",
			baseline.Status, tampered.Status)
		return res
	}
	res.TamperedSim = lua_engine.Similarity(baseline.Body, tampered.Body)
	res.ControlSim = lua_engine.Similarity(baseline.Body, control.Body)
	if res.TamperedSim >= idorMaxSim {
		res.Detail = fmt.Sprintf(
			"tampered response ~ baseline (sim=%.3f); ID change had no effect on the body",
			res.TamperedSim)
		return res
	}
	controlRejected := !is2xx(control.Status)
	controlMatchedBaseline := is2xx(control.Status) && res.ControlSim >= idorMaxSim
	if controlMatchedBaseline {
		// Control was accepted with content identical to baseline -
		// the app is returning the same body for any ID. SPA shell
		// or fully public resource; not IDOR.
		res.Detail = fmt.Sprintf(
			"control returned ~baseline (sim=%.3f) - endpoint ignores the ID parameter, suppressing finding",
			res.ControlSim)
		return res
	}
	if is2xx(control.Status) {
		// Control accepted but didn't match baseline: check whether it
		// matches the tampered body instead. If the app returns the
		// same generic response (e.g. a "no such record" 200 page) for
		// every non-seed ID, then tampered diverging from baseline
		// reflects "not the seed user's record" rather than broken
		// authorization. Suppress.
		res.TamperedControlSim = lua_engine.Similarity(tampered.Body, control.Body)
		if res.TamperedControlSim >= idorMaxSim {
			res.Detail = fmt.Sprintf(
				"control and tampered returned ~same content (sim=%.3f) - endpoint serves a generic body for any non-seed ID, suppressing finding",
				res.TamperedControlSim)
			return res
		}
	}
	res.Vulnerable = true
	res.PIIHints = piiHintsIn(tampered.Body)
	switch {
	case controlRejected && len(res.PIIHints) > 0:
		res.Confidence = idorConfidenceHigh
		res.Detail = fmt.Sprintf(
			"app rejected garbage ID (status=%d) but accepted tampered ID and returned distinct content (sim=%.3f) with PII markers (%s)",
			control.Status, res.TamperedSim, joinFirst(res.PIIHints, 3))
	case controlRejected:
		res.Confidence = idorConfidenceMedium
		res.Detail = fmt.Sprintf(
			"app rejected garbage ID (status=%d) but accepted tampered ID and returned distinct content (sim=%.3f)",
			control.Status, res.TamperedSim)
	default:
		res.Confidence = idorConfidenceLow
		res.Detail = fmt.Sprintf(
			"tampered and control both 2xx but each returned distinct content (tampered sim=%.3f, control sim=%.3f) - possible per-record exposure",
			res.TamperedSim, res.ControlSim)
	}
	return res
}

func is2xx(status int) bool {
	return status >= 200 && status < 300
}

// piiPatterns are byte-substring and regex markers that suggest the
// tampered body contains user-record fields - emails, name pairs,
// kv-shaped JSON for sensitive keys. Each hit becomes one bullet in
// the finding's Details list and elevates confidence to High when the
// control rejected.
//
// Conservative on purpose: a marker that fires on benign HTML
// (footer email links, capitalized brand names) would inflate
// confidence on non-IDOR endpoints. The current set sticks to fields
// that real APIs serialize, not free-form text.
var (
	rePIIEmail   = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	rePIINameKV  = regexp.MustCompile(`(?i)"(first_?name|last_?name|full_?name|display_?name)"\s*:\s*"[^"]{1,64}"`)
	rePIIEmailKV = regexp.MustCompile(`(?i)"(email|email_address|user_email)"\s*:\s*"[^"]{1,128}"`)
	rePIIPhoneKV = regexp.MustCompile(`(?i)"(phone|phone_number|mobile|telephone)"\s*:\s*"[^"]{1,32}"`)
	rePIIIDKV    = regexp.MustCompile(`(?i)"(ssn|social|nin|passport|tax_id|account_number|card_last4)"\s*:\s*"[^"]{1,64}"`)
	rePIIAddrKV  = regexp.MustCompile(`(?i)"(street|street_address|address_line_?1|postcode|postal_code|zip|zip_code)"\s*:\s*"[^"]{1,128}"`)
)

func piiHintsIn(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	var hits []string
	if m := rePIINameKV.FindAll(body, 2); len(m) > 0 {
		hits = append(hits, fmt.Sprintf("name field (%s)", string(m[0])))
	}
	if m := rePIIEmailKV.FindAll(body, 2); len(m) > 0 {
		hits = append(hits, fmt.Sprintf("email field (%s)", string(m[0])))
	} else if m := rePIIEmail.Find(body); m != nil && bytes.Contains(bytes.ToLower(body), []byte(`"`)) {
		// Plain email in a JSON-looking body is still useful evidence
		// but rank it below the structured KV hit above.
		hits = append(hits, fmt.Sprintf("plain email (%s)", string(m)))
	}
	if m := rePIIPhoneKV.Find(body); m != nil {
		hits = append(hits, fmt.Sprintf("phone field (%s)", string(m)))
	}
	if m := rePIIIDKV.Find(body); m != nil {
		hits = append(hits, fmt.Sprintf("government/account id field (%s)", string(m)))
	}
	if m := rePIIAddrKV.Find(body); m != nil {
		hits = append(hits, fmt.Sprintf("address field (%s)", string(m)))
	}
	return hits
}

// joinFirst joins up to n entries of hints with a comma so the verdict
// Detail stays one line even when piiHintsIn finds several markers.
func joinFirst(hints []string, n int) string {
	if len(hints) > n {
		hints = hints[:n]
	}
	var b bytes.Buffer
	for i, h := range hints {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(h)
	}
	return b.String()
}
