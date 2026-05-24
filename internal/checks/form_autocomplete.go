package checks

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"golang.org/x/net/html"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// FormAutocomplete detects sensitive form fields with insecure autocomplete
// settings. Password fields and fields asking for payment / personal info
// should disable browser autocomplete or use context-specific values like
// autocomplete="new-password" to prevent credential interception via
// compromised browser history or other client-side attacks.
type FormAutocomplete struct{}

func (FormAutocomplete) Name() string { return "form-autocomplete" }

func (FormAutocomplete) Level() Level { return LevelPassive }

// sensitiveInputs maps input type names to their severity when autocomplete
// is not properly restricted. These are informational hardening hints rather
// than exploitable bugs: the threat model (attacker with browser access)
// usually means credentials are already compromised, and modern password
// managers actively rely on autocomplete being enabled.
var sensitiveInputs = map[string]Severity{
	"password": SeverityInfo,
	"email":    SeverityInfo,
	"tel":      SeverityInfo,
	"phone":    SeverityInfo,
	"url":      SeverityInfo,
	"search":   SeverityInfo,
}

// safeAutocompletes is the set of autocomplete values that effectively
// disable storage of sensitive data. "off" disables it entirely; new-password
// tells the browser not to use saved passwords; new (rarely used) is similar.
var safeAutocompletes = map[string]struct{}{
	"off":            {},
	"new-password":   {},
	"current-password": {}, // acceptable for password confirmation / change flows
	"new":            {},
}

func (c FormAutocomplete) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	if p.Body == nil || len(p.Body) == 0 {
		return nil, nil
	}

	z := html.NewTokenizer(bytes.NewReader(p.Body))
	var findings []Finding
	seen := map[string]struct{}{}

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tag, hasAttr := z.TagName()
		if string(tag) != "input" || !hasAttr {
			continue
		}

		var typeAttr, nameAttr, autocompleteAttr string
		for {
			key, val, more := z.TagAttr()
			switch strings.ToLower(string(key)) {
			case "type":
				typeAttr = strings.ToLower(string(val))
			case "name":
				nameAttr = string(val)
			case "autocomplete":
				autocompleteAttr = strings.ToLower(string(val))
			}
			if !more {
				break
			}
		}

		if nameAttr == "" {
			continue
		}

		severity, isSensitive := sensitiveInputs[typeAttr]
		if !isSensitive {
			// Check for pattern-based detection (credit card, SSN, etc.)
			severity, isSensitive = c.detectBySensitivePattern(nameAttr)
		}
		if !isSensitive {
			continue
		}

		if _, safe := safeAutocompletes[autocompleteAttr]; safe {
			continue
		}

		dedupeKey := MakeKey(c.Name(), ScopePage, p.URL, "field:"+nameAttr)
		if _, dup := seen[dedupeKey]; dup {
			continue
		}
		seen[dedupeKey] = struct{}{}

		findings = append(findings, Finding{
			Check:       c.Name(),
			Target:      p.URL,
			URL:         p.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("sensitive form field %q allows browser autocomplete", nameAttr),
			Detail:      fmt.Sprintf("Input field %q (type=%q) at %s does not disable autocomplete. An attacker with access to the browser (malware, physical theft) can retrieve previously entered values from browser history or password manager integration.", nameAttr, typeAttr, p.URL),
			CWE:         "CWE-1021",
			OWASP:       "A05:2021 Security Misconfiguration",
			Remediation: fmt.Sprintf("Add autocomplete=\"off\" (or \"new-password\" for password fields) to the <input> element to prevent browser autocomplete for this field."),
			Evidence:    BuildEvidence("GET", p.URL, p.Status, p.Headers, ""),
			DedupeKey:   dedupeKey,
		})
	}

	return findings, nil
}

// detectBySensitivePattern checks the input name for patterns that indicate
// a sensitive field (credit card number, SSN, etc.) even when the type
// attribute is plain "text".
func (c FormAutocomplete) detectBySensitivePattern(name string) (Severity, bool) {
	lower := strings.ToLower(name)
	// Common naming patterns for sensitive fields; match on substring so
	// cc_number, card-number, cardNumber all match "card".
	patterns := map[string]Severity{
		"card":     SeverityLow,  // credit card field
		"cvv":      SeverityLow,  // card verification value
		"cvc":      SeverityLow,  // same as CVV
		"ssn":      SeverityLow,  // social security number
		"passport": SeverityLow,  // passport number
		"tax":      SeverityLow,  // tax ID
		"account":  SeverityInfo, // bank account (depends on context)
		"pin":      SeverityLow,  // personal identification number
	}
	for pattern, sev := range patterns {
		if strings.Contains(lower, pattern) {
			return sev, true
		}
	}
	return "", false
}
