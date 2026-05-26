package lua_engine

import (
	"strings"
)

// FormAutocomplete detects sensitive form fields with insecure autocomplete
// settings. Password fields and fields asking for payment / personal info
// should disable browser autocomplete or use context-specific values like
// autocomplete="new-password" to prevent credential interception via
// compromised browser history or other client-side attacks.
type FormAutocomplete struct{}

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
	"off":              {},
	"new-password":     {},
	"current-password": {}, // acceptable for password confirmation / change flows
	"new":              {},
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
