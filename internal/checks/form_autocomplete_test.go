package checks

import (
	"context"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestFormAutocompletePassword(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		wantLen int
		wantSev Severity
	}{
		{
			name:    "password without autocomplete",
			html:    `<form><input type="password" name="pwd"></form>`,
			wantLen: 1,
			wantSev: SeverityInfo,
		},
		{
			name:    "password with autocomplete=off",
			html:    `<form><input type="password" name="pwd" autocomplete="off"></form>`,
			wantLen: 0,
		},
		{
			name:    "password with autocomplete=new-password",
			html:    `<form><input type="password" name="pwd" autocomplete="new-password"></form>`,
			wantLen: 0,
		},
		{
			name:    "password with autocomplete=current-password",
			html:    `<form><input type="password" name="pwd" autocomplete="current-password"></form>`,
			wantLen: 0,
		},
		{
			name:    "multiple password fields, first unsafe",
			html:    `<form><input type="password" name="pwd1"><input type="password" name="pwd2" autocomplete="off"></form>`,
			wantLen: 1,
			wantSev: SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := page.Page{
				URL:     "https://example.com/login",
				Status:  200,
				Headers: map[string][]string{},
				Body:    []byte(tt.html),
			}
			c := FormAutocomplete{}
			findings, err := c.Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("Run() error: %v", err)
			}
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d", len(findings), tt.wantLen)
			}
			if tt.wantLen > 0 && findings[0].Severity != tt.wantSev {
				t.Errorf("got severity %v, want %v", findings[0].Severity, tt.wantSev)
			}
		})
	}
}

func TestFormAutocompleteEmail(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		wantLen int
		wantSev Severity
	}{
		{
			name:    "email without autocomplete",
			html:    `<form><input type="email" name="email"></form>`,
			wantLen: 1,
			wantSev: SeverityInfo,
		},
		{
			name:    "email with autocomplete=off",
			html:    `<form><input type="email" name="email" autocomplete="off"></form>`,
			wantLen: 0,
		},
		{
			name:    "tel without autocomplete",
			html:    `<form><input type="tel" name="phone"></form>`,
			wantLen: 1,
			wantSev: SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := page.Page{
				URL:     "https://example.com/signup",
				Status:  200,
				Headers: map[string][]string{},
				Body:    []byte(tt.html),
			}
			c := FormAutocomplete{}
			findings, err := c.Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("Run() error: %v", err)
			}
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d", len(findings), tt.wantLen)
			}
			if tt.wantLen > 0 && findings[0].Severity != tt.wantSev {
				t.Errorf("got severity %v, want %v", findings[0].Severity, tt.wantSev)
			}
		})
	}
}

func TestFormAutocompletePatternDetection(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		wantLen int
		wantSev Severity
	}{
		{
			name:    "credit card field by name pattern",
			html:    `<form><input type="text" name="card_number"></form>`,
			wantLen: 1,
			wantSev: SeverityLow,
		},
		{
			name:    "CVV field without autocomplete",
			html:    `<form><input type="text" name="cvv"></form>`,
			wantLen: 1,
			wantSev: SeverityLow,
		},
		{
			name:    "SSN field without autocomplete",
			html:    `<form><input type="text" name="ssn"></form>`,
			wantLen: 1,
			wantSev: SeverityLow,
		},
		{
			name:    "card field with autocomplete=off",
			html:    `<form><input type="text" name="card_number" autocomplete="off"></form>`,
			wantLen: 0,
		},
		{
			name:    "account field (info severity pattern)",
			html:    `<form><input type="text" name="account_number"></form>`,
			wantLen: 1,
			wantSev: SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := page.Page{
				URL:     "https://example.com/checkout",
				Status:  200,
				Headers: map[string][]string{},
				Body:    []byte(tt.html),
			}
			c := FormAutocomplete{}
			findings, err := c.Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("Run() error: %v", err)
			}
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d", len(findings), tt.wantLen)
			}
			if tt.wantLen > 0 && findings[0].Severity != tt.wantSev {
				t.Errorf("got severity %v, want %v", findings[0].Severity, tt.wantSev)
			}
		})
	}
}

func TestFormAutocompleteEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		wantLen int
	}{
		{
			name:    "input without name attribute is skipped",
			html:    `<form><input type="password"></form>`,
			wantLen: 0,
		},
		{
			name:    "non-input elements are skipped",
			html:    `<form><textarea name="notes"></textarea></form>`,
			wantLen: 0,
		},
		{
			name:    "non-sensitive input types",
			html:    `<form><input type="text" name="username"></form>`,
			wantLen: 0,
		},
		{
			name:    "empty body",
			html:    ``,
			wantLen: 0,
		},
		{
			name:    "self-closing input tag",
			html:    `<input type="password" name="pwd" />`,
			wantLen: 1,
		},
		{
			name:    "case insensitive autocomplete values",
			html:    `<form><input type="password" name="pwd" autocomplete="OFF"></form>`,
			wantLen: 0,
		},
		{
			name:    "case insensitive type detection",
			html:    `<form><input type="PASSWORD" name="pwd"></form>`,
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := page.Page{
				URL:     "https://example.com/",
				Status:  200,
				Headers: map[string][]string{},
				Body:    []byte(tt.html),
			}
			c := FormAutocomplete{}
			findings, err := c.Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("Run() error: %v", err)
			}
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d", len(findings), tt.wantLen)
			}
		})
	}
}

func TestFormAutocompleteDeduplication(t *testing.T) {
	// Same field appearing twice on a page should only produce one finding
	html := `<form>
		<input type="password" name="pwd">
		<input type="password" name="pwd">
	</form>`
	p := page.Page{
		URL:     "https://example.com/",
		Status:  200,
		Headers: map[string][]string{},
		Body:    []byte(html),
	}
	c := FormAutocomplete{}
	findings, err := c.Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (deduplicated)", len(findings))
	}
}
