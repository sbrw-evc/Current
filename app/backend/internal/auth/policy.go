package auth

import (
	"fmt"
	"strings"
	"unicode"
)

// PasswordPolicy for local users (settings key "password_policy").
// The web console edits min_length, letters, digits, symbols and
// not_username (the same rules are checked in the browser).
type PasswordPolicy struct {
	MinLength int `json:"min_length"`
	// Letters, Digits, Symbols: the password must contain at least one
	// letter / digit / other character.
	Letters bool `json:"letters"`
	Digits  bool `json:"digits"`
	Symbols bool `json:"symbols"`
	// NotUsername: the password must not contain the user name.
	NotUsername bool `json:"not_username"`
	// RequireClasses: how many of lower case, upper case, digits and other
	// characters the password must contain (0-4); for API clients, not shown
	// in the console.
	RequireClasses int `json:"require_classes,omitempty"`
}

// DefaultPolicy: at least 12 characters (the console proposes letters,
// digits and not_username on top and sends its policy with the setup).
var DefaultPolicy = PasswordPolicy{MinLength: 12}

// Normalize applies defaults and limits.
func (p PasswordPolicy) Normalize() PasswordPolicy {
	if p.MinLength <= 0 {
		p.MinLength = DefaultPolicy.MinLength
	}
	p.MinLength = min(max(p.MinLength, 8), 128)
	p.RequireClasses = min(max(p.RequireClasses, 0), 4)
	return p
}

// PolicyError lists what the password lacks.
type PolicyError struct{ Violations []string }

func (e *PolicyError) Error() string {
	return "the password does not meet the policy: " + strings.Join(e.Violations, "; ")
}

// Validate checks a password for the user name.
func (p PasswordPolicy) Validate(password, username string) error {
	p = p.Normalize()
	var v []string
	if n := len([]rune(password)); n < p.MinLength {
		v = append(v, fmt.Sprintf("at least %d characters", p.MinLength))
	}
	if len(password) > 1024 {
		v = append(v, "at most 1024 bytes")
	}
	var lower, upper, digit, other bool
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			classes++
		}
	}
	if classes < p.RequireClasses {
		v = append(v, fmt.Sprintf("characters of at least %d kinds (lower case, upper case, digits, symbols)", p.RequireClasses))
	}
	if p.Letters && !(lower || upper || hasLetter(password)) {
		v = append(v, "at least one letter")
	}
	if p.Digits && !digit {
		v = append(v, "at least one digit")
	}
	if p.Symbols && !other {
		v = append(v, "at least one symbol")
	}
	u := strings.ToLower(strings.TrimSpace(username))
	switch {
	case u == "":
	case p.NotUsername && strings.Contains(strings.ToLower(password), u):
		v = append(v, "must not contain the user name")
	case strings.EqualFold(strings.TrimSpace(password), u):
		v = append(v, "must differ from the user name")
	}
	if len(v) > 0 {
		return &PolicyError{Violations: v}
	}
	return nil
}

// hasLetter reports letters without case (e.g. CJK), which IsLower / IsUpper miss.
func hasLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}
