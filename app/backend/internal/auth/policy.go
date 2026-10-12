package auth

import (
	"fmt"
	"strings"
	"unicode"
)

// PasswordPolicy for local users (settings key "password_policy").
type PasswordPolicy struct {
	MinLength int `json:"min_length"`
	// RequireClasses: how many of lower case, upper case, digits and other
	// characters the password must contain (0-4).
	RequireClasses int `json:"require_classes"`
}

// DefaultPolicy: at least 12 characters.
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
	if username != "" && strings.EqualFold(strings.TrimSpace(password), strings.TrimSpace(username)) {
		v = append(v, "must differ from the user name")
	}
	if len(v) > 0 {
		return &PolicyError{Violations: v}
	}
	return nil
}
