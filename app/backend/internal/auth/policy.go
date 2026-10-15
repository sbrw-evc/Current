package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// PasswordPolicy for local users (settings key "password_policy"). It is the
// policy of the whole Umbrella family: the same JSON as in Umbrella
// Monitoring, Inventory DB and Network Control, so the hub's policy is copied
// as is (docs/identity-federation.md).
type PasswordPolicy struct {
	MinLength        int    `json:"min_length"`
	RequireDigits    bool   `json:"require_digits"`
	MinDigits        int    `json:"min_digits"`
	RequireSpecial   bool   `json:"require_special"`
	MinSpecial       int    `json:"min_special"`
	RequireMixedCase bool   `json:"require_mixed_case"`
	Letters          string `json:"letters"`
	MaxAgeDays       int    `json:"max_age_days"`
	WarnDays         int    `json:"warn_days"`
	// HistoryCount: a new password must differ from this many previous ones.
	HistoryCount int `json:"history_count"`
	// BlockCommon rejects the most common passwords, keyboard sequences and
	// the user name with a few characters added.
	BlockCommon bool `json:"block_common"`
	// LockoutAttempts wrong passwords in a row lock the account for
	// LockoutMinutes (0 = the built-in limits).
	LockoutAttempts int `json:"lockout_attempts"`
	LockoutMinutes  int `json:"lockout_minutes"`
}

const (
	LettersLatin         = "latin"
	LettersCyrillic      = "cyrillic"
	LettersLatinCyrillic = "latin_cyrillic"
	LettersAny           = "any"

	policyMinLength   = 8
	policyMaxLength   = 128
	policyMaxCount    = 16
	policyMaxAgeDays  = 3650
	policyMaxWarnDays = 90
	policyMaxHistory  = 24
	policyMinLockout  = 3
	policyMaxLockout  = 100
	policyMaxLockMins = 1440
	maxPasswordBytes  = 1024
	ViolationLength   = "length"
	ViolationDigits   = "digits"
	ViolationSpecial  = "special"
	ViolationCase     = "mixed_case"
	ViolationLetters  = "letters"
	ViolationUsername = "username"
	ViolationControl  = "control"
	ViolationCommon   = "common"
	ViolationHistory  = "history"
)

// DefaultPolicy is the corporate default (NIST SP 800-63B / CIS), the same as
// Umbrella Monitoring's.
var DefaultPolicy = PasswordPolicy{MinLength: 12, RequireDigits: true, MinDigits: 1, RequireSpecial: true, MinSpecial: 1,
	RequireMixedCase: true, Letters: LettersLatin, HistoryCount: 5, BlockCommon: true, LockoutAttempts: 10, LockoutMinutes: 15}

// UnmarshalJSON also reads the policy of Flow 1.x ({"min_length", "letters":
// bool, "digits", "symbols", "not_username"}).
func (p *PasswordPolicy) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if l, ok := raw["letters"]; ok && len(l) > 0 && (l[0] == 't' || l[0] == 'f') {
		var old struct {
			MinLength   int  `json:"min_length"`
			Digits      bool `json:"digits"`
			Symbols     bool `json:"symbols"`
			NotUsername bool `json:"not_username"`
		}
		if err := json.Unmarshal(b, &old); err != nil {
			return err
		}
		*p = PasswordPolicy{MinLength: old.MinLength, RequireDigits: old.Digits, RequireSpecial: old.Symbols,
			Letters: LettersAny, BlockCommon: old.NotUsername}
		if old.Digits {
			p.MinDigits = 1
		}
		if old.Symbols {
			p.MinSpecial = 1
		}
		return nil
	}
	type plain PasswordPolicy
	var v plain
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = PasswordPolicy(v)
	return nil
}

// Check reports what is wrong with a policy entered by an administrator.
func (p PasswordPolicy) Check() error {
	switch {
	case p.MinLength < policyMinLength || p.MinLength > policyMaxLength:
		return fmt.Errorf("minimum length must be between %d and %d", policyMinLength, policyMaxLength)
	case p.RequireDigits && (p.MinDigits < 1 || p.MinDigits > policyMaxCount):
		return fmt.Errorf("number of digits must be between 1 and %d", policyMaxCount)
	case p.RequireSpecial && (p.MinSpecial < 1 || p.MinSpecial > policyMaxCount):
		return fmt.Errorf("number of special characters must be between 1 and %d", policyMaxCount)
	case p.Letters != "" && p.Letters != LettersLatin && p.Letters != LettersCyrillic && p.Letters != LettersLatinCyrillic && p.Letters != LettersAny:
		return errors.New("allowed letters must be latin, cyrillic, latin_cyrillic or any")
	case p.MaxAgeDays < 0 || p.MaxAgeDays > policyMaxAgeDays:
		return fmt.Errorf("password lifetime must be between 1 and %d days, or 0", policyMaxAgeDays)
	case p.MaxAgeDays > 0 && (p.WarnDays < 0 || p.WarnDays > policyMaxWarnDays || p.WarnDays >= p.MaxAgeDays):
		return fmt.Errorf("expiry warning must be between 0 and %d days and shorter than the lifetime", policyMaxWarnDays)
	case p.HistoryCount < 0 || p.HistoryCount > policyMaxHistory:
		return fmt.Errorf("password history must be between 0 and %d", policyMaxHistory)
	case p.LockoutAttempts != 0 && (p.LockoutAttempts < policyMinLockout || p.LockoutAttempts > policyMaxLockout):
		return fmt.Errorf("lockout threshold must be between %d and %d, or 0", policyMinLockout, policyMaxLockout)
	case p.LockoutAttempts != 0 && (p.LockoutMinutes < 1 || p.LockoutMinutes > policyMaxLockMins):
		return fmt.Errorf("lockout duration must be between 1 and %d minutes", policyMaxLockMins)
	}
	need := p.MinDigits*b2i(p.RequireDigits) + p.MinSpecial*b2i(p.RequireSpecial) + 2*b2i(p.RequireMixedCase)
	if need > p.MinLength {
		return errors.New("required digits, special characters and letters do not fit into the minimum length")
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Normalize applies defaults and limits (a stored policy is always usable).
func (p PasswordPolicy) Normalize() PasswordPolicy {
	if p.MinLength <= 0 {
		p.MinLength = DefaultPolicy.MinLength
	}
	p.MinLength = min(max(p.MinLength, policyMinLength), policyMaxLength)
	if p.RequireDigits {
		p.MinDigits = min(max(p.MinDigits, 1), policyMaxCount)
	} else {
		p.MinDigits = 0
	}
	if p.RequireSpecial {
		p.MinSpecial = min(max(p.MinSpecial, 1), policyMaxCount)
	} else {
		p.MinSpecial = 0
	}
	switch p.Letters {
	case LettersLatin, LettersCyrillic, LettersLatinCyrillic, LettersAny:
	default:
		p.Letters = LettersAny
	}
	p.MaxAgeDays = min(max(p.MaxAgeDays, 0), policyMaxAgeDays)
	if p.MaxAgeDays == 0 {
		p.WarnDays = 0
	} else {
		p.WarnDays = min(max(p.WarnDays, 0), policyMaxWarnDays, p.MaxAgeDays-1)
	}
	p.HistoryCount = min(max(p.HistoryCount, 0), policyMaxHistory)
	if p.LockoutAttempts <= 0 {
		p.LockoutAttempts, p.LockoutMinutes = 0, 0
	} else {
		p.LockoutAttempts = min(max(p.LockoutAttempts, policyMinLockout), policyMaxLockout)
		p.LockoutMinutes = min(max(p.LockoutMinutes, 1), policyMaxLockMins)
	}
	return p
}

// PolicyError lists the violated rules (length, digits, special, mixed_case,
// letters, username, control, common, history).
type PolicyError struct{ Violations []string }

// PolicyViolations, HTTPStatus and ErrorCode make httpx answer 400
// weak_password with the violations.
func (e *PolicyError) PolicyViolations() []string { return e.Violations }
func (e *PolicyError) HTTPStatus() int            { return 400 }
func (e *PolicyError) ErrorCode() string          { return "weak_password" }

func (e *PolicyError) Error() string {
	return "the password does not meet the policy: " + strings.Join(e.Violations, ", ")
}

func (p PasswordPolicy) letterAllowed(r rune) bool {
	switch p.Letters {
	case LettersLatin:
		return unicode.Is(unicode.Latin, r)
	case LettersCyrillic:
		return unicode.Is(unicode.Cyrillic, r)
	case LettersLatinCyrillic:
		return unicode.Is(unicode.Latin, r) || unicode.Is(unicode.Cyrillic, r)
	}
	return true
}

// Violations lists the rules the password breaks.
func (p PasswordPolicy) Violations(password, username string) []string {
	p = p.Normalize()
	var out []string
	add := func(v string) {
		for _, x := range out {
			if x == v {
				return
			}
		}
		out = append(out, v)
	}
	runes := []rune(password)
	if len(runes) < p.MinLength || len(password) > maxPasswordBytes {
		add(ViolationLength)
	}
	var digits, special int
	var upper, lower bool
	for _, r := range runes {
		switch {
		case unicode.IsControl(r):
			add(ViolationControl)
		case unicode.IsDigit(r):
			digits++
		case unicode.IsLetter(r):
			if !p.letterAllowed(r) {
				add(ViolationLetters)
			}
			upper = upper || unicode.IsUpper(r)
			lower = lower || unicode.IsLower(r)
		case unicode.IsPunct(r) || unicode.IsSymbol(r) || unicode.IsSpace(r):
			special++
		}
	}
	if p.RequireDigits && digits < p.MinDigits {
		add(ViolationDigits)
	}
	if p.RequireSpecial && special < p.MinSpecial {
		add(ViolationSpecial)
	}
	if p.RequireMixedCase && (!upper || !lower) {
		add(ViolationCase)
	}
	if u := strings.TrimSpace(username); u != "" && strings.EqualFold(strings.TrimSpace(password), u) {
		add(ViolationUsername)
	}
	if p.BlockCommon && IsCommonPassword(password, username) {
		add(ViolationCommon)
	}
	return out
}

// Validate checks a password for the user name.
func (p PasswordPolicy) Validate(password, username string) error {
	if v := p.Violations(password, username); len(v) > 0 {
		return &PolicyError{Violations: v}
	}
	return nil
}
