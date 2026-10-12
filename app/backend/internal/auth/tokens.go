package auth

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
)

// API tokens (docs/integrations.md §1): "flow_" + 32 random bytes in
// base64url. PostgreSQL keeps only HMAC-SHA256(tokens key, token); the key
// lives in OpenBao at keys#tokens and is created on first use.

const (
	// TokenPrefix starts every Flow API token.
	TokenPrefix = "flow_"
	tokenBytes  = 32
	keyTokens   = "tokens"
	// tokenLen is the length of a well-formed token.
	tokenLen = len(TokenPrefix) + 43
)

// NewAPIToken returns a fresh token.
func NewAPIToken() string { return RandomToken(TokenPrefix, tokenBytes) }

// WellFormedToken reports whether s looks like a Flow API token.
func WellFormedToken(s string) bool {
	if len(s) != tokenLen || !strings.HasPrefix(s, TokenPrefix) {
		return false
	}
	for _, r := range s[len(TokenPrefix):] {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// TokenDisplay is the part of a token that may be shown later ("flow_AbCd…").
func TokenDisplay(token string) string {
	if len(token) < len(TokenPrefix)+4 {
		return TokenPrefix + "…"
	}
	return token[:len(TokenPrefix)+4] + "…"
}

// TokenHash is the stored form of an API token. The key is created when it
// does not exist yet (an upgrade from a version without tokens).
func (k *Keys) TokenHash(ctx context.Context, token string) (string, error) {
	key, err := k.key(keyTokens)
	if err != nil {
		if err := k.Ensure(ctx); err != nil {
			return "", err
		}
		if key, err = k.key(keyTokens); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(mac(key, "token:"+token)), nil
}

// BearerToken returns the token of an "Authorization: Bearer" header.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	return tok, tok != ""
}
