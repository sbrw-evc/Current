// Package auth holds sign-in sessions persisted in PostgreSQL, CSRF tokens,
// API tokens and the keys (in OpenBao) they are derived with. People sign in
// through SPA (internal/spa); Flow keeps no passwords.
package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// RandomToken is prefix + bytes random bytes in base64url.
func RandomToken(prefix string, bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}
