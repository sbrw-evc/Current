package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Vault is the part of the OpenBao client auth needs (*secrets.Client).
type Vault interface {
	Resolve(ref string) (string, error)
	PutRef(ctx context.Context, path, key, value string) (string, error)
	Ref(path, key string) string
}

// ErrUnavailable: OpenBao cannot be read or written.
var ErrUnavailable = errors.New("key store (OpenBao) is unavailable")

// Keys are the HMAC keys of sessions, CSRF tokens, API tokens and SPA
// sign-in states, kept in OpenBao at keys#session, keys#csrf, keys#tokens and
// keys#state. Session IDs and API
// tokens are stored in PostgreSQL only as HMACs; the CSRF token is
// HMAC(csrf key, id), so neither a database dump nor the logs give a usable
// token.
type Keys struct {
	vault Vault
}

const (
	KeysPath       = "keys"
	keySession     = "session"
	keyCSRF        = "csrf"
	keyState       = "state"
	keyBytes       = 32
	csrfTokenBytes = 24
)

func NewKeys(v Vault) *Keys { return &Keys{vault: v} }

// Ensure creates the keys that do not exist yet.
func (k *Keys) Ensure(ctx context.Context) error {
	for _, name := range []string{keySession, keyCSRF, keyTokens, keyState} {
		if v, err := k.vault.Resolve(k.vault.Ref(KeysPath, name)); err == nil && v != "" {
			continue
		}
		b := make([]byte, keyBytes)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		if _, err := k.vault.PutRef(ctx, KeysPath, name, base64.StdEncoding.EncodeToString(b)); err != nil {
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	return nil
}

func (k *Keys) key(name string) ([]byte, error) {
	v, err := k.vault.Resolve(k.vault.Ref(KeysPath, name))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) < 16 {
		return nil, fmt.Errorf("%w: key %s is invalid", ErrUnavailable, name)
	}
	return b, nil
}

func mac(key []byte, id string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id))
	return m.Sum(nil)
}

// SessionHash is the stored form of a session ID.
func (k *Keys) SessionHash(id string) (string, error) {
	key, err := k.key(keySession)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(mac(key, id)), nil
}

// CSRF is the CSRF token of a session ID.
func (k *Keys) CSRF(id string) (string, error) {
	key, err := k.key(keyCSRF)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(mac(key, "csrf:"+id)[:csrfTokenBytes]), nil
}

// StateMAC signs the state of an SPA sign-in. The key is created when it does
// not exist yet (an upgrade).
func (k *Keys) StateMAC(ctx context.Context, data string) ([]byte, error) {
	key, err := k.key(keyState)
	if err != nil {
		if err := k.Ensure(ctx); err != nil {
			return nil, err
		}
		if key, err = k.key(keyState); err != nil {
			return nil, err
		}
	}
	return mac(key, "state:"+data), nil
}
