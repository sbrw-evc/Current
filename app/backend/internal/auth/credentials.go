package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Vault is the part of the OpenBao client auth needs (*secrets.Client).
type Vault interface {
	Resolve(ref string) (string, error)
	PutRef(ctx context.Context, path, key, value string) (string, error)
	Ref(path, key string) string
}

// ErrUnavailable: OpenBao cannot be read or written.
var ErrUnavailable = errors.New("password store (OpenBao) is unavailable")

const hashKey = "password_hash"

// Passwords keeps local users' password hashes in OpenBao at users/<id>,
// as Umbrella does; PostgreSQL holds only the openbao:// reference.
type Passwords struct{ vault Vault }

func NewPasswords(v Vault) *Passwords { return &Passwords{vault: v} }

// PasswordPath is the OpenBao path of a user's password hash.
func PasswordPath(userID int64) string { return "users/" + strconv.FormatInt(userID, 10) }

// Set hashes the password, stores the hash and returns its reference.
func (p *Passwords) Set(ctx context.Context, userID int64, password string) (string, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	ref, err := p.vault.PutRef(ctx, PasswordPath(userID), hashKey, hash)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return ref, nil
}

// Verify checks a password against the hash behind ref ("" = no password:
// the check still takes the same time and fails).
func (p *Passwords) Verify(ref, password string) (bool, error) {
	if ref == "" {
		CheckPassword("", password)
		return false, nil
	}
	hash, err := p.vault.Resolve(ref)
	if err != nil {
		CheckPassword("", password)
		return false, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return CheckPassword(hash, password), nil
}

// Keys are the HMAC keys of sessions, CSRF tokens and API tokens, kept in
// OpenBao at keys#session, keys#csrf and keys#tokens. Session IDs and API
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
	keyBytes       = 32
	csrfTokenBytes = 24
)

func NewKeys(v Vault) *Keys { return &Keys{vault: v} }

// Ensure creates the keys that do not exist yet.
func (k *Keys) Ensure(ctx context.Context) error {
	for _, name := range []string{keySession, keyCSRF, keyTokens} {
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

// HistoryPath keeps the hashes of a user's previous passwords, newest first.
func HistoryPath(userID int64) string { return PasswordPath(userID) + "/history" }

const historyKey = "hashes"

// ErrReused: the new password is the current one or a remembered previous one.
var ErrReused = errors.New("the password was used before")

// Replace sets a new password and remembers the previous hash, keeping keep
// of them. With check the new password is refused (ErrReused) when it matches
// the current one or a remembered one.
func (p *Passwords) Replace(ctx context.Context, userID int64, currentRef, password string, keep int, check bool) (string, error) {
	var current string
	if currentRef != "" {
		h, err := p.vault.Resolve(currentRef)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		current = h
	}
	history := p.history(userID)
	if check && keep > 0 {
		for _, h := range append([]string{current}, history...)[:min(keep, len(history)+1)] {
			if h != "" && CheckPassword(h, password) {
				return "", ErrReused
			}
		}
	}
	ref, err := p.Set(ctx, userID, password)
	if err != nil {
		return "", err
	}
	if keep > 0 && current != "" {
		history = append([]string{current}, history...)
		if len(history) > keep {
			history = history[:keep]
		}
		b, _ := json.Marshal(history)
		if _, err := p.vault.PutRef(ctx, HistoryPath(userID), historyKey, string(b)); err != nil {
			return ref, fmt.Errorf("%w: password history: %v", ErrUnavailable, err)
		}
	}
	return ref, nil
}

func (p *Passwords) history(userID int64) []string {
	raw, err := p.vault.Resolve(p.vault.Ref(HistoryPath(userID), historyKey))
	if err != nil || raw == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}
