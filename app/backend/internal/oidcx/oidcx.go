// Package oidcx is the OpenID Connect relying party used by the SPA client
// (internal/spa): discovery, the authorization code flow with PKCE S256, ID
// token verification (RS256, keys from the issuer's JWKS) and JWT signing for
// the fake SPA of the tests.
package oidcx

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// ErrInvalidToken: the ID token does not verify.
var ErrInvalidToken = errors.New("the ID token is invalid")

// Timeout bounds every call to a provider.
var Timeout = 10 * time.Second

func client() *http.Client { return &http.Client{Timeout: Timeout} }

// Metadata is the part of the provider's discovery document the flow uses.
type Metadata struct {
	Issuer        string   `json:"issuer"`
	Authorization string   `json:"authorization_endpoint"`
	Token         string   `json:"token_endpoint"`
	UserInfo      string   `json:"userinfo_endpoint"`
	JWKS          string   `json:"jwks_uri"`
	Algorithms    []string `json:"id_token_signing_alg_values_supported"`
}

type cached struct {
	m  Metadata
	at time.Time
}

var (
	discoveryMu    sync.Mutex
	discoveryCache = map[string]cached{}
)

// Discover reads the discovery document of the issuer (kept for an hour).
func Discover(ctx context.Context, issuer string) (Metadata, error) {
	issuer = strings.TrimRight(issuer, "/")
	discoveryMu.Lock()
	c, ok := discoveryCache[issuer]
	discoveryMu.Unlock()
	if ok && time.Since(c.at) < time.Hour {
		return c.m, nil
	}
	var m Metadata
	if err := GetJSON(ctx, issuer+"/.well-known/openid-configuration", &m); err != nil {
		return Metadata{}, fmt.Errorf("discovery of %s: %w", issuer, err)
	}
	if strings.TrimRight(m.Issuer, "/") != issuer {
		return Metadata{}, fmt.Errorf("discovery of %s names the issuer %q", issuer, m.Issuer)
	}
	if m.Authorization == "" || m.Token == "" || m.JWKS == "" {
		return Metadata{}, fmt.Errorf("discovery of %s lacks endpoints", issuer)
	}
	discoveryMu.Lock()
	discoveryCache[issuer] = cached{m: m, at: time.Now()}
	discoveryMu.Unlock()
	return m, nil
}

// GetJSON reads a JSON document.
func GetJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := client().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
}

// Request is a started sign-in: state, nonce and the PKCE verifier.
type Request struct {
	State    string
	Nonce    string
	Verifier string
}

// Random is 32 random bytes in base64url.
func Random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func NewRequest() Request { return Request{State: Random(), Nonce: Random(), Verifier: Random()} }

// Challenge is the S256 PKCE challenge of a verifier.
func Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// Client is the application registered at the provider.
type Client struct {
	Issuer      string
	ClientID    string
	Secret      string
	RedirectURI string
	Scopes      []string
	// Extra are additional authorization parameters (login_hint, idp_hint, prompt).
	Extra url.Values
}

// AuthURL is the provider's sign-in page for the request.
func AuthURL(c Client, m Metadata, r Request) string {
	q := url.Values{
		"client_id":             {c.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {c.RedirectURI},
		"scope":                 {strings.Join(c.Scopes, " ")},
		"state":                 {r.State},
		"nonce":                 {r.Nonce},
		"code_challenge":        {Challenge(r.Verifier)},
		"code_challenge_method": {"S256"},
	}
	for k, v := range c.Extra {
		q[k] = v
	}
	sep := "?"
	if strings.Contains(m.Authorization, "?") {
		sep = "&"
	}
	return m.Authorization + sep + q.Encode()
}

// Tokens is the token endpoint's answer.
type Tokens struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
}

// Exchange redeems the code.
func Exchange(ctx context.Context, c Client, m Metadata, code string, r Request) (Tokens, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.RedirectURI},
		"client_id":     {c.ClientID},
		"client_secret": {c.Secret},
		"code_verifier": {r.Verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := client().Do(req)
	if err != nil {
		return Tokens{}, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		return Tokens{}, fmt.Errorf("token endpoint: HTTP %d %s %s", res.StatusCode, e.Error, e.Description)
	}
	var t Tokens
	if err := json.Unmarshal(body, &t); err != nil || t.IDToken == "" {
		return Tokens{}, fmt.Errorf("token endpoint: no ID token")
	}
	return t, nil
}

// Claims are the claims of an ID token.
type Claims map[string]any

func (c Claims) String(k string) string {
	switch v := c[k].(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return fmt.Sprint(int64(v))
	}
	return ""
}

func (c Claims) Bool(k string) bool {
	switch v := c[k].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

func (c Claims) Time(k string) time.Time {
	if v, ok := c[k].(float64); ok {
		return time.Unix(int64(v), 0)
	}
	return time.Time{}
}

// Strings reads a claim that is a list or a single string (groups, roles, aud).
func (c Claims) Strings(k string) []string {
	switch v := c[k].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// Verify checks the ID token: the signature (keys from the JWKS), issuer, audience, expiry and
// nonce.
func Verify(ctx context.Context, m Metadata, clientID, raw, nonce string, now time.Time) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	var h header
	if err := decodePart(parts[0], &h); err != nil {
		return nil, ErrInvalidToken
	}
	key, err := jwksKey(ctx, m.JWKS, h.Kid, h.Alg)
	if err != nil {
		return nil, err
	}
	if err := VerifySignature(h.Alg, key, parts[0]+"."+parts[1], parts[2]); err != nil {
		return nil, err
	}
	var cl Claims
	if err := decodePart(parts[1], &cl); err != nil {
		return nil, ErrInvalidToken
	}
	if strings.TrimRight(cl.String("iss"), "/") != strings.TrimRight(m.Issuer, "/") {
		return nil, fmt.Errorf("%w: issuer %q", ErrInvalidToken, cl.String("iss"))
	}
	if !slices.Contains(cl.Strings("aud"), clientID) {
		return nil, fmt.Errorf("%w: audience", ErrInvalidToken)
	}
	if exp := cl.Time("exp"); exp.IsZero() || now.After(exp.Add(time.Minute)) {
		return nil, fmt.Errorf("%w: expired", ErrInvalidToken)
	}
	if iat := cl.Time("iat"); !iat.IsZero() && iat.After(now.Add(5*time.Minute)) {
		return nil, fmt.Errorf("%w: issued in the future", ErrInvalidToken)
	}
	if nonce != "" && cl.String("nonce") != nonce {
		return nil, fmt.Errorf("%w: nonce", ErrInvalidToken)
	}
	return cl, nil
}

// Algorithm is the "alg" of a JWT header ("" when it cannot be read).
func Algorithm(raw string) string {
	head, _, _ := strings.Cut(raw, ".")
	var h header
	if decodePart(head, &h) != nil {
		return ""
	}
	return h.Alg
}

func decodePart(s string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// JWK is one key of a JWKS document.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// Public is the public key of the JWK.
func (k JWK) Public() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(n) < 256 {
			return nil, ErrInvalidToken
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, ErrInvalidToken
		}
		x, err1 := base64.RawURLEncoding.DecodeString(k.X)
		y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
		if err1 != nil || err2 != nil {
			return nil, ErrInvalidToken
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	}
	return nil, ErrInvalidToken
}

// RSAJWK describes an RSA public key.
func RSAJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256", N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())}
}

var (
	jwksMu    sync.Mutex
	jwksCache = map[string]struct {
		keys []JWK
		at   time.Time
	}{}
)

func jwksKey(ctx context.Context, u, kid, alg string) (crypto.PublicKey, error) {
	for attempt := 0; attempt < 2; attempt++ {
		jwksMu.Lock()
		c, ok := jwksCache[u]
		jwksMu.Unlock()
		if !ok || attempt == 1 || time.Since(c.at) > time.Hour {
			var doc struct {
				Keys []JWK `json:"keys"`
			}
			if err := GetJSON(ctx, u, &doc); err != nil {
				return nil, fmt.Errorf("signing keys: %w", err)
			}
			c.keys, c.at = doc.Keys, time.Now()
			jwksMu.Lock()
			jwksCache[u] = c
			jwksMu.Unlock()
		}
		for _, k := range c.keys {
			if k.Kid == kid && (k.Alg == "" || k.Alg == alg) {
				return k.Public()
			}
		}
	}
	return nil, fmt.Errorf("%w: unknown signing key %q", ErrInvalidToken, kid)
}

// VerifySignature checks an RS256 or ES256 signature.
func VerifySignature(alg string, key crypto.PublicKey, signed, sig string) error {
	s, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return ErrInvalidToken
	}
	h := sha256.Sum256([]byte(signed))
	switch k := key.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], s) != nil {
			return fmt.Errorf("%w: signature", ErrInvalidToken)
		}
		return nil
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(s) != 64 || !ecdsa.Verify(k, h[:], new(big.Int).SetBytes(s[:32]), new(big.Int).SetBytes(s[32:])) {
			return fmt.Errorf("%w: signature", ErrInvalidToken)
		}
		return nil
	}
	return fmt.Errorf("%w: algorithm %s", ErrInvalidToken, alg)
}

// Sign makes a JWT signed with an RSA (RS256) or P-256 (ES256) key (the fake
// SPA of the tests).
func Sign(key crypto.Signer, kid string, claims any) (string, error) {
	alg := "RS256"
	if _, ok := key.(*ecdsa.PrivateKey); ok {
		alg = "ES256"
	}
	hb, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	h := sha256.Sum256([]byte(signed))
	var sig []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, k, h[:])
		if err == nil {
			sig = make([]byte, 64)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
		}
	default:
		err = errors.New("unsupported key")
	}
	if err != nil {
		return "", err
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
