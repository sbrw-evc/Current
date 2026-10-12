package entra

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/sbrw-evc/network/app/backend/internal/directory"
)

const (
	maxBody = 1 << 20
	skew    = 5 * time.Minute
)

type Metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Request is one sign-in attempt: the values the callback must see again.
type Request struct {
	State    string
	Nonce    string
	Verifier string
}

func NewRequest() Request {
	return Request{State: random(), Nonce: random(), Verifier: random()}
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (c Config) scope() string {
	return "openid profile email " + c.cloud().Graph + "/User.Read"
}

// Account is a signed-in Entra user: the immutable object ID and the profile
// Flow keeps (Identity.DN is the object ID, Identity.Groups the group object
// IDs in lower case when Config.ReadGroups is set).
type Account struct {
	ObjectID string
	directory.Identity
}

func client() *http.Client { return &http.Client{Timeout: Timeout} }

func Discover(ctx context.Context, c Config) (Metadata, error) {
	var m Metadata
	if _, err := getJSON(ctx, c.discoveryURL(), "", &m); err != nil {
		return m, fmt.Errorf("tenant %s: %w", c.TenantID, err)
	}
	if m.Issuer == "" || m.AuthorizationEndpoint == "" || m.TokenEndpoint == "" || m.JWKSURI == "" {
		return m, fmt.Errorf("tenant %s: the OpenID configuration is incomplete", c.TenantID)
	}
	return m, nil
}

// AuthURL is where the browser goes to sign in.
func AuthURL(c Config, m Metadata, r Request) string {
	sum := sha256.Sum256([]byte(r.Verifier))
	q := url.Values{
		"client_id":             {c.ClientID},
		"response_type":         {"code"},
		"response_mode":         {"query"},
		"redirect_uri":          {c.RedirectURL},
		"scope":                 {c.scope()},
		"state":                 {r.State},
		"nonce":                 {r.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
	}
	sep := "?"
	if strings.Contains(m.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return m.AuthorizationEndpoint + sep + q.Encode()
}

// Test checks that the tenant answers and that the application ID and the client secret are valid.
func Test(ctx context.Context, c Config, secret string) (Probe, error) {
	c, err := c.Normalize()
	if err != nil {
		return Probe{}, err
	}
	var p Probe
	m, err := Discover(ctx, c)
	if err != nil {
		return p, err
	}
	p.Issuer = m.Issuer
	p.TenantID = tenantOf(m.Issuer)
	if _, err := token(ctx, m, url.Values{"grant_type": {"client_credentials"}, "client_id": {c.ClientID}, "client_secret": {secret},
		"scope": {c.cloud().Graph + "/.default"}}); err != nil {
		return p, err
	}
	p.Credentials = true
	return p, nil
}

func tenantOf(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	if part := strings.Split(strings.Trim(u.Path, "/"), "/"); len(part) > 0 && guidRe.MatchString(part[0]) {
		return part[0]
	}
	return ""
}

// SignIn completes the callback: it redeems the code, verifies the ID token and reads the profile.
func SignIn(ctx context.Context, c Config, secret, code string, r Request, now time.Time) (Account, error) {
	if code == "" || len(code) > 8192 {
		return Account{}, ErrInvalidUser
	}
	m, err := Discover(ctx, c)
	if err != nil {
		return Account{}, err
	}
	t, err := token(ctx, m, url.Values{"grant_type": {"authorization_code"}, "client_id": {c.ClientID}, "client_secret": {secret},
		"code": {code}, "redirect_uri": {c.RedirectURL}, "code_verifier": {r.Verifier}, "scope": {c.scope()}})
	if err != nil {
		return Account{}, err
	}
	cl, err := verify(ctx, c, m, t.IDToken, r.Nonce, now)
	if err != nil {
		return Account{}, err
	}
	return account(ctx, c, cl, t.AccessToken)
}

type tokens struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
}

type tokenError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func token(ctx context.Context, m Metadata, form url.Values) (tokens, error) {
	var t tokens
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return t, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client().Do(req)
	if err != nil {
		return t, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return t, fmt.Errorf("token endpoint: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var e tokenError
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			desc, _, _ := strings.Cut(e.Description, "\r\n")
			return t, fmt.Errorf("token endpoint: %s: %s", e.Error, strings.TrimSpace(desc))
		}
		return t, fmt.Errorf("token endpoint: HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &t); err != nil {
		return t, fmt.Errorf("token endpoint: %w", err)
	}
	return t, nil
}

type claims struct {
	Issuer            string          `json:"iss"`
	Audience          json.RawMessage `json:"aud"`
	Expires           int64           `json:"exp"`
	NotBefore         int64           `json:"nbf"`
	Nonce             string          `json:"nonce"`
	TenantID          string          `json:"tid"`
	ObjectID          string          `json:"oid"`
	PreferredUsername string          `json:"preferred_username"`
	Name              string          `json:"name"`
	Email             string          `json:"email"`
	Groups            []string        `json:"groups"`
	ClaimNames        map[string]any  `json:"_claim_names"`
	HasGroups         bool            `json:"hasgroups"`
}

func (cl claims) audience(want string) bool {
	var one string
	if json.Unmarshal(cl.Audience, &one) == nil {
		return one == want
	}
	var many []string
	return json.Unmarshal(cl.Audience, &many) == nil && slices.Contains(many, want)
}

// groupsComplete reports whether the token lists every group, so Graph need not be asked.
func (cl claims) groupsComplete() bool {
	_, overage := cl.ClaimNames["groups"]
	return cl.Groups != nil && !overage && !cl.HasGroups
}

func verify(ctx context.Context, c Config, m Metadata, raw, nonce string, now time.Time) (claims, error) {
	var cl claims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return cl, errors.New("ID token is malformed")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodePart(parts[0], &hdr); err != nil {
		return cl, fmt.Errorf("ID token header: %w", err)
	}
	if hdr.Alg != "RS256" {
		return cl, fmt.Errorf("ID token algorithm %q is not accepted", hdr.Alg)
	}
	key, err := signingKey(ctx, m, hdr.Kid)
	if err != nil {
		return cl, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return cl, errors.New("ID token signature is malformed")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return cl, errors.New("ID token signature is invalid")
	}
	if err := decodePart(parts[1], &cl); err != nil {
		return cl, fmt.Errorf("ID token claims: %w", err)
	}
	switch {
	case cl.Issuer != m.Issuer:
		return cl, fmt.Errorf("ID token issuer %q is not the tenant issuer", cl.Issuer)
	case !cl.audience(c.ClientID):
		return cl, errors.New("ID token was issued to another application")
	case cl.Expires == 0 || now.After(time.Unix(cl.Expires, 0).Add(skew)):
		return cl, errors.New("ID token has expired")
	case cl.NotBefore != 0 && now.Add(skew).Before(time.Unix(cl.NotBefore, 0)):
		return cl, errors.New("ID token is not valid yet")
	case cl.Nonce == "" || cl.Nonce != nonce:
		return cl, errors.New("ID token nonce does not match the sign-in request")
	case cl.ObjectID == "" || cl.TenantID == "":
		return cl, ErrInvalidUser
	case guidRe.MatchString(c.TenantID) && !strings.EqualFold(cl.TenantID, c.TenantID):
		return cl, errors.New("ID token comes from another tenant")
	}
	return cl, nil
}

func decodePart(s string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func signingKey(ctx context.Context, m Metadata, kid string) (*rsa.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if _, err := getJSON(ctx, m.JWKSURI, "", &set); err != nil {
		return nil, fmt.Errorf("signing keys: %w", err)
	}
	for _, k := range set.Keys {
		if k.Kid != kid || k.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("signing key is malformed")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}
	return nil, fmt.Errorf("signing key %q is not published by the tenant", kid)
}

type graphUser struct {
	DisplayName       string `json:"displayName"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
}

func account(ctx context.Context, c Config, cl claims, access string) (Account, error) {
	a := Account{ObjectID: strings.ToLower(cl.ObjectID)}
	id := &a.Identity
	id.Username = strings.ToLower(strings.TrimSpace(cl.PreferredUsername))
	id.Name, id.Email = cl.Name, cl.Email

	if access != "" {
		var g graphUser
		if _, err := getJSON(ctx, graphURL(c, "/v1.0/me?$select=displayName,mail,userPrincipalName"), access, &g); err != nil {
			slog.Warn("entra: profile from Microsoft Graph unavailable, using the ID token", "err", err)
		} else {
			id.Name = firstSet(g.DisplayName, id.Name)
			id.Email = firstSet(g.Mail, id.Email)
			if id.Username == "" {
				id.Username = strings.ToLower(g.UserPrincipalName)
			}
		}
	}
	if id.Username == "" {
		id.Username = strings.ToLower(id.Email)
	}
	if !validUsername(id.Username) {
		return a, ErrInvalidUser
	}
	id.Name = firstSet(strings.TrimSpace(id.Name), id.Username)
	id.DN = a.ObjectID
	id.Groups = []string{}

	if !c.ReadGroups {
		return a, nil
	}
	groups := cl.Groups
	if !cl.groupsComplete() {
		var err error
		if groups, err = memberOf(ctx, c, access, "/v1.0/me"); err != nil {
			return a, err
		}
	}
	id.Groups = lowerAll(groups)
	return a, nil
}

// memberOf lists the groups the user belongs to, directly or through nested groups. who is
// "/v1.0/me" with a delegated token or "/v1.0/users/{id}" with an application token.
func memberOf(ctx context.Context, c Config, access, who string) ([]string, error) {
	if access == "" {
		return nil, errors.New("group membership: no Microsoft Graph access token")
	}
	var out []string
	next := graphURL(c, who+"/transitiveMemberOf/microsoft.graph.group?$select=id&$top=999")
	for page := 0; next != "" && page < 50; page++ {
		var res struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
			Next string `json:"@odata.nextLink"`
		}
		if code, err := getJSON(ctx, next, access, &res); err != nil {
			return nil, graphError{code: code, err: fmt.Errorf("group membership: %w", err)}
		}
		for _, g := range res.Value {
			out = append(out, g.ID)
		}
		next = ""
		if res.Next != "" && strings.HasPrefix(res.Next, c.cloud().Graph+"/") {
			next = res.Next
		}
	}
	return out, nil
}

func graphURL(c Config, path string) string { return c.cloud().Graph + path }

func getJSON(ctx context.Context, u, bearer string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error.Code != "" {
			return resp.StatusCode, fmt.Errorf("HTTP %d: %s: %s", resp.StatusCode, e.Error.Code, e.Error.Message)
		}
		return resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, json.Unmarshal(body, out)
}

func validUsername(u string) bool {
	if u == "" || len(u) > 256 {
		return false
	}
	for _, r := range u {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func firstSet(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

type graphError struct {
	code int
	err  error
}

func (e graphError) Error() string { return e.err.Error() }
func (e graphError) Unwrap() error { return e.err }

func lowerAll(v []string) []string {
	out := make([]string, 0, len(v))
	for _, s := range v {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}
