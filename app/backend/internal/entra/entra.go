// Package entra signs users in with Microsoft Entra ID (Azure AD) over
// OpenID Connect: authorization code flow with PKCE and a confidential client
// secret, ID token verification against the tenant keys, and the profile and
// group membership from Microsoft Graph. Ported from Umbrella Monitoring
// (app/backend/internal/entra).
package entra

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// SecretPath / SecretKey: where the client secret lives in OpenBao.
	SecretPath = "entra"
	SecretKey  = "client_secret"
	// CallbackPath is the redirect URI path registered in Entra ID.
	CallbackPath = "/api/auth/entra/callback"

	CloudGlobal = "global"
	CloudUSGov  = "usgov"
	CloudChina  = "china"
)

// Timeout of each call to Entra ID and Microsoft Graph.
var Timeout = 10 * time.Second

// Cloud is a national cloud: where users sign in and where Microsoft Graph answers.
type Cloud struct {
	Login string
	Graph string
}

// Clouds maps a cloud name to its endpoints. Tests add their own entry.
var Clouds = map[string]Cloud{
	CloudGlobal: {Login: "https://login.microsoftonline.com", Graph: "https://graph.microsoft.com"},
	CloudUSGov:  {Login: "https://login.microsoftonline.us", Graph: "https://graph.microsoft.us"},
	CloudChina:  {Login: "https://login.chinacloudapi.cn", Graph: "https://microsoftgraph.chinacloudapi.cn"},
}

// ErrInvalidUser: the sign-in response has no usable account.
var ErrInvalidUser = errors.New("the sign-in response has no usable account")

var (
	guidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	tenantRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
)

// Config is the Entra ID application Flow signs in with.
type Config struct {
	Enabled         bool   `json:"enabled"`
	Cloud           string `json:"cloud"`
	TenantID        string `json:"tenant_id"`
	ClientID        string `json:"client_id"`
	ClientSecretRef string `json:"client_secret_ref,omitempty"`
	RedirectURL     string `json:"redirect_url"`
	// ReadGroups makes the sign-in read the user's groups (for the group →
	// role mapping). Set at sign-in, never saved.
	ReadGroups bool `json:"-"`
}

// Normalize trims and checks the settings.
func (c Config) Normalize() (Config, error) {
	c.Cloud = strings.ToLower(strings.TrimSpace(c.Cloud))
	if c.Cloud == "" {
		c.Cloud = CloudGlobal
	}
	if _, ok := Clouds[c.Cloud]; !ok {
		return c, errors.New("unknown Microsoft cloud")
	}
	c.TenantID = strings.ToLower(strings.TrimSpace(c.TenantID))
	c.ClientID = strings.ToLower(strings.TrimSpace(c.ClientID))
	c.RedirectURL = strings.TrimSpace(c.RedirectURL)
	switch c.TenantID {
	case "":
		return c, errors.New("tenant ID is required")
	case "common", "organizations", "consumers":
		return c, errors.New("use your own tenant ID or domain: multi-tenant sign-in would let any Microsoft account in")
	}
	if !tenantRe.MatchString(c.TenantID) {
		return c, errors.New("tenant must be a directory (tenant) ID or a domain such as contoso.onmicrosoft.com")
	}
	if !guidRe.MatchString(c.ClientID) {
		return c, errors.New("application (client) ID must be a GUID")
	}
	u, err := url.Parse(c.RedirectURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != CallbackPath || u.RawQuery != "" || u.Fragment != "" {
		return c, fmt.Errorf("redirect URI must look like https://flow.example%s", CallbackPath)
	}
	return c, nil
}

func (c Config) cloud() Cloud { return Clouds[c.Cloud] }

func (c Config) discoveryURL() string {
	return c.cloud().Login + "/" + url.PathEscape(c.TenantID) + "/v2.0/.well-known/openid-configuration"
}

// ValidGroupID reports whether s is an Entra group object ID.
func ValidGroupID(s string) bool { return guidRe.MatchString(strings.TrimSpace(s)) }

// Probe is what a settings check found out about the tenant and the application.
type Probe struct {
	Issuer      string `json:"issuer,omitempty"`
	TenantID    string `json:"tenant_id,omitempty"`
	Credentials bool   `json:"credentials"`
}

// TestReport is the answer of a settings check.
type TestReport struct {
	OK    bool   `json:"ok"`
	Probe Probe  `json:"probe"`
	Error string `json:"error,omitempty"`
}

// Report builds a TestReport.
func Report(p Probe, err error) TestReport {
	r := TestReport{OK: err == nil, Probe: p}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}
