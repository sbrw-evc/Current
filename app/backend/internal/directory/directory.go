// Package directory signs users in through LDAP / Active Directory: a service
// account finds the user, the user's own bind checks the password, and the
// groups the user belongs to (nested ones too) are returned for the group →
// role mapping. A smaller port of Umbrella Monitoring's directory package.
package directory

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"
)

const (
	KindAD       = "ad"
	KindOpenLDAP = "openldap"

	Placeholder = "{username}"

	// SecretPath / SecretKey: where the service account password lives in OpenBao.
	SecretPath = "ldap"
	SecretKey  = "bind_password"

	adNestedMember = "1.2.840.113556.1.4.1941"
	maxGroups      = 2000
)

var Timeout = 10 * time.Second

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserNotFound       = errors.New("user not found in the directory")
	ErrAmbiguousUser      = errors.New("several directory entries match the username")
)

// Config is the directory connection, stored in the settings table (key "ldap").
type Config struct {
	Enabled         bool   `json:"enabled"`
	Kind            string `json:"kind"`
	URL             string `json:"url"`
	StartTLS        bool   `json:"start_tls"`
	SkipVerify      bool   `json:"skip_verify"`
	CACert          string `json:"ca_cert,omitempty"`
	BindDN          string `json:"bind_dn"`
	BindPasswordRef string `json:"bind_password_ref,omitempty"`
	BaseDN          string `json:"base_dn"`
	UserFilter      string `json:"user_filter"`
	UsernameAttr    string `json:"username_attr"`
	NameAttr        string `json:"name_attr"`
	EmailAttr       string `json:"email_attr"`
}

// Defaults returns the attribute defaults for a directory kind.
func Defaults(kind string) Config {
	if kind == KindOpenLDAP {
		return Config{Kind: KindOpenLDAP, UserFilter: "(&(objectClass=inetOrgPerson)(uid={username}))",
			UsernameAttr: "uid", NameAttr: "cn", EmailAttr: "mail"}
	}
	return Config{Kind: KindAD, UserFilter: "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))",
		UsernameAttr: "sAMAccountName", NameAttr: "displayName", EmailAttr: "mail"}
}

var attrRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

// Normalize applies defaults and checks the configuration.
func (c Config) Normalize() (Config, error) {
	c.Kind = strings.ToLower(strings.TrimSpace(c.Kind))
	if c.Kind == "" {
		c.Kind = KindAD
	}
	if c.Kind != KindAD && c.Kind != KindOpenLDAP {
		return c, errors.New("directory type must be ad or openldap")
	}
	d := Defaults(c.Kind)
	c.URL = strings.TrimSpace(c.URL)
	c.BindDN = strings.TrimSpace(c.BindDN)
	c.BaseDN = strings.TrimSpace(c.BaseDN)
	c.CACert = strings.TrimSpace(c.CACert)
	c.UserFilter = firstSet(strings.TrimSpace(c.UserFilter), d.UserFilter)
	c.UsernameAttr = firstSet(strings.TrimSpace(c.UsernameAttr), d.UsernameAttr)
	c.NameAttr = firstSet(strings.TrimSpace(c.NameAttr), d.NameAttr)
	c.EmailAttr = firstSet(strings.TrimSpace(c.EmailAttr), d.EmailAttr)
	for _, a := range c.attrs() {
		if !attrRe.MatchString(a) {
			return c, fmt.Errorf("attribute name %q is invalid", a)
		}
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Hostname() == "" {
		return c, errors.New("server address must look like ldap://host:389 or ldaps://host:636")
	}
	if u.Scheme == "ldaps" && c.StartTLS {
		return c, errors.New("StartTLS works only with ldap://, ldaps:// is already encrypted")
	}
	if c.BindDN == "" {
		return c, errors.New("service account (bind DN) is required")
	}
	if !ValidDN(c.BaseDN) {
		return c, errors.New("search base DN is invalid")
	}
	if !strings.Contains(c.UserFilter, Placeholder) {
		return c, fmt.Errorf("user filter must contain %s", Placeholder)
	}
	if _, err := ldap.CompileFilter(strings.ReplaceAll(c.UserFilter, Placeholder, "probe")); err != nil {
		return c, fmt.Errorf("user filter is invalid: %v", err)
	}
	if c.CACert != "" {
		if _, err := certPool(c.CACert); err != nil {
			return c, err
		}
	}
	return c, nil
}

// Identity is a signed-in directory user.
type Identity struct {
	DN       string   `json:"dn"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups"` // normalized DNs, nested groups included
}

// Authenticate checks the user's password and returns the identity with groups.
func Authenticate(c Config, bindPassword, username, password string) (Identity, error) {
	if password == "" || len(password) > 1024 || checkUsername(username) != nil {
		return Identity{}, ErrInvalidCredentials
	}
	c, err := c.Normalize()
	if err != nil {
		return Identity{}, err
	}
	conn, err := connect(c, bindPassword)
	if err != nil {
		return Identity{}, err
	}
	defer conn.Close()
	e, err := findUser(conn, c, username)
	if err != nil {
		return Identity{}, err
	}
	if err := conn.Bind(e.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return Identity{}, ErrInvalidCredentials
		}
		return Identity{}, fmt.Errorf("user bind: %w", err)
	}
	if err := conn.Bind(c.BindDN, bindPassword); err != nil {
		return Identity{}, fmt.Errorf("service account bind: %w", err)
	}
	id := Identity{DN: e.DN, Username: firstSet(value(e, c.UsernameAttr), username), Name: firstSet(value(e, c.NameAttr), username),
		Email: value(e, c.EmailAttr)}
	if id.Groups, err = groupsOf(conn, c, e, username); err != nil {
		return Identity{}, err
	}
	return id, nil
}

// TestResult is what Test found.
type TestResult struct {
	OK    bool      `json:"ok"`
	Error string    `json:"error,omitempty"`
	User  *Identity `json:"user,omitempty"`
}

// Test connects with the service account, checks the search base and, when
// username is set, finds the user (and checks the password when it is set).
func Test(c Config, bindPassword, username, password string) TestResult {
	fail := func(err error) TestResult { return TestResult{Error: err.Error()} }
	c, err := c.Normalize()
	if err != nil {
		return fail(err)
	}
	if strings.TrimSpace(username) != "" && password != "" {
		id, err := Authenticate(c, bindPassword, username, password)
		if err != nil {
			return fail(err)
		}
		return TestResult{OK: true, User: &id}
	}
	conn, err := connect(c, bindPassword)
	if err != nil {
		return fail(err)
	}
	defer conn.Close()
	if _, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, seconds(), false,
		"(objectClass=*)", []string{"1.1"}, nil)); err != nil {
		return fail(fmt.Errorf("search base %s: %w", c.BaseDN, err))
	}
	if strings.TrimSpace(username) == "" {
		return TestResult{OK: true}
	}
	e, err := findUser(conn, c, username)
	if err != nil {
		return fail(err)
	}
	id := Identity{DN: e.DN, Username: firstSet(value(e, c.UsernameAttr), username), Name: value(e, c.NameAttr), Email: value(e, c.EmailAttr)}
	if id.Groups, err = groupsOf(conn, c, e, username); err != nil {
		return fail(err)
	}
	return TestResult{OK: true, User: &id}
}

func connect(c Config, bindPassword string) (*ldap.Conn, error) {
	if bindPassword == "" {
		return nil, errors.New("service account password is empty")
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), InsecureSkipVerify: c.SkipVerify}
	if c.CACert != "" {
		pool, err := certPool(c.CACert)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = pool
	}
	conn, err := ldap.DialURL(c.URL, ldap.DialWithDialer(&net.Dialer{Timeout: Timeout}), ldap.DialWithTLSConfig(tc))
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", c.URL, err)
	}
	conn.SetTimeout(Timeout)
	if c.StartTLS {
		if err := conn.StartTLS(tc); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS: %w", err)
		}
	}
	if err := conn.Bind(c.BindDN, bindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("service account bind: %w", err)
	}
	return conn, nil
}

func findUser(conn *ldap.Conn, c Config, username string) (*ldap.Entry, error) {
	filter := strings.ReplaceAll(c.UserFilter, Placeholder, ldap.EscapeFilter(username))
	attrs := append(c.attrs(), "memberOf")
	res, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, seconds(), false,
		filter, attrs, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, ErrAmbiguousUser
	}
	if err != nil {
		return nil, fmt.Errorf("user search: %w", err)
	}
	switch len(res.Entries) {
	case 0:
		return nil, ErrUserNotFound
	case 1:
		return res.Entries[0], nil
	}
	return nil, ErrAmbiguousUser
}

// groupsOf returns the normalized DNs of the user's groups. AD resolves nested
// groups with the LDAP_MATCHING_RULE_IN_CHAIN; OpenLDAP uses memberOf (when
// the overlay is on) plus groups listing the user as member / uniqueMember / memberUid.
func groupsOf(conn *ldap.Conn, c Config, e *ldap.Entry, username string) ([]string, error) {
	set := map[string]bool{}
	for _, g := range e.GetAttributeValues("memberOf") {
		set[NormalizeDN(g)] = true
	}
	var filter string
	if c.Kind == KindAD {
		filter = "(&(objectClass=group)(member:" + adNestedMember + ":=" + ldap.EscapeFilter(e.DN) + "))"
	} else {
		dn := ldap.EscapeFilter(e.DN)
		filter = "(|(member=" + dn + ")(uniqueMember=" + dn + ")(memberUid=" + ldap.EscapeFilter(username) + "))"
	}
	res, err := conn.SearchWithPaging(ldap.NewSearchRequest(groupRoot(c.BaseDN), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, seconds()*3, false, filter, []string{"1.1"}, nil), 500)
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil, fmt.Errorf("group search: %w", err)
	}
	if res != nil {
		for _, g := range res.Entries {
			set[NormalizeDN(g.DN)] = true
		}
	}
	out := make([]string, 0, len(set))
	for g := range set {
		if len(out) == maxGroups {
			break
		}
		out = append(out, g)
	}
	return out, nil
}

// groupRoot is the domain part (dc=…) of the search base: groups often live
// outside the users' OU.
func groupRoot(base string) string {
	dn, err := ldap.ParseDN(base)
	if err != nil {
		return base
	}
	i := len(dn.RDNs)
	for i > 0 && len(dn.RDNs[i-1].Attributes) == 1 && strings.EqualFold(dn.RDNs[i-1].Attributes[0].Type, "dc") {
		i--
	}
	if i == len(dn.RDNs) {
		return base
	}
	return (&ldap.DN{RDNs: dn.RDNs[i:]}).String()
}

// NormalizeDN returns the DN in one canonical lower-case spelling.
func NormalizeDN(s string) string {
	dn, err := ldap.ParseDN(strings.TrimSpace(s))
	if err != nil || len(dn.RDNs) == 0 {
		return strings.ToLower(strings.TrimSpace(s))
	}
	return strings.ToLower(dn.String())
}

// ValidDN reports whether s is a non-empty DN.
func ValidDN(s string) bool {
	dn, err := ldap.ParseDN(strings.TrimSpace(s))
	return err == nil && len(dn.RDNs) > 0
}

func (c Config) attrs() []string {
	var out []string
	for _, a := range []string{c.UsernameAttr, c.NameAttr, c.EmailAttr} {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

func value(e *ldap.Entry, attr string) string {
	if attr == "" {
		return ""
	}
	return strings.TrimSpace(e.GetAttributeValue(attr))
}

func checkUsername(u string) error {
	if strings.TrimSpace(u) == "" || len(u) > 256 {
		return errors.New("username is empty or too long")
	}
	for _, r := range u {
		if unicode.IsControl(r) {
			return errors.New("username contains control characters")
		}
	}
	return nil
}

func certPool(pem string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pem)) {
		return nil, errors.New("CA certificate: no PEM certificates found")
	}
	return pool, nil
}

func seconds() int { return int(Timeout / time.Second) }

func firstSet(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}
