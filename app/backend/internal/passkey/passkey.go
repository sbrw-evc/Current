// Package passkey runs the WebAuthn (FIDO2) ceremonies of passkeys: Windows Hello (face,
// fingerprint, iris, PIN), Touch ID / Face ID, Android biometrics and security keys. User
// verification (biometrics or a PIN) is always required, so a passkey sign-in is two-factor by
// itself, and the credentials are discoverable: the person picks the account in the browser.
package passkey

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	// ErrOrigin: the page is not inside the passkey domain.
	ErrOrigin = errors.New("the address of the page is outside the passkey domain")
	// ErrCeremony: the ceremony is unknown or has expired.
	ErrCeremony = errors.New("the passkey request has expired: try again")
	// ErrUnknown: no account has this passkey.
	ErrUnknown = errors.New("this passkey is not registered")
	// ErrRejected: the browser's answer did not verify.
	ErrRejected = errors.New("the passkey could not be verified")
)

// Key is a stored passkey: what the ceremonies need of it.
type Key struct {
	ID             string
	Name           string
	CredentialID   []byte
	PublicKey      []byte
	UserHandle     []byte
	SignCount      uint32
	AAGUID         []byte
	Transports     []string
	BackupEligible bool
	BackupState    bool
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

// HostWithin reports whether host is the passkey domain or a subdomain of it.
func HostWithin(host, rpID string) bool {
	host, rpID = strings.ToLower(host), strings.ToLower(rpID)
	return rpID != "" && (host == rpID || strings.HasSuffix(host, "."+rpID))
}

// Party is the relying party: the passkey domain, the name people see and the page origin of
// the ceremony.
type Party struct {
	RPID   string
	Name   string
	Origin string
}

// NewParty checks that origin (scheme://host[:port] of the page) is inside the passkey domain.
// An empty rpID is the page's host name.
func NewParty(rpID, name, origin string) (Party, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return Party{}, ErrOrigin
	}
	host := u.Hostname()
	if rpID == "" {
		rpID = host
	}
	local := host == "localhost"
	if (u.Scheme != "https" && !(u.Scheme == "http" && local)) || !HostWithin(host, rpID) {
		return Party{}, ErrOrigin
	}
	return Party{RPID: strings.ToLower(rpID), Name: name, Origin: u.Scheme + "://" + u.Host}, nil
}

func (p Party) web() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{RPID: p.RPID, RPDisplayName: p.Name, RPOrigins: []string{p.Origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 3 * time.Minute, TimeoutUVD: 3 * time.Minute},
		}})
}

// Account is a person as a passkey ceremony sees them.
type Account struct {
	// Handle is the user ID stored in the authenticator.
	Handle  []byte
	Name    string
	Display string
	Keys    []Key
}

func (a Account) WebAuthnID() []byte          { return a.Handle }
func (a Account) WebAuthnName() string        { return a.Name }
func (a Account) WebAuthnDisplayName() string { return a.Display }
func (a Account) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(a.Keys))
	for _, k := range a.Keys {
		out = append(out, credential(k))
	}
	return out
}

func credential(k Key) webauthn.Credential {
	c := webauthn.Credential{ID: k.CredentialID, PublicKey: k.PublicKey,
		Flags:         webauthn.CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: k.BackupEligible, BackupState: k.BackupState},
		Authenticator: webauthn.Authenticator{AAGUID: k.AAGUID, SignCount: k.SignCount}}
	for _, t := range k.Transports {
		c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
	}
	return c
}

// ceremony is a started ceremony, kept until its answer.
type ceremony struct {
	party   Party
	session webauthn.SessionData
	userID  string
	expiry  time.Time
}

// Ceremonies keeps started ceremonies in memory for a few minutes.
type Ceremonies struct {
	mu sync.Mutex
	m  map[string]ceremony
}

const (
	ceremonyTTL = 5 * time.Minute
	ceremonyMax = 10000
)

func NewCeremonies() *Ceremonies { return &Ceremonies{m: map[string]ceremony{}} }

func (c *Ceremonies) put(x ceremony) string {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	id := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	x.expiry = now.Add(ceremonyTTL)
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.m {
		if now.After(v.expiry) {
			delete(c.m, k)
		}
	}
	for len(c.m) >= ceremonyMax {
		for k := range c.m {
			delete(c.m, k)
			break
		}
	}
	c.m[id] = x
	return id
}

func (c *Ceremonies) take(id string) (ceremony, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	x, ok := c.m[id]
	delete(c.m, id)
	return x, ok && time.Now().Before(x.expiry)
}

// Started is a ceremony to hand to the browser: its ID and the options of
// navigator.credentials.create / get.
type Started struct {
	Ceremony string `json:"ceremony"`
	Options  any    `json:"options"`
}

// BeginRegistration starts adding a passkey to the account of userID.
func (c *Ceremonies) BeginRegistration(p Party, userID string, acc Account) (Started, error) {
	w, err := p.web()
	if err != nil {
		return Started{}, err
	}
	var exclude []protocol.CredentialDescriptor
	for _, k := range acc.Keys {
		exclude = append(exclude, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: k.CredentialID})
	}
	opts, session, err := w.BeginRegistration(acc, webauthn.WithExclusions(exclude),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification: protocol.VerificationRequired}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
	if err != nil {
		return Started{}, err
	}
	return Started{Ceremony: c.put(ceremony{party: p, session: *session, userID: userID}), Options: opts}, nil
}

// FinishRegistration checks the browser's answer and returns the new passkey. The account
// must be the one the ceremony began for.
func (c *Ceremonies) FinishRegistration(id, userID string, acc Account, body []byte, now time.Time) (Key, error) {
	x, ok := c.take(id)
	if !ok || x.userID != userID {
		return Key{}, ErrCeremony
	}
	w, err := x.party.web()
	if err != nil {
		return Key{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		return Key{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	cred, err := w.CreateCredential(acc, x.session, parsed)
	if err != nil {
		return Key{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if !cred.Flags.UserVerified {
		return Key{}, fmt.Errorf("%w: the authenticator did not verify the person", ErrRejected)
	}
	k := Key{CredentialID: cred.ID, PublicKey: cred.PublicKey, UserHandle: acc.Handle, SignCount: cred.Authenticator.SignCount,
		AAGUID: cred.Authenticator.AAGUID, BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState, CreatedAt: now}
	for _, t := range cred.Transport {
		k.Transports = append(k.Transports, string(t))
	}
	k.Name = DefaultName(k)
	return k, nil
}

// BeginLogin starts a passkey sign-in: the browser offers every passkey of the domain.
func (c *Ceremonies) BeginLogin(p Party) (Started, error) {
	w, err := p.web()
	if err != nil {
		return Started{}, err
	}
	opts, session, err := w.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return Started{}, err
	}
	return Started{Ceremony: c.put(ceremony{party: p, session: *session}), Options: opts}, nil
}

// Lookup finds the account that has the credential.
type Lookup func(credentialID, userHandle []byte) (Account, error)

// FinishLogin verifies the browser's answer. It returns the account, the passkey with its new
// sign counter and use time.
func (c *Ceremonies) FinishLogin(id string, body []byte, lookup Lookup, now time.Time) (Account, Key, error) {
	x, ok := c.take(id)
	if !ok || x.userID != "" {
		return Account{}, Key{}, ErrCeremony
	}
	w, err := x.party.web()
	if err != nil {
		return Account{}, Key{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		return Account{}, Key{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	var acc Account
	user, cred, err := w.ValidatePasskeyLogin(func(rawID, handle []byte) (webauthn.User, error) {
		a, err := lookup(rawID, handle)
		if err != nil {
			return nil, err
		}
		acc = a
		return a, nil
	}, x.session, parsed)
	if errors.Is(err, ErrUnknown) || user == nil {
		return Account{}, Key{}, ErrUnknown
	}
	if err != nil {
		return Account{}, Key{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if !cred.Flags.UserVerified {
		return Account{}, Key{}, fmt.Errorf("%w: the authenticator did not verify the person", ErrRejected)
	}
	for _, k := range acc.Keys {
		if bytes.Equal(k.CredentialID, cred.ID) {
			k.SignCount, k.BackupState = cred.Authenticator.SignCount, cred.Flags.BackupState
			t := now
			k.LastUsedAt = &t
			return acc, k, nil
		}
	}
	return Account{}, Key{}, ErrUnknown
}

// AccountFor collects the passkeys of a user that carry handle: an account may hold passkeys
// of different handles (its own and those synchronized from the hub).
func AccountFor(name, display string, keys []Key, credentialID, handle []byte) (Account, bool) {
	acc := Account{Handle: handle, Name: name, Display: display}
	found := false
	for _, k := range keys {
		if !bytes.Equal(k.UserHandle, handle) {
			continue
		}
		acc.Keys = append(acc.Keys, k)
		if bytes.Equal(k.CredentialID, credentialID) {
			found = true
		}
	}
	return acc, found
}

// knownAuthenticators names the most common authenticators by AAGUID.
var knownAuthenticators = map[string]string{
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
	"dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain",
	"adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"b5397666-4885-aa6b-cebf-e52262a439a2": "Chromium",
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
	"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
	"cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5",
	"ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5",
	"fa2b99dc-9e39-4257-8f92-4a30d23c4118": "YubiKey 5 NFC",
	"2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 NFC",
	"c5ef55ff-ad9a-4b9f-b580-adebafe026d0": "YubiKey 5Ci",
	"a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa": "Security Key by Yubico",
}

// AAGUIDString formats an AAGUID as a UUID.
func AAGUIDString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ParseAAGUID reads a UUID back.
func ParseAAGUID(s string) []byte {
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return nil
	}
	out := make([]byte, 16)
	if _, err := fmt.Sscanf(s, "%32x", &out); err != nil {
		return nil
	}
	return out
}

// DefaultName names a new passkey after its authenticator.
func DefaultName(k Key) string {
	if n, ok := knownAuthenticators[AAGUIDString(k.AAGUID)]; ok {
		return n
	}
	for _, t := range k.Transports {
		switch t {
		case "usb", "nfc", "ble":
			return "Security key"
		case "hybrid":
			return "Phone"
		}
	}
	return "Passkey"
}

// Encode and Decode carry credential IDs and keys in JSON (base64url without padding).
func Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
