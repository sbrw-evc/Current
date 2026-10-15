// Package passkeytest is a software passkey authenticator for tests: it answers
// navigator.credentials.create and get the way a platform authenticator (Windows Hello, Touch
// ID) does, with user verification.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator holds one credential.
type Authenticator struct {
	Origin    string
	RPID      string
	key       *ecdsa.PrivateKey
	credID    []byte
	handle    []byte
	signCount uint32
	// SkipUV leaves out user verification (a key that only checks presence).
	SkipUV bool
}

func New(origin, rpID string) *Authenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &Authenticator{Origin: origin, RPID: rpID, key: k, credID: id}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *Authenticator) flags(attested bool) byte {
	f := byte(0x01) // user present
	if !a.SkipUV {
		f |= 0x04
	}
	if attested {
		f |= 0x40
	}
	return f
}

func (a *Authenticator) authData(attested bool) []byte {
	h := sha256.Sum256([]byte(a.RPID))
	out := append([]byte{}, h[:]...)
	out = append(out, a.flags(attested))
	a.signCount++
	out = binary.BigEndian.AppendUint32(out, a.signCount)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
		out = append(out, a.credID...)
		x, y := make([]byte, 32), make([]byte, 32)
		a.key.X.FillBytes(x)
		a.key.Y.FillBytes(y)
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		out = append(out, cose...)
	}
	return out
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

// options reads the challenge (and the user ID) of the options a server returned.
type options struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

func parse(opts any) options {
	b, _ := json.Marshal(opts)
	var o options
	_ = json.Unmarshal(b, &o)
	return o
}

// Create answers registration options with a new credential (attestation "none").
func (a *Authenticator) Create(opts any) json.RawMessage {
	o := parse(opts)
	a.handle, _ = base64.RawURLEncoding.DecodeString(o.PublicKey.User.ID)
	cd := clientData("webauthn.create", o.PublicKey.Challenge, a.Origin)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(true)})
	b, _ := json.Marshal(map[string]any{"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response":                map[string]any{"clientDataJSON": b64(cd), "attestationObject": b64(att), "transports": []string{"internal"}},
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{}})
	return b
}

// Get answers login options with an assertion.
func (a *Authenticator) Get(opts any) json.RawMessage {
	o := parse(opts)
	cd := clientData("webauthn.get", o.PublicKey.Challenge, a.Origin)
	ad := a.authData(false)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	b, _ := json.Marshal(map[string]any{"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response":                map[string]any{"clientDataJSON": b64(cd), "authenticatorData": b64(ad), "signature": b64(sig), "userHandle": b64(a.handle)},
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{}})
	return b
}

// Credential registers the authenticator's credential for handle outside a
// ceremony (as if it had been registered elsewhere, e.g. in the hub) and
// returns its ID and COSE public key.
func (a *Authenticator) Credential(handle []byte) (credentialID, publicKey []byte) {
	a.handle = handle
	x, y := make([]byte, 32), make([]byte, 32)
	a.key.X.FillBytes(x)
	a.key.Y.FillBytes(y)
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	return a.credID, cose
}
