// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package webauthntest is the Go fake WebAuthn authenticator (port of
// src/test/helpers/fake-authenticator.ts, #162/#228): a P-256 keypair that
// produces real, cryptographically-valid registration and authentication
// responses in the @simplewebauthn JSON shapes go-webauthn parses. Drives
// the ceremony parity tests; a fixed key + credential id makes the derived
// material deterministic (matching the golden fixtures).
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator flag bits (WebAuthn §6.1).
const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
	flagAT = 0x40 // attested credential data included
)

// Authenticator is a fake WebAuthn authenticator holding one P-256 credential.
type Authenticator struct {
	RpID    string
	Origin  string
	credID  []byte
	priv    *ecdsa.PrivateKey
	counter uint32
}

// Options configure a fake authenticator.
type Options struct {
	RpID   string // default "localhost"
	Origin string // default "http://localhost"
	// PrivateKeyPEM pins the P-256 key (PKCS#8) for deterministic derived
	// material; empty generates a fresh key.
	PrivateKeyPEM string
	// CredentialID pins the credential id; nil generates a random 32-byte id.
	CredentialID []byte
}

// New builds a fake authenticator.
func New(o Options) (*Authenticator, error) {
	rpID := o.RpID
	if rpID == "" {
		rpID = "localhost"
	}
	origin := o.Origin
	if origin == "" {
		origin = "http://localhost"
	}
	credID := o.CredentialID
	if credID == nil {
		credID = make([]byte, 32)
		if _, err := rand.Read(credID); err != nil {
			return nil, err
		}
	}

	var priv *ecdsa.PrivateKey
	if o.PrivateKeyPEM != "" {
		block, _ := pem.Decode([]byte(o.PrivateKeyPEM))
		if block == nil {
			return nil, fmt.Errorf("bad PEM")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an EC key")
		}
		priv = ec
	} else {
		var err error
		if priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, err
		}
	}
	return &Authenticator{RpID: rpID, Origin: origin, credID: credID, priv: priv}, nil
}

// CredentialID returns the base64url credential id.
func (a *Authenticator) CredentialID() string {
	return base64.RawURLEncoding.EncodeToString(a.credID)
}

// ECDSAPublicKey exposes the credential's public key for signature
// verification in tests.
func (a *Authenticator) ECDSAPublicKey() *ecdsa.PublicKey {
	return &a.priv.PublicKey
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func (a *Authenticator) coseKey() []byte {
	x := pad32(a.priv.PublicKey.X.Bytes())
	y := pad32(a.priv.PublicKey.Y.Bytes())
	// COSE_Key for ES256 / EC2 / P-256. Integer keys; canonical encoding.
	m := map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y}
	enc, _ := cbor.Marshal(m)
	return enc
}

func (a *Authenticator) clientDataJSON(typ, challenge string) []byte {
	// @simplewebauthn field order; go-webauthn parses as JSON so order is not
	// load-bearing here (unlike the SSH sshd byte-compare in spike/).
	b, _ := json.Marshal(map[string]any{
		"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false,
	})
	return b
}

// Register produces a RegistrationResponseJSON for the given base64url
// challenge (RegistrationResponseJSON in @simplewebauthn).
func (a *Authenticator) Register(challenge string) json.RawMessage {
	rpIDHash := sha256.Sum256([]byte(a.RpID))

	cose := a.coseKey()
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(a.credID)))
	attestedCredData := concat(make([]byte, 16), credIDLen, a.credID, cose) // zero AAGUID

	authData := concat(rpIDHash[:], []byte{flagUP | flagUV | flagAT}, u32(0), attestedCredData)
	attObj, _ := cbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{}, "authData": authData,
	})

	cdj := a.clientDataJSON("webauthn.create", challenge)
	resp := map[string]any{
		"id":    a.CredentialID(),
		"rawId": a.CredentialID(),
		"response": map[string]any{
			"clientDataJSON":    b64url(cdj),
			"attestationObject": b64url(attObj),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults":  map[string]any{},
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
	}
	out, _ := json.Marshal(resp)
	return out
}

// Authenticate produces an AuthenticationResponseJSON for the challenge,
// incrementing the internal signature counter.
func (a *Authenticator) Authenticate(challenge string) json.RawMessage {
	a.counter++
	rpIDHash := sha256.Sum256([]byte(a.RpID))
	authData := concat(rpIDHash[:], []byte{flagUP | flagUV}, u32(a.counter))

	cdj := a.clientDataJSON("webauthn.get", challenge)
	cdjHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(concat(authData, cdjHash[:]))
	sig, _ := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])

	resp := map[string]any{
		"id":    a.CredentialID(),
		"rawId": a.CredentialID(),
		"response": map[string]any{
			"clientDataJSON":    b64url(cdj),
			"authenticatorData": b64url(authData),
			"signature":         b64url(sig),
		},
		"clientExtensionResults":  map[string]any{},
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
	}
	out, _ := json.Marshal(resp)
	return out
}

func u32(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
