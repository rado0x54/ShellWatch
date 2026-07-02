// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package spike is the Phase 0 de-risk spike for the Go rewrite (#210):
// a custom ssh.Signer that produces webauthn-sk-ecdsa signatures from a
// fake WebAuthn authenticator, composable with ssh.NewCertSigner.
//
// Byte-format ground truth is the production Node implementation:
//   - src/webauthn/signature-format.ts — SSH wire layout
//     (Signature.Blob = mpint R || mpint S; Signature.Rest = flags ||
//     counter || string origin || string clientDataJSON || string extensions)
//   - src/test/helpers/fake-authenticator.ts — assertion construction
//     (authData = SHA256(rpId) || flags || u32(counter); ECDSA over
//     SHA256(authData || SHA256(clientDataJSON)))
//
// The verifier (sshd) RECONSTRUCTS authData from the key's application
// string plus the flags/counter/extensions carried in the signature — which
// is why the wire format carries no authenticatorData field. The rpId
// hashed into authData must therefore equal the sk key's application.
package spike

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/ssh"
)

const webauthnSKAlgo = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"

// Authenticator flag bits (WebAuthn §6.1).
const (
	flagUP = 0x01
	flagUV = 0x04
)

// WebauthnSigner is an ssh.Signer producing webauthn-sk-ecdsa signatures
// with a local P-256 key standing in for the passkey (fake authenticator).
//
// Pub is the ssh.PublicKey presented on the wire. For the certificate path
// this is cert.Key — the sk-ecdsa key embedded in the cert (ssh-keygen
// canonicalizes the cert type to sk-ecdsa-…-cert-v01; webauthn- is a
// signature algorithm, not a key type). x/crypto parses sk-ecdsa natively,
// so no custom key type is needed; only the Signature we return is custom.
type WebauthnSigner struct {
	Pub     ssh.PublicKey
	Priv    *ecdsa.PrivateKey
	RpID    string // must equal the sk key's application string
	Origin  string // clientDataJSON origin; hostname must match RpID
	counter uint32
	// ChallengeStdB64 switches clientDataJSON.challenge to standard base64
	// (browsers emit base64url-no-pad; the toggle exists to probe what the
	// target sshd accepts).
	ChallengeStdB64 bool
}

var _ ssh.Signer = (*WebauthnSigner)(nil)

func (s *WebauthnSigner) PublicKey() ssh.PublicKey { return s.Pub }

// Sign produces the webauthn-sk-ecdsa SSH signature over data (the SSH
// signing payload — for publickey auth, the session-bound blob built by the
// transport layer).
func (s *WebauthnSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	s.counter++

	enc := base64.RawURLEncoding.EncodeToString(data)
	if s.ChallengeStdB64 {
		enc = base64.StdEncoding.EncodeToString(data)
	}
	// KEY ORDER IS LOAD-BEARING: sshd's webauthn check does not parse this
	// JSON — it byte-compares the prefix against the literal
	// {"type":"webauthn.get","challenge":"<b64url>","origin":"<origin>"
	// (openssh ssh-ecdsa-sk.c webauthn_check_prepare_hash). Browsers emit
	// exactly this order; Go's json.Marshal(map) sorts keys and can never
	// match, so the JSON is assembled literally.
	cdj := []byte(fmt.Sprintf(
		`{"type":"webauthn.get","challenge":"%s","origin":"%s","crossOrigin":false}`,
		enc, s.Origin))

	// authData = SHA256(rpId) || flags || u32be(counter)   (no extensions)
	rpIDHash := sha256.Sum256([]byte(s.RpID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flagUP|flagUV)
	authData = binary.BigEndian.AppendUint32(authData, s.counter)

	// ECDSA over SHA256(authData || SHA256(clientDataJSON)).
	cdjHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdjHash[:]...))
	r, sc, err := ecdsa.Sign(rand.Reader, s.Priv, digest[:])
	if err != nil {
		return nil, err
	}

	// Blob: raw mpint R || mpint S (Marshal wraps Blob once as an SSH string,
	// which the verifier consumes via sshbuf_froms as the ecdsa_signature).
	blob := append(mpint(r), mpint(sc)...)

	// Rest: appended verbatim after the Blob string.
	rest := []byte{flagUP | flagUV}
	rest = binary.BigEndian.AppendUint32(rest, s.counter)
	rest = appendSSHString(rest, []byte(s.Origin))
	rest = appendSSHString(rest, cdj)
	rest = appendSSHString(rest, nil) // extensions: empty

	return &ssh.Signature{Format: webauthnSKAlgo, Blob: blob, Rest: rest}, nil
}

func appendSSHString(dst, s []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

// mpint encodes a positive big integer as an SSH mpint (length-prefixed,
// big-endian, 0x00-padded when the MSB is set).
func mpint(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return appendSSHString(nil, b)
}

// LoadP256PrivateKeyPEM loads the fake authenticator's PKCS#8 P-256 key
// (spike/out/keys/webauthn-sk.pem, from mint-webauthn-sk-key.ts).
func LoadP256PrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an EC key: %T", key)
	}
	return ec, nil
}
