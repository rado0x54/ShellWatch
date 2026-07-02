// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Phase 0 spike tests (#210): certificate auth against the spike sshd
// (spike/docker-compose.yml, 127.0.0.1:2222). Run ../gen-spike-env.sh and
// `docker compose up -d` in spike/ first; tests skip when the target or the
// key material is absent.
package spike

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const spikeAddr = "127.0.0.1:2222"

func keysDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "out", "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("spike key material missing (%v) — run spike/gen-spike-env.sh", err)
	}
	return dir
}

func requireSshd(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", spikeAddr, 2*time.Second)
	if err != nil {
		t.Skipf("spike sshd not reachable on %s — run `docker compose up -d` in spike/", spikeAddr)
	}
	conn.Close()
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseCert(t *testing.T, path string) *ssh.Certificate {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey(mustReadFile(t, path))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("%s is not a certificate: %T", path, pub)
	}
	return cert
}

func dialAndRun(t *testing.T, signer ssh.Signer) error {
	t.Helper()
	client, err := ssh.Dial("tcp", spikeAddr, &ssh.ClientConfig{
		User:            "spike",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // throwaway spike host
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("dial/auth: %w", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("session: %w", err)
	}
	defer sess.Close()
	out, err := sess.Output("echo spike-ok")
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	if string(out) != "spike-ok\n" {
		return fmt.Errorf("unexpected output %q", out)
	}
	return nil
}

// TestControlCertAuth proves the CA/sshd plumbing with a plain ed25519
// cert, independent of anything webauthn.
func TestControlCertAuth(t *testing.T) {
	requireSshd(t)
	dir := keysDir(t)

	raw, err := ssh.ParsePrivateKey(mustReadFile(t, filepath.Join(dir, "control")))
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, filepath.Join(dir, "control-cert.pub"))
	signer, err := ssh.NewCertSigner(cert, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := dialAndRun(t, signer); err != nil {
		t.Fatalf("control cert auth failed: %v", err)
	}
	t.Log("control: ed25519 cert accepted via TrustedUserCAKeys")
}

// TestWebauthnSKCertAuth is the crux of #210 Phase 0: an sk-ecdsa user cert
// presented by ssh.NewCertSigner wrapped around a custom Signer whose
// signatures use the webauthn-sk-ecdsa algorithm, minted by a fake
// authenticator — i.e. exactly what the Go backend will do with a real
// passkey behind the pending-action flow.
func TestWebauthnSKCertAuth(t *testing.T) {
	requireSshd(t)
	dir := keysDir(t)

	priv, err := LoadP256PrivateKeyPEM(mustReadFile(t, filepath.Join(dir, "webauthn-sk.pem")))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Application string `json:"application"`
	}
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(dir, "webauthn-sk.meta.json")), &meta); err != nil {
		t.Fatal(err)
	}

	cert := parseCert(t, filepath.Join(dir, "webauthn-sk-cert.pub"))
	t.Logf("cert type on the wire: %s (embedded key: %s, application=%s)",
		cert.Type(), cert.Key.Type(), meta.Application)

	origin := os.Getenv("SPIKE_ORIGIN")
	if origin == "" {
		origin = "https://" + meta.Application
	}
	wa := &WebauthnSigner{
		Pub:    cert.Key, // the sk-ecdsa key embedded in the canonicalized cert
		Priv:   priv,
		RpID:   meta.Application,
		Origin: origin,
	}
	signer, err := ssh.NewCertSigner(cert, wa)
	if err != nil {
		t.Fatalf("NewCertSigner(cert, webauthnSigner): %v", err)
	}

	if err := dialAndRun(t, signer); err != nil {
		// Probe the one deliberately-uncertain encoding choice before failing:
		// browsers emit base64url-no-pad challenges; retry with std base64.
		wa2 := &WebauthnSigner{Pub: cert.Key, Priv: priv, RpID: meta.Application,
			Origin: origin, ChallengeStdB64: true}
		signer2, err2 := ssh.NewCertSigner(cert, wa2)
		if err2 == nil {
			if errStd := dialAndRun(t, signer2); errStd == nil {
				t.Fatalf("AUTH SUCCEEDED ONLY WITH STD-BASE64 CHALLENGE — browsers emit base64url; "+
					"record this in spike/README.md and adjust the signer default. (b64url attempt: %v)", err)
			}
		}
		t.Fatalf("webauthn-sk cert auth failed (both challenge encodings): %v", err)
	}
	t.Log("crux validated: sk-ecdsa cert + webauthn-sk-ecdsa signature accepted by sshd")
}
