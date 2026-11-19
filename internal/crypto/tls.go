package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/http"
	"time"
)

// Fingerprint is SHA-256 of the stable Ed25519 device public key.
func (im *IdentityManager) Fingerprint() string {
	im.mu.RLock()
	defer im.mu.RUnlock()
	h := sha256.Sum256(im.pubKey)
	return hex.EncodeToString(h[:])
}

func (im *IdentityManager) TLSConfig(ips []string) (*tls.Config, error) {
	im.mu.RLock()
	defer im.mu.RUnlock()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "LanChat " + im.peerID}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}}
	for _, ip := range append(ips, "127.0.0.1", "::1") {
		if p := net.ParseIP(ip); p != nil {
			cert.IPAddresses = append(cert.IPAddresses, p)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, im.pubKey, im.privKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: im.privKey}}}, nil
}

// PinnedClient authenticates the key copied out-of-band in the pairing string.
// PKI hostname verification is replaced by an explicit full public-key pin.
func PinnedClient(fingerprint string, timeout time.Duration) (*http.Client, error) {
	raw, err := hex.DecodeString(fingerprint)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("complete device fingerprint required")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) != 1 {
			return errors.New("unexpected certificate chain")
		}
		cert := cs.PeerCertificates[0]
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("not an Ed25519 device")
		}
		h := sha256.Sum256(pub)
		if hex.EncodeToString(h[:]) != fingerprint {
			return errors.New("device fingerprint mismatch")
		}
		if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			return errors.New("device certificate expired")
		}
		return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	}}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: cfg, Proxy: nil, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &idleConn{Conn: c}, nil
	}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second, MaxConnsPerHost: 8}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func (im *IdentityManager) PeerClient(peerID string, timeout time.Duration) (*http.Client, error) {
	p, ok := im.GetTrustedPeer(peerID)
	if !ok || !ValidPeerIdentity(p.PeerID, p.PublicKeyHex) {
		return nil, errors.New("untrusted device identity; pair again")
	}
	pub, _ := hex.DecodeString(p.PublicKeyHex)
	h := sha256.Sum256(pub)
	return PinnedClient(hex.EncodeToString(h[:]), timeout)
}

type idleConn struct{ net.Conn }

func (c *idleConn) Read(b []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	return c.Conn.Read(b)
}
func (c *idleConn) Write(b []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(90 * time.Second))
	return c.Conn.Write(b)
}
