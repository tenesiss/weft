package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"time"
)

// TransportCertificate binds the full WEFT ID to its Ed25519 TLS key. It is
// self-signed: trust comes from explicit WEFT identity pinning, not public CAs.
// The returned TLS credential contains a private signer; never serialize/log it.
func (i *Identity) TransportCertificate(now time.Time) (tls.Certificate, error) {
	if i.ID() == "" {
		return tls.Certificate{}, errors.New("invalid identity")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "WEFT peer"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{{Scheme: "weft", Opaque: i.ID()}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, i.signingSK.Public(), i.signingSK)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Copy the key so callers cannot mutate this identity through TLS credentials.
	key := append(ed25519.PrivateKey(nil), i.signingSK...)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
