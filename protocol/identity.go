// Package protocol implements WEFT identities, the experimental v2 encrypted
// message format, and the independently versioned v1 proof-of-possession exchange.
package protocol

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

// Identity keeps independent encryption and signing private keys unexported.
// It is safe for concurrent use. Do not log or serialize private keys.
type Identity struct {
	encryptionPK [32]byte
	encryptionSK [32]byte
	signingSK    ed25519.PrivateKey
}

type PublicIdentity struct {
	EncryptionKey [32]byte
	SigningKey    ed25519.PublicKey
}

func GenerateIdentity() (*Identity, error) {
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{encryptionPK: *pk, encryptionSK: *sk, signingSK: signing}, nil
}

func (i *Identity) ID() string {
	if i == nil || len(i.signingSK) != ed25519.PrivateKeySize {
		return ""
	}
	return encode(i.encryptionPK[:]) + "." + encode(i.signingSK.Public().(ed25519.PublicKey))
}

// ParseID accepts exactly two unpadded, canonical base64url 32-byte public keys.
func ParseID(id string) (PublicIdentity, error) {
	var identity PublicIdentity
	if len(id) != 87 {
		return identity, errors.New("node ID must be encryption_pk.signing_pk (87 characters)")
	}
	parts := strings.Split(id, ".")
	if len(parts) != 2 {
		return identity, errors.New("invalid node ID")
	}
	encryption, err := decode(parts[0], 32)
	if err != nil {
		return identity, err
	}
	signing, err := decode(parts[1], ed25519.PublicKeySize)
	if err != nil {
		return identity, err
	}
	// Reject low-order X25519 keys before they reach NaCl's legacy API.
	public, err := ecdh.X25519().NewPublicKey(encryption)
	if err != nil {
		return identity, err
	}
	probe := [32]byte{1}
	private, _ := ecdh.X25519().NewPrivateKey(probe[:])
	if _, err := private.ECDH(public); err != nil {
		return identity, errors.New("invalid X25519 public key")
	}
	copy(identity.EncryptionKey[:], encryption)
	identity.SigningKey = ed25519.PublicKey(signing)
	return identity, nil
}
