package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
)

const keyfileDomain = "DEMP/KEYFILE/v1\x00"

type keyfile struct {
	Version    int    `json:"version"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func keyfileCipher(password, salt []byte) (cipher.AEAD, error) {
	if len(password) < 12 {
		return nil, errors.New("key password must contain at least 12 bytes")
	}
	// Fixed, bounded parameters: scrypt N=32768, r=8, p=1, approximately 32 MiB.
	key, err := scrypt.Key(password, salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SaveEncrypted persists both private keys with scrypt and AES-256-GCM. Existing
// files are never overwritten. File mode 0600 is used where the OS supports it;
// confidentiality on Windows also relies on the password and directory ACLs.
func (i *Identity) SaveEncrypted(path string, password []byte) error {
	if i.ID() == "" {
		return errors.New("invalid identity")
	}
	data := keyfile{Version: 1, Salt: make([]byte, 16), Nonce: make([]byte, 12)}
	if _, err := rand.Read(data.Salt); err != nil {
		return err
	}
	if _, err := rand.Read(data.Nonce); err != nil {
		return err
	}
	aead, err := keyfileCipher(password, data.Salt)
	if err != nil {
		return err
	}
	secret := make([]byte, 64)
	copy(secret[:32], i.encryptionSK[:])
	copy(secret[32:], i.signingSK.Seed())
	defer clear(secret)
	data.Ciphertext = aead.Seal(nil, data.Nonce, secret, []byte(keyfileDomain))
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func LoadIdentity(path string, password []byte) (*Identity, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return nil, err
	}
	var data keyfile
	if err := DecodeJSON(encoded, &data, 4096); err != nil {
		return nil, err
	}
	if data.Version != 1 || len(data.Salt) != 16 || len(data.Nonce) != 12 || len(data.Ciphertext) != 80 {
		return nil, errors.New("invalid encrypted key file")
	}
	aead, err := keyfileCipher(password, data.Salt)
	if err != nil {
		return nil, err
	}
	secret, err := aead.Open(nil, data.Nonce, data.Ciphertext, []byte(keyfileDomain))
	if err != nil {
		return nil, errors.New("wrong key password or corrupt key file")
	}
	defer clear(secret)
	encryption, err := ecdh.X25519().NewPrivateKey(secret[:32])
	if err != nil {
		return nil, err
	}
	id := &Identity{signingSK: ed25519.NewKeyFromSeed(secret[32:])}
	copy(id.encryptionSK[:], secret[:32])
	copy(id.encryptionPK[:], encryption.PublicKey().Bytes())
	return id, nil
}
