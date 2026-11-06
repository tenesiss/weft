package protocol

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedKeyfileRoundTrip(t *testing.T) {
	alice, bob, message := fixture(t)
	path := filepath.Join(t.TempDir(), "identity.key.json")
	password := []byte("test-only-long-passphrase")
	if err := bob.SaveEncrypted(path, password); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, bob.encryptionSK[:]) || bytes.Contains(stored, bob.signingSK.Seed()) {
		t.Fatal("plaintext key leaked")
	}
	loaded, err := LoadIdentity(path, password)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID() != bob.ID() {
		t.Fatal("identity changed on reload")
	}
	if _, err := message.Open(loaded, testNow); err != nil {
		t.Fatal("reloaded encryption key failed", err)
	}
	reply, err := NewMessage(loaded, alice.ID(), []byte("reply"), testNow, DefaultLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reply.Open(alice, testNow); err != nil {
		t.Fatal("reloaded signing key failed", err)
	}
	if err := bob.SaveEncrypted(path, password); err == nil {
		t.Fatal("existing key overwritten")
	}
	if _, err := LoadIdentity(path, []byte("wrong-test-passphrase")); err == nil {
		t.Fatal("wrong password accepted")
	}
	stored[len(stored)/2] ^= 1
	if err := os.WriteFile(path, stored, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(path, password); err == nil {
		t.Fatal("corrupt key accepted")
	}
}

func TestRejectShortKeyPassword(t *testing.T) {
	if err := identity(t).SaveEncrypted(filepath.Join(t.TempDir(), "key.json"), []byte("short")); err == nil {
		t.Fatal("short password accepted")
	}
}
