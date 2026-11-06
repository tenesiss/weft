package protocol

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestProofOfBothKeys(t *testing.T) {
	alice, bob := identity(t), identity(t)
	binding := [32]byte{42}
	c, pending, err := NewChallenge(alice, bob.ID(), binding, testNow)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := AnswerChallenge(bob, c, alice.ID(), binding, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.Verify(proof, [32]byte{99}, testNow); err == nil {
		t.Fatal("proof accepted in wrong session")
	}
	if err := pending.Verify(proof, binding, testNow); err != nil {
		t.Fatal(err)
	}
	if err := pending.Verify(proof, binding, testNow); err == nil {
		t.Fatal("proof replay accepted")
	}
}

func TestProofRejectsImpersonationAndExpiry(t *testing.T) {
	alice, bob, mallory := identity(t), identity(t), identity(t)
	binding := [32]byte{42}
	c, pending, err := NewChallenge(alice, bob.ID(), binding, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"wrong identity": func() error { _, err := AnswerChallenge(mallory, c, alice.ID(), binding, testNow); return err },
		"wrong verifier": func() error { _, err := AnswerChallenge(bob, c, mallory.ID(), binding, testNow); return err },
		"wrong session":  func() error { _, err := AnswerChallenge(bob, c, alice.ID(), [32]byte{1}, testNow); return err },
		"expired": func() error {
			_, err := AnswerChallenge(bob, c, alice.ID(), binding, testNow.Add(ProofLifetime))
			return err
		},
		"tampered": func() error {
			modified := c
			modified.ExpiresAt++
			_, err := AnswerChallenge(bob, modified, alice.ID(), binding, testNow)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if run() == nil {
				t.Fatal("invalid proof challenge accepted")
			}
		})
	}
	proof, err := AnswerChallenge(bob, c, alice.ID(), binding, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.Verify(proof, binding, testNow.Add(time.Minute)); err == nil {
		t.Fatal("expired proof accepted")
	}
	_, another, err := NewChallenge(alice, bob.ID(), binding, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := another.Verify(proof, binding, testNow); err == nil {
		t.Fatal("proof reused for another challenge")
	}
}

func TestSigningKeyAloneCannotAnswer(t *testing.T) {
	alice, bob, mallory := identity(t), identity(t), identity(t)
	binding := [32]byte{42}
	c, pending, err := NewChallenge(alice, bob.ID(), binding, testNow)
	if err != nil {
		t.Fatal(err)
	}
	// The attacker has Bob's signing key and public encryption key, but not his
	// encryption secret. Its claimed ID is exactly Bob's.
	signingOnly := &Identity{encryptionPK: bob.encryptionPK, encryptionSK: mallory.encryptionSK, signingSK: bob.signingSK}
	if _, err := AnswerChallenge(signingOnly, c, alice.ID(), binding, testNow); err == nil {
		t.Fatal("signing key alone sufficed")
	}
	// Conversely, possession of the encryption key cannot forge the signature.
	forged := Proof{ChallengeID: challengeID(c), Signature: encode(ed25519.Sign(mallory.signingSK, responseBytes(c, pending.nonce)))}
	if err := pending.Verify(forged, binding, testNow); err == nil {
		t.Fatal("encryption key alone sufficed")
	}
}
