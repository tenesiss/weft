package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const ProofLifetime = time.Minute

// Challenge proves ownership of BOTH keys. Binding must come from an
// authenticated transport session (for example a TLS exporter), not a value
// supplied by an unauthenticated remote peer.
type Challenge struct {
	Verifier   string `json:"verifier"`
	Subject    string `json:"subject"`
	Binding    string `json:"binding"`
	ExpiresAt  int64  `json:"expires_at"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
}

type Proof struct {
	ChallengeID string `json:"challenge_id"`
	Signature   string `json:"signature"`
}

// PendingProof is verifier-local, one-use state. Never serialize or send it.
type PendingProof struct {
	mu        sync.Mutex
	challenge Challenge
	nonce     []byte
	used      bool
}

func challengeBytes(c Challenge) []byte {
	var b bytes.Buffer
	b.WriteString("WEFT/POI-CHALLENGE/v1\x00")
	field(&b, []byte(c.Verifier))
	field(&b, []byte(c.Subject))
	field(&b, []byte(c.Binding))
	_ = binary.Write(&b, binary.BigEndian, uint64(c.ExpiresAt))
	field(&b, []byte(c.Ciphertext))
	return b.Bytes()
}

func challengeID(c Challenge) string {
	hash := sha256.Sum256(challengeBytes(c))
	return encode(hash[:])
}

func responseBytes(c Challenge, nonce []byte) []byte {
	var b bytes.Buffer
	b.WriteString("WEFT/POI-RESPONSE/v1\x00")
	field(&b, []byte(challengeID(c)))
	field(&b, nonce)
	return b.Bytes()
}

func NewChallenge(verifier *Identity, subject string, binding [32]byte, now time.Time) (Challenge, *PendingProof, error) {
	var c Challenge
	if verifier == nil || len(verifier.signingSK) != ed25519.PrivateKeySize {
		return c, nil, errors.New("invalid verifier identity")
	}
	if binding == [32]byte{} {
		return c, nil, errors.New("empty session binding")
	}
	public, err := ParseID(subject)
	if err != nil {
		return c, nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return c, nil, err
	}
	ciphertext, err := box.SealAnonymous(nil, nonce, &public.EncryptionKey, rand.Reader)
	if err != nil {
		return c, nil, err
	}
	c = Challenge{Verifier: verifier.ID(), Subject: subject, Binding: encode(binding[:]), ExpiresAt: now.Add(ProofLifetime).UnixMilli(), Ciphertext: encode(ciphertext)}
	c.Signature = encode(ed25519.Sign(verifier.signingSK, challengeBytes(c)))
	return c, &PendingProof{challenge: c, nonce: nonce}, nil
}

func AnswerChallenge(subject *Identity, c Challenge, expectedVerifier string, binding [32]byte, now time.Time) (Proof, error) {
	var proof Proof
	if subject == nil || len(subject.signingSK) != ed25519.PrivateKeySize {
		return proof, errors.New("invalid subject identity")
	}
	if binding == [32]byte{} || c.Subject != subject.ID() || c.Verifier != expectedVerifier || c.Binding != encode(binding[:]) {
		return proof, errors.New("challenge identity or session mismatch")
	}
	if c.ExpiresAt <= now.UnixMilli() || c.ExpiresAt > now.Add(ProofLifetime+ClockSkew).UnixMilli() {
		return proof, errors.New("invalid challenge expiration")
	}
	public, err := ParseID(c.Verifier)
	if err != nil {
		return proof, err
	}
	ciphertext, err := decode(c.Ciphertext, 32+box.AnonymousOverhead)
	if err != nil {
		return proof, err
	}
	signature, err := decode(c.Signature, ed25519.SignatureSize)
	if err != nil {
		return proof, err
	}
	if !ed25519.Verify(public.SigningKey, challengeBytes(c), signature) {
		return proof, errors.New("invalid challenge signature")
	}
	nonce, ok := box.OpenAnonymous(nil, ciphertext, &subject.encryptionPK, &subject.encryptionSK)
	if !ok {
		return proof, errors.New("cannot decrypt identity challenge")
	}
	proof = Proof{ChallengeID: challengeID(c), Signature: encode(ed25519.Sign(subject.signingSK, responseBytes(c, nonce)))}
	return proof, nil
}

func (p *PendingProof) Verify(proof Proof, binding [32]byte, now time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used || p.challenge.ExpiresAt <= now.UnixMilli() {
		return errors.New("challenge expired or already used")
	}
	if p.challenge.Binding != encode(binding[:]) || proof.ChallengeID != challengeID(p.challenge) {
		return errors.New("proof session or challenge mismatch")
	}
	public, err := ParseID(p.challenge.Subject)
	if err != nil {
		return err
	}
	signature, err := decode(proof.Signature, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public.SigningKey, responseBytes(p.challenge, p.nonce), signature) {
		return errors.New("invalid identity proof")
	}
	p.used = true
	clear(p.nonce)
	return nil
}
