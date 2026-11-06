package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const (
	Version         = 2
	MaxPayloadBytes = 64 * 1024
	MaxBodyBytes    = 95 * 1024
	MaxWireBytes    = 128 * 1024
	MaxLifetime     = 24 * time.Hour
	DefaultLifetime = 5 * time.Minute
	ClockSkew       = 30 * time.Second
)

// Body is private to the sender and recipient. Its signature covers every field
// except BodySignature. Payload is arbitrary bytes (standard base64 inside JSON).
// Only use a body returned successfully by OpenBody as authenticated content.
type Body struct {
	Version       int    `json:"version"`
	Source        string `json:"source"`
	Target        string `json:"target"`
	Nonce         string `json:"nonce"`
	CreatedAt     int64  `json:"created_at"`
	ExpiresAt     int64  `json:"expires_at"`
	Payload       []byte `json:"payload"`
	BodySignature string `json:"body_signature"`
}

// Message contains only the public routing envelope and the encrypted body.
// ExpiresAt is an untrusted relay hint until OpenBody checks the signed copy.
type Message struct {
	Version   int    `json:"version"`
	MessageID string `json:"messageID"`
	Target    string `json:"target"`
	ExpiresAt int64  `json:"expires_at"`
	Body      string `json:"body"`
}

// canonicalBody is a wire-independent, domain-separated signing format. The
// signature itself is excluded; JSON object order and whitespace are irrelevant.
func canonicalBody(b Body) []byte {
	var out bytes.Buffer
	out.WriteString("DEMP/BODY/v2\x00")
	_ = binary.Write(&out, binary.BigEndian, uint32(b.Version))
	field(&out, []byte(b.Source))
	field(&out, []byte(b.Target))
	field(&out, []byte(b.Nonce))
	_ = binary.Write(&out, binary.BigEndian, uint64(b.CreatedAt))
	_ = binary.Write(&out, binary.BigEndian, uint64(b.ExpiresAt))
	field(&out, b.Payload)
	return out.Bytes()
}

// envelopeID is a public content hash, NOT proof of origin. Anyone can recompute
// it; only the recipient can authenticate the encrypted body and routing fields.
func envelopeID(m Message) string {
	var out bytes.Buffer
	out.WriteString("DEMP/ENVELOPE/v2\x00")
	_ = binary.Write(&out, binary.BigEndian, uint32(m.Version))
	field(&out, []byte(m.Target))
	_ = binary.Write(&out, binary.BigEndian, uint64(m.ExpiresAt))
	field(&out, []byte(m.Body))
	hash := sha256.Sum256(out.Bytes())
	return encode(hash[:])
}

// ContentID identifies authenticated signed content across re-encryption. Use it
// ONLY on a successfully opened body, for recipient-side replay suppression.
// Keep this ID private: publishing it would make different encryptions linkable.
func (b Body) ContentID() string {
	var out bytes.Buffer
	out.WriteString("DEMP/CONTENT/v2\x00")
	out.Write(canonicalBody(b))
	field(&out, []byte(b.BodySignature))
	hash := sha256.Sum256(out.Bytes())
	return encode(hash[:])
}

// NewMessage signs the body, then encrypts the entire signed body for target.
// Source, payload, nonce, creation time, and signature never enter the envelope.
func NewMessage(sender *Identity, target string, plaintext []byte, now time.Time, lifetime time.Duration) (Message, error) {
	var message Message
	if sender == nil || len(sender.signingSK) != ed25519.PrivateKeySize {
		return message, errors.New("invalid sender identity")
	}
	if len(plaintext) > MaxPayloadBytes {
		return message, errors.New("payload too large")
	}
	if lifetime < time.Second || lifetime > MaxLifetime {
		return message, errors.New("lifetime must be between one second and 24 hours")
	}
	recipient, err := ParseID(target)
	if err != nil {
		return message, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return message, err
	}
	body := Body{
		Version: Version, Source: sender.ID(), Target: target, Nonce: encode(nonce),
		CreatedAt: now.UnixMilli(), ExpiresAt: now.Add(lifetime).UnixMilli(),
		Payload: append([]byte{}, plaintext...),
	}
	body.BodySignature = encode(ed25519.Sign(sender.signingSK, canonicalBody(body)))
	if err := body.verify(now); err != nil {
		return message, err
	}
	inner, err := json.Marshal(body)
	if err != nil {
		return message, err
	}
	if len(inner) > MaxBodyBytes {
		return message, errors.New("signed body too large")
	}
	ciphertext, err := box.SealAnonymous(nil, inner, &recipient.EncryptionKey, rand.Reader)
	if err != nil {
		return message, err
	}
	message = Message{Version: Version, Target: target, ExpiresAt: body.ExpiresAt, Body: encode(ciphertext)}
	message.MessageID = envelopeID(message)
	if err := message.ValidateEnvelope(now); err != nil {
		return Message{}, err
	}
	return message, nil
}

// ValidateEnvelope checks relay-visible structure, size, expiry bounds and the
// content hash. It does NOT authenticate a sender, expiry, or the encrypted body.
func (m Message) ValidateEnvelope(now time.Time) error {
	if m.Version != Version {
		return errors.New("unsupported protocol version")
	}
	if _, err := ParseID(m.Target); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if m.ExpiresAt <= 0 || m.ExpiresAt <= now.UnixMilli() {
		return errors.New("envelope expired")
	}
	if m.ExpiresAt > now.Add(MaxLifetime+ClockSkew).UnixMilli() {
		return errors.New("envelope expiry too far in the future")
	}
	if _, err := m.ciphertext(); err != nil {
		return err
	}
	if !ValidMessageID(m.MessageID) || m.MessageID != envelopeID(m) {
		return errors.New("invalid envelope content hash")
	}
	return nil
}

func (m Message) ciphertext() ([]byte, error) {
	minSize := box.AnonymousOverhead + 1
	if len(m.Body) < encoding.EncodedLen(minSize) || len(m.Body) > encoding.EncodedLen(box.AnonymousOverhead+MaxBodyBytes) {
		return nil, errors.New("invalid ciphertext size")
	}
	b, err := encoding.DecodeString(m.Body)
	if err != nil || encode(b) != m.Body || len(b) < minSize {
		return nil, errors.New("invalid ciphertext encoding")
	}
	return b, nil
}

func (b Body) verify(now time.Time) error {
	if b.Version != Version {
		return errors.New("unsupported body version")
	}
	source, err := ParseID(b.Source)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if _, err := ParseID(b.Target); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if _, err := decode(b.Nonce, 16); err != nil {
		return err
	}
	if b.CreatedAt <= 0 || b.ExpiresAt <= b.CreatedAt || b.ExpiresAt-b.CreatedAt > MaxLifetime.Milliseconds() {
		return errors.New("invalid message lifetime")
	}
	if b.CreatedAt > now.Add(ClockSkew).UnixMilli() {
		return errors.New("message created in the future")
	}
	if b.ExpiresAt <= now.UnixMilli() {
		return errors.New("message expired")
	}
	if b.Payload == nil || len(b.Payload) > MaxPayloadBytes {
		return errors.New("missing or oversized payload")
	}
	signature, err := decode(b.BodySignature, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	if !ed25519.Verify(source.SigningKey, canonicalBody(b), signature) {
		return errors.New("invalid body signature")
	}
	return nil
}

// OpenBody decrypts, verifies the sender's signature and signed lifetime, then
// binds the public version, target and expiry to the authenticated inner fields.
// No unverified body or payload is returned on failure.
func (m Message) OpenBody(recipient *Identity, now time.Time) (Body, error) {
	if recipient == nil || len(recipient.signingSK) != ed25519.PrivateKeySize {
		return Body{}, errors.New("invalid recipient identity")
	}
	if err := m.ValidateEnvelope(now); err != nil {
		return Body{}, err
	}
	if recipient.ID() != m.Target {
		return Body{}, errors.New("message is addressed to another identity")
	}
	ciphertext, _ := m.ciphertext()
	inner, ok := box.OpenAnonymous(nil, ciphertext, &recipient.encryptionPK, &recipient.encryptionSK)
	if !ok {
		return Body{}, errors.New("cannot decrypt body")
	}
	var body Body
	if err := DecodeJSON(inner, &body, MaxBodyBytes); err != nil {
		return Body{}, err
	}
	if err := body.verify(now); err != nil {
		return Body{}, err
	}
	if m.Version != body.Version || m.Target != body.Target || m.ExpiresAt != body.ExpiresAt {
		return Body{}, errors.New("envelope differs from signed body")
	}
	return body, nil
}

// Open is a convenience wrapper returning only the authenticated payload.
func (m Message) Open(recipient *Identity, now time.Time) ([]byte, error) {
	body, err := m.OpenBody(recipient, now)
	if err != nil {
		return nil, err
	}
	return body.Payload, nil
}

func (m Message) Marshal() ([]byte, error) { return json.Marshal(m) }

// ParseMessage only validates the public envelope. Recipients must call OpenBody
// or Open before trusting source identity or processing any decrypted content.
func ParseMessage(data []byte, now time.Time) (Message, error) {
	var message Message
	if err := DecodeJSON(data, &message, MaxWireBytes); err != nil {
		return message, err
	}
	return message, message.ValidateEnvelope(now)
}

func ValidMessageID(id string) bool { _, err := decode(id, sha256.Size); return err == nil }
