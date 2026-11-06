package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

var testNow = time.Unix(1800000000, 0)

func identity(t testing.TB) *Identity {
	t.Helper()
	i, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func fixture(t testing.TB) (*Identity, *Identity, Message) {
	t.Helper()
	a, b := identity(t), identity(t)
	m, err := NewMessage(a, b.ID(), []byte("hello, encrypted world"), testNow, DefaultLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return a, b, m
}

func sealInner(t testing.TB, target string, expiry int64, inner []byte) Message {
	t.Helper()
	recipient, err := ParseID(target)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.SealAnonymous(nil, inner, &recipient.EncryptionKey, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := Message{Version: Version, Target: target, ExpiresAt: expiry, Body: encode(ciphertext)}
	m.MessageID = envelopeID(m)
	return m
}

func sealBody(t testing.TB, target string, expiry int64, body Body) Message {
	t.Helper()
	inner, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return sealInner(t, target, expiry, inner)
}

func requireRejectedBody(t *testing.T, m Message, recipient *Identity, now time.Time) {
	t.Helper()
	body, err := m.OpenBody(recipient, now)
	if err == nil {
		t.Fatal("unauthenticated body accepted")
	}
	if body.Source != "" || body.Payload != nil || body.BodySignature != "" {
		t.Fatal("unverified content escaped on error")
	}
	if payload, err := m.Open(recipient, now); err == nil || payload != nil {
		t.Fatal("unverified payload escaped on error")
	}
}

func TestWholeBodyRoundTripAndWirePrivacy(t *testing.T) {
	alice, bob, m := fixture(t)
	wire, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	body, err := m.OpenBody(bob, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if body.Source != alice.ID() || body.Target != bob.ID() || string(body.Payload) != "hello, encrypted world" {
		t.Fatal("incorrect authenticated body")
	}
	for _, secret := range []string{alice.ID(), body.BodySignature, body.Nonce, "hello, encrypted world", `"source"`, `"body_signature"`, `"payload"`, `"created_at"`} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatalf("private body field leaked onto wire: %q", secret)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 5 {
		t.Fatalf("unexpected public envelope: %s", wire)
	}
	var encrypted string
	if err := json.Unmarshal(fields["body"], &encrypted); err != nil || encrypted != m.Body {
		t.Fatal("body is not an opaque ciphertext string")
	}
	parsed, err := ParseMessage(wire, testNow)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := parsed.Open(bob, testNow)
	if err != nil || string(plaintext) != "hello, encrypted world" {
		t.Fatalf("open: %q, %v", plaintext, err)
	}
	requireRejectedBody(t, parsed, identity(t), testNow)
	// Reordering the public envelope preserves its semantic content hash.
	reformatted, _ := json.MarshalIndent(fields, "", "  ")
	if _, err := ParseMessage(reformatted, testNow); err != nil {
		t.Fatal(err)
	}
	// Reordering the encrypted body also preserves its signature.
	inner, _ := json.Marshal(body)
	var bodyFields map[string]json.RawMessage
	if err := json.Unmarshal(inner, &bodyFields); err != nil {
		t.Fatal(err)
	}
	reformatted, _ = json.MarshalIndent(bodyFields, "", "  ")
	resealed := sealInner(t, bob.ID(), m.ExpiresAt, reformatted)
	if _, err := resealed.OpenBody(bob, testNow); err != nil {
		t.Fatalf("JSON formatting changed signature: %v", err)
	}
}

func TestEnvelopeHashBindsPublicFields(t *testing.T) {
	_, _, original := fixture(t)
	other := identity(t).ID()
	for name, change := range map[string]func(*Message){
		"id":         func(m *Message) { m.MessageID = encode(make([]byte, 32)) },
		"target":     func(m *Message) { m.Target = other },
		"version":    func(m *Message) { m.Version++ },
		"expiry":     func(m *Message) { m.ExpiresAt++ },
		"ciphertext": func(m *Message) { b, _ := m.ciphertext(); b[len(b)-1] ^= 1; m.Body = encode(b) },
	} {
		t.Run(name, func(t *testing.T) {
			m := original
			change(&m)
			if m.ValidateEnvelope(testNow) == nil {
				t.Fatal("changed envelope retained its original ID")
			}
		})
	}
}

func TestAllBodyFieldsAuthenticatedAfterDecryption(t *testing.T) {
	_, bob, original := fixture(t)
	body, err := original.OpenBody(bob, testNow)
	if err != nil {
		t.Fatal(err)
	}
	other := identity(t).ID()
	for name, change := range map[string]func(*Body){
		"version": func(b *Body) { b.Version++ },
		"source":  func(b *Body) { b.Source = other },
		"target":  func(b *Body) { b.Target = other },
		"nonce":   func(b *Body) { b.Nonce = encode(make([]byte, 16)) },
		"created": func(b *Body) { b.CreatedAt-- },
		"expiry":  func(b *Body) { b.ExpiresAt++ },
		"payload": func(b *Body) { b.Payload = []byte("forged plaintext") },
		"signature": func(b *Body) {
			signature, _ := decode(b.BodySignature, 64)
			signature[0] ^= 1
			b.BodySignature = encode(signature)
		},
		"missing signature": func(b *Body) { b.BodySignature = "" },
	} {
		t.Run(name, func(t *testing.T) {
			modified := body
			change(&modified)
			forged := sealBody(t, bob.ID(), original.ExpiresAt, modified)
			if err := forged.ValidateEnvelope(testNow); err != nil {
				t.Fatal("relays should only validate the public envelope", err)
			}
			requireRejectedBody(t, forged, bob, testNow)
		})
	}
}

func TestRecomputedHashDoesNotAuthenticateEnvelope(t *testing.T) {
	_, bob, original := fixture(t)
	t.Run("extended expiry", func(t *testing.T) {
		m := original
		m.ExpiresAt++
		m.MessageID = envelopeID(m)
		if err := m.ValidateEnvelope(testNow); err != nil {
			t.Fatal(err)
		}
		requireRejectedBody(t, m, bob, testNow)
	})
	t.Run("modified ciphertext", func(t *testing.T) {
		m := original
		ciphertext, _ := m.ciphertext()
		ciphertext[len(ciphertext)-1] ^= 1
		m.Body = encode(ciphertext)
		m.MessageID = envelopeID(m)
		if err := m.ValidateEnvelope(testNow); err != nil {
			t.Fatal(err)
		}
		requireRejectedBody(t, m, bob, testNow)
	})
	t.Run("different recipient", func(t *testing.T) {
		body, err := original.OpenBody(bob, testNow)
		if err != nil {
			t.Fatal(err)
		}
		carol := identity(t)
		// Even someone who knows the signed plaintext cannot redirect it to Carol.
		m := sealBody(t, carol.ID(), original.ExpiresAt, body)
		if err := m.ValidateEnvelope(testNow); err != nil {
			t.Fatal(err)
		}
		requireRejectedBody(t, m, carol, testNow)
	})
	t.Run("expired body with renewed envelope", func(t *testing.T) {
		m := original
		m.ExpiresAt += DefaultLifetime.Milliseconds()
		m.MessageID = envelopeID(m)
		later := testNow.Add(DefaultLifetime)
		if err := m.ValidateEnvelope(later); err != nil {
			t.Fatal(err)
		}
		requireRejectedBody(t, m, bob, later)
	})
}

func TestContentIDStableAcrossReencryption(t *testing.T) {
	_, bob, original := fixture(t)
	body, err := original.OpenBody(bob, testNow)
	if err != nil {
		t.Fatal(err)
	}
	resealed := sealBody(t, bob.ID(), original.ExpiresAt, body)
	opened, err := resealed.OpenBody(bob, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if original.MessageID == resealed.MessageID {
		t.Fatal("fresh encryption reused outer ID")
	}
	if body.ContentID() != opened.ContentID() {
		t.Fatal("recipient cannot identify re-encrypted duplicate")
	}
}

func TestMessageLimits(t *testing.T) {
	a, b, m := fixture(t)
	if err := m.ValidateEnvelope(testNow.Add(DefaultLifetime)); err == nil {
		t.Fatal("expired envelope accepted")
	}
	requireRejectedBody(t, m, b, testNow.Add(-ClockSkew-time.Millisecond))
	for _, lifetime := range []time.Duration{0, MaxLifetime + time.Second} {
		if _, err := NewMessage(a, b.ID(), nil, testNow, lifetime); err == nil {
			t.Fatal("invalid lifetime accepted")
		}
	}
	if _, err := NewMessage(a, b.ID(), make([]byte, MaxPayloadBytes+1), testNow, DefaultLifetime); err == nil {
		t.Fatal("oversized payload accepted")
	}
	for _, size := range []int{0, MaxPayloadBytes} {
		message, err := NewMessage(a, b.ID(), make([]byte, size), testNow, DefaultLifetime)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := message.Marshal()
		if _, err := ParseMessage(wire, testNow); err != nil {
			t.Fatal(err)
		}
		if plaintext, err := message.Open(b, testNow); err != nil || len(plaintext) != size {
			t.Fatal("payload size boundary failed", err)
		}
	}
	second, err := NewMessage(a, b.ID(), []byte("hello, encrypted world"), testNow, DefaultLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if second.MessageID == m.MessageID || second.Body == m.Body {
		t.Fatal("messages reused randomness")
	}
	m.ExpiresAt = testNow.Add(MaxLifetime + ClockSkew + time.Millisecond).UnixMilli()
	m.MessageID = envelopeID(m)
	if m.ValidateEnvelope(testNow) == nil {
		t.Fatal("unbounded relay expiry accepted")
	}
}

func TestStrictMessageDecoding(t *testing.T) {
	_, _, m := fixture(t)
	wire, _ := m.Marshal()
	for name, invalid := range map[string][]byte{
		"duplicate":      []byte(strings.Replace(string(wire), `"target":`, `"target":"bad","target":`, 1)),
		"case duplicate": []byte(strings.Replace(string(wire), `"target":`, `"TARGET":"bad","target":`, 1)),
		"unknown":        append([]byte(`{"unexpected":true,`), wire[1:]...),
		"trailing":       append(bytes.Clone(wire), []byte(` {}`)...),
		"oversize":       bytes.Repeat([]byte(" "), MaxWireBytes+1),
		"invalid utf8":   {0xff},
		"deep":           []byte(strings.Repeat("[", 20) + strings.Repeat("]", 20)),
		"null":           []byte("null"),
		"v1":             []byte(`{"version":1,"body":{"source":"public"},"body_signature":"public"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMessage(invalid, testNow); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
}

func TestStrictDecryptedBodyDecoding(t *testing.T) {
	_, bob, m := fixture(t)
	body, err := m.OpenBody(bob, testNow)
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := json.Marshal(body)
	for name, invalid := range map[string][]byte{
		"duplicate":       []byte(strings.Replace(string(inner), `"source":`, `"source":"bad","source":`, 1)),
		"unknown":         append([]byte(`{"unexpected":true,`), inner[1:]...),
		"trailing":        append(bytes.Clone(inner), []byte(` {}`)...),
		"null":            []byte("null"),
		"missing payload": []byte(strings.Replace(string(inner), `"payload":"aGVsbG8sIGVuY3J5cHRlZCB3b3JsZA==",`, "", 1)),
	} {
		t.Run(name, func(t *testing.T) { requireRejectedBody(t, sealInner(t, bob.ID(), m.ExpiresAt, invalid), bob, testNow) })
	}
}

func TestIdentityValidation(t *testing.T) {
	i := identity(t)
	if _, err := ParseID(i.ID()); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(i.ID(), ".")
	for _, bad := range []string{"", i.ID() + "=", parts[0], encode(make([]byte, 32)) + "." + parts[1], strings.ReplaceAll(i.ID(), ".", ".."), strings.Repeat("!", 43) + "." + parts[1]} {
		if _, err := ParseID(bad); err == nil {
			t.Fatalf("accepted invalid identity %s", bad)
		}
	}
}

func FuzzParseMessage(f *testing.F) {
	_, _, m := fixture(f)
	wire, _ := m.Marshal()
	f.Add(wire)
	f.Add([]byte(`{"body":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseMessage(data, testNow)
		if err == nil {
			if err := parsed.ValidateEnvelope(testNow); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzOpenBody(f *testing.F) {
	_, bob, m := fixture(f)
	body, err := m.OpenBody(bob, testNow)
	if err != nil {
		f.Fatal(err)
	}
	inner, _ := json.Marshal(body)
	f.Add(inner)
	f.Add([]byte(`{"source":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxBodyBytes {
			return
		}
		sealed := sealInner(t, bob.ID(), m.ExpiresAt, data)
		opened, err := sealed.OpenBody(bob, testNow)
		if err != nil {
			if opened.Source != "" || opened.Payload != nil {
				t.Fatal("unverified body returned")
			}
		} else if err := opened.verify(testNow); err != nil {
			t.Fatal(err)
		}
	})
}
