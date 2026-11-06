# Weft v2 wire protocol

Version 2 encrypts the complete signed body. It replaces the incompatible v1 message format; v1 messages are rejected. Identity encoding and the independently versioned v1 proof-of-possession exchange remain unchanged.

The literal `DEMP/...` domain separators below remain part of the current wire format. The Weft project name does not change these bytes or the encoded messages.

## Identity

`encryption_pk.signing_pk` consists of two independent 32-byte public keys: X25519 followed by Ed25519. Each is encoded as canonical, unpadded base64url, separated by one dot: 87 ASCII characters total. Private keys remain local. Low-order X25519 public keys are rejected.

The complete source ID is signed inside the encrypted body, binding its encryption key to the signing key for that message. Only the recipient can read and verify it. Possession of the encryption secret requires the separate challenge below. A contact's expected ID must still be obtained through trusted contact exchange or another application policy.

## Public envelope

```json
{
  "version": 2,
  "messageID": "<base64url public envelope hash>",
  "target": "<recipient encryption_pk.signing_pk>",
  "expires_at": 1800000300000,
  "body": "<base64url sealed box containing the entire signed body>"
}
```

There is no public `source` or `body_signature`. `target` is the final recipient, never a next-hop address. The public expiry lets relays discard cached envelopes without decrypting them. It is an **untrusted cache hint** until the recipient checks the signed copy inside the body.

`messageID` is a public hash identifying this envelope for relay deduplication. The recipient authenticates the sender by verifying the signature inside the encrypted body.

## Encrypted body

The plaintext of the sealed box is a UTF-8 JSON object with this structure:

```json
{
  "version": 2,
  "source": "<sender encryption_pk.signing_pk>",
  "target": "<recipient encryption_pk.signing_pk>",
  "nonce": "<base64url 16 random bytes>",
  "created_at": 1800000000000,
  "expires_at": 1800000300000,
  "payload": "<standard padded base64 of arbitrary payload bytes>",
  "body_signature": "<base64url 64-byte Ed25519 signature>"
}
```

The signature covers every body field except `body_signature` itself. The sender signs first, includes the signature in the body, then encrypts the entire object. The recipient must decrypt before it can verify the hidden signature; the API exposes no body or payload until all checks succeed.

The inner and outer `version`, `target`, and `expires_at` MUST match exactly. These signed copies prevent an attacker from redirecting a valid body or extending its accepted lifetime by changing the public header and recalculating its hash.

## Signed bytes and encryption

`U32(x)` and `U64(x)` mean unsigned big-endian integers. `LP(s)` means `U32(byte length of s) || UTF-8(s)`. `\0` means one zero byte. IDs and nonce are encoded as their textual strings; **payload bytes are decoded before signing**. JSON whitespace, object order and payload base64 presentation do not participate in the signature.

```text
signed_bytes = "DEMP/BODY/v2\0"
            || U32(body.version)
            || LP(body.source)
            || LP(body.target)
            || LP(body.nonce)
            || U64(body.created_at)
            || U64(body.expires_at)
            || U32(length(payload_raw_bytes)) || payload_raw_bytes

body.body_signature = base64url(Ed25519.Sign(sender.signing_sk, signed_bytes))

plaintext = UTF8(JSON(body_including_signature))
ciphertext = SealAnonymous(plaintext, recipient.encryption_pk)
envelope.body = base64url(ciphertext)

envelope_bytes = "DEMP/ENVELOPE/v2\0"
              || U32(envelope.version)
              || LP(envelope.target)
              || U64(envelope.expires_at)
              || LP(envelope.body)

envelope.messageID = base64url(SHA256(envelope_bytes))
```

Version 2 fixes the cryptographic suite to X25519 + XSalsa20-Poly1305 sealed boxes and Ed25519 signatures. Cryptographic/encoding changes require a new message version and domains. Signatures use the Weft-specific encoding above.

The implementation uses [Go's NaCl sealed-box API](https://pkg.go.dev/golang.org/x/crypto/nacl/box), compatible with [libsodium sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes). Each encryption uses a fresh ephemeral key and keeps the source's long-term public key inside the encrypted body. The enclosed Ed25519 signature authenticates the sender.

## Validation and limits

`ValidateEnvelope(now)` and `ParseMessage(data, now)` perform only relay-visible checks: supported version, valid target ID, canonical ciphertext encoding, size bounds, public expiry bounds, and correct envelope hash. The expiry must be positive, strictly later than `now`, and at most 24 hours plus 30 seconds ahead of `now`.

`OpenBody(recipient, now)` validates the envelope, checks the intended recipient, opens the sealed box, strictly parses the body, verifies its signature and signed lifetime, and compares signed/public header fields. It returns a zero body on any error. `Open` performs the same checks and returns only the verified payload.

Signed timestamps are positive Unix milliseconds. Inner expiry must follow creation by at most 24 hours; creation may be at most 30 seconds ahead of the recipient's clock. A message expires at `now >= expires_at`, without expiry grace. `NewMessage` accepts lifetimes from one second through 24 hours; `DefaultLifetime` is five minutes.

Payloads accept 0 through 65,536 arbitrary bytes. The payload field is required and must not be null; an empty payload is encoded as `""`. Signed-body JSON is capped at 97,280 bytes (95 KiB), and envelope JSON at 131,072 bytes (128 KiB). The constructor's maximum payload fits both caps despite the nested base64 encodings.

The envelope body, IDs, nonce, signature and hashes use canonical unpadded base64url. The inner JSON payload uses standard padded base64, matching Go's `[]byte` JSON representation; signatures cover its decoded bytes. Both JSON layers reject unknown fields, duplicate keys (including case aliases), invalid UTF-8, trailing JSON values and nesting beyond 16 levels. Go's decoder accepts case aliases for a single known field; emit the exact names shown above.

## Replay protection and metadata

The router deduplicates outer envelope IDs until their public expiry. All open/parse methods are stateless. For recipient application replay protection across re-encryption or restarts, use a successfully verified body's private content ID:

```text
contentID = base64url(SHA256("DEMP/CONTENT/v2\0"
                        || signed_bytes || LP(body.body_signature)))
```

`Body.ContentID()` uses that formula. Re-encrypting the same signed plaintext with fresh randomness produces a different envelope ID while preserving the content ID. Persist this private ID transactionally with application effects after successfully verifying the body. Keep it private to prevent relays from linking re-encrypted copies.

Encrypting source and signature keeps original-sender metadata inside the body. Target, expiry, envelope ID, size, timing and the immediate transport peer remain visible; identical ciphertext is linkable. The first-hop peer may infer the sender from the connection. Adapters preserve this separation by keeping the original sender's ID and signature inside the encrypted body.

## Proof of identity / possession

This separate exchange retains its v1 domains. Before granting privileges to an identity, establish an authenticated transport session, pin the expected verifier identity, and obtain a 32-byte session binding independently at both ends, such as a TLS exporter. A self-asserted peer ID or remote-supplied binding is insufficient. Keep this exchange inside that session; do not attach its identities or signatures to gossip messages.

1. The verifier generates a random 32-byte secret and seals it to the subject's encryption public key.
2. The verifier signs a challenge containing verifier ID, subject ID, session binding, expiry, and ciphertext. It retains the secret in local `PendingProof` state.
3. The subject verifies the issuer, session, signature, and expiry; decrypts the secret; and signs the response transcript with its signing private key.
4. The verifier checks the response against the retained secret, consumes the challenge once, and clears its secret buffer.

Exact encoding, with the same `LP` and `U64` definitions:

```text
challenge_bytes = "DEMP/POI-CHALLENGE/v1\0"
               || LP(verifier) || LP(subject) || LP(binding)
               || U64(expires_at) || LP(ciphertext)

challenge.signature = base64url(Ed25519.Sign(verifier.signing_sk, challenge_bytes))
challenge_id = base64url(SHA256(challenge_bytes))

response_bytes = "DEMP/POI-RESPONSE/v1\0" || LP(challenge_id)
              || U32(32) || secret_raw_bytes

proof = { challenge_id, signature: base64url(Ed25519.Sign(subject.signing_sk, response_bytes)) }
```

Challenges last one minute; the subject rejects expiry more than 90 seconds in the future. Expiry is strict at the verifier. A successful proof is single-use; invalid attempts do not consume it. The caller must limit pending challenges, expire abandoned state, and rate-limit attempts. Send only `Challenge` and `Proof`, never `PendingProof`. A network adapter should use `DecodeJSON` with a small cap (4 KiB suffices) for each proof frame.

This proves control of both private keys in the bound session. Replacing either public key changes the Weft ID.
