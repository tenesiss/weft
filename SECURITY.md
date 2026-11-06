# Weft security

Weft combines end-to-end message encryption, recipient-side signature verification, and mutually authenticated transport connections.

## Security properties

- End-to-end encryption of the entire body, including source, payload, nonce, creation time and signature.
- Recipient-side Ed25519 authentication of every body field except the signature itself. The signed body is encrypted in full; the recipient checks that version, target and expiry match the public envelope before returning any plaintext.
- A public envelope content hash for relay deduplication, and a private `Body.ContentID()` for recipient-side deduplication across re-encryption. The encrypted Ed25519 signature authenticates the sender.
- Session-bound, one-use proof of possession of both private keys over mutually authenticated TLS.
- Implemented TCP transport with TLS 1.3, exact outbound identity pins, configurable inbound admission, mutual TLS-bound both-key proofs before routing, bounded binary framing, deadlines and connection limits.
- Password-encrypted identity files using fixed-cost scrypt and AES-256-GCM, with exclusive creation and bounded parsing.
- In-memory envelope duplicate suppression until public expiry, bounded cache admission, bounded gossip batches, and per-peer frame limits.

## Integration

The TLS client replaces Web PKI hostname/CA verification with mandatory self-certificate validation and exact Weft identity pinning in `VerifyConnection`. Keep that callback and require an explicit outbound identity pin. Listener admission rejects unlisted identities by default; open admission is opt-in. All incoming control and routing frames consume transport rate limits; reconnecting resets per-connection budgets.

Use `ParseMessage` / `DecodePacket` on bounded input. `ValidateEnvelope` checks the public envelope. Recipients decrypt the sealed body, verify its signature, and compare signed/public fields before exposing content; `OpenBody` and `Open` perform all those checks and return no plaintext on failure. Apply application authorization to the verified sender. Keep secret keys private and the POI transcript inside its authenticated transport session.

`node.Node` suppresses verified private content IDs in memory until signed expiry. Persist each verified `ContentID()` transactionally with application effects to preserve replay protection across restarts.

Sealed bodies are decrypted with the recipient's long-term private encryption key; possession of that key also permits decryption of recorded bodies. TLS 1.3 uses ephemeral session keys for transport connections. Protect identity files with a strong passphrase and appropriate directory permissions.
