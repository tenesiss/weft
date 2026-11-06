# Weft TCP transport v1

The current transport retains its exact wire identifiers: the `DEMP` frame magic, `demp/1` ALPN, `demp:` certificate URI scheme and `EXPORTER-DEMP-POI-v1` exporter label. Key files likewise retain the `DEMP/KEYFILE/v1\0` domain and the CLI reads `DEMP_KEY_PASSWORD`. These are implementation constants, independent of the Weft project name.

The implementation uses **custom Weft frames over TCP secured by TLS 1.3**. The separate router-mapping control plane uses UDP for PCP/NAT-PMP and HTTP/SOAP for UPnP. TLS supplies the reviewed connection cryptography; Weft supplies peer identity, the both-key proof exchange, packet framing, and routing. Transport version 1 carries message version 2.

## Trust and connection setup

1. Dial a configured TCP address. Outbound calls require the complete expected Weft ID; addresses never establish identity by themselves.
2. Negotiate TLS 1.3 with ALPN `demp/1`. Both sides present an Ed25519 self-signed certificate containing exactly one `demp:<encryption_pk.signing_pk>` URI. The certificate public key must equal the ID's signing key, its signature must verify, and its validity and key usages must be acceptable.
3. The dialer checks its explicit identity pin. The listener checks its configured inbound identity allowlist; the default admits nobody. `AllowUnknownPeers` / `-allow any` (also `-allow-unknown`) admits any identity that proves both private keys, with certificate validation, mutual proofs, outbound pins, message validation, and resource limits enforced.
4. Derive a 32-byte session binding with `ExportKeyingMaterial("EXPORTER-DEMP-POI-v1", "demp/1", 32)`.
5. Perform the mutual POI exchange below inside TLS. Only after both signing and encryption keys have been proven can either side exchange routing packets.

The client configuration sets `InsecureSkipVerify` to replace hostname/public-CA verification with mandatory Weft self-certificate validation and exact identity pinning in `VerifyConnection`. The server requires a client certificate and runs the same certificate validation plus its allowlist. TLS resumption/session tickets are disabled so every connection runs the full authentication exchange.

Certificates are generated in memory for 24 hours and automatically refreshed for new connections when less than an hour remains. Existing sessions remain authenticated. No public CA, DNS name, certificate file, or Internet service is needed.

References: [Go TLS verification callbacks and exporter API](https://pkg.go.dev/crypto/tls), [TLS 1.3 specification](https://www.rfc-editor.org/rfc/rfc8446).

## Mutual proof exchange

TLS proves ownership of each certificate's signing key. Weft then proves possession of the identity's encryption key as well, using the [existing POI transcript](PROTOCOL.md#proof-of-identity--possession) and the TLS exporter binding:

```text
Dialer                                      Listener
  CHALLENGE (for listener) -------------------->
                          <-------------------- PROOF
                          <-------------------- CHALLENGE (for dialer)
  PROOF -------------------------------------->
                          <-------------------- READY
  PACKET / PING / PONG <----------------------> PACKET / PING / PONG
```

Each challenge contains the expected verifier and subject IDs, a sealed random secret, expiry, and the session binding; it is signed by the verifier. Responses prove decryption and signing. A proof captured from another connection fails because the challenge and exporter differ. Unexpected frame order, failed signatures, wrong identities, wrong bindings, expiry, missing completion, or a timeout closes the socket. Routing data sent before this exchange completes is rejected.

Authentication frames contain immediate-peer identities and stay within that peer's encrypted TLS connection. They are never attached to forwarded message envelopes. Relays preserve the v2 encrypted body unchanged.

## Binary framing

Every Weft frame is inside TLS and has a 12-byte header:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII `DEMP` |
| 4 | 1 | Transport version `1` |
| 5 | 1 | Frame type |
| 6 | 2 | Reserved, must be zero |
| 8 | 4 | Unsigned big-endian payload byte length |
| 12 | length | Payload bytes |

| Type | Value | Payload / maximum |
| --- | --- | --- |
| CHALLENGE | 1 | Strict JSON `protocol.Challenge`, 4,096 bytes |
| PROOF | 2 | Strict JSON `protocol.Proof`, 1,024 bytes |
| READY | 3 | Empty |
| PACKET | 16 | Strict JSON `routing.Packet`, 132,096 bytes |
| PING | 17 | Empty |
| PONG | 18 | Empty |

JSON data frames must be nonempty. Unknown types, nonzero reserved flags, unsupported versions, excessive lengths and truncated frames are rejected. The length is checked before allocating the payload. Reads use `io.ReadFull`, so TCP fragmentation and coalescing cannot alter message boundaries. Writes handle short writes and are serialized so concurrent callers cannot interleave frames.

After authentication, only PACKET/PING/PONG are valid. A PING receives one PONG; PONG does not produce another response. PACKET carries the existing DATA/IHAVE/IWANT protocol.

## Limits and lifecycle

Default node limits:

| Resource | Default |
| --- | --- |
| Complete TLS + POI handshake | 10 seconds |
| One complete frame read | 45 seconds |
| One frame write | 5 seconds |
| Keepalive ping interval | 10 seconds |
| Concurrent dials / inbound handshakes | 8 |
| Connected authenticated peers | 64 |
| Queued outgoing routing packets per peer | 8 |
| Buffered authenticated application deliveries | 32 |
| All incoming Weft frames per connection | 240 per one-minute window |
| Routing DATA/IHAVE/IWANT per peer | 120 per one-minute window |
| Router cache | 1,024 envelopes / 8 MiB serialized bytes |
| Recipient replay cache | 1,024 private content IDs |

Control frames count against the transport budget. Deadlines cover a whole frame, preventing a partial frame from holding a reader indefinitely. Full outgoing queues disconnect slow peers rather than growing memory. A disconnected peer is removed from the router, allowing cached messages to use remaining gossip routes. Application delivery uses bounded backpressure; shutdown/cancellation can discard a pending delivery.

The node starts its own gossip timer. Simultaneous connections converge on the connection initiated by the lexicographically smaller identity. Closing a node cancels dials and pending handshakes, closes sockets, waits for its workers, and closes delivery/error channels. The CLI maintains both startup `-peer` connections and runtime `connect:{"id":"ID","ip":"host:port"}` endpoints using exponential retry delays capped at 30 seconds plus up to 50% jitter. It keeps at most one retry worker per configured identity and bounds configured endpoints by the node's peer limit.

`node.Disconnect` removes a current session from routing and closes it. Library callers must cancel and wait for their outstanding dials/retry workers first. The CLI's `disconnect:{"id":"ID"}` command performs that cancellation and wait before closing the session, so a late outbound handshake cannot undo the command. Allowed peers can reconnect, and cached envelopes remain available for forwarding. Runtime `connect` leaves the inbound admission policy unchanged; startup `-peer` entries continue to be allowed inbound. See [runtime commands](../README.md#runtime-commands) for the complete local CLI interface.

Reconnection resets per-connection limits. Diagnostic errors use a bounded, best-effort channel.

## Application delivery

`node.Node` wires `Router.Publish`, `Router.Handle`, and `Router.Gossip` to authenticated sessions. A transport peer identity comes from the certificate and proof, never a packet's claimed original source.

When an envelope targets this node, it is decrypted with `OpenBody`, its signature and public/signed header agreement are checked, and its private `ContentID()` is deduplicated until the signed expiry. Only then is a `node.Delivery` emitted. The application must still decide whether that authenticated original sender is authorized.

`Publish` returning nil means local router acceptance. The CLI defaults to `0.0.0.0:9000` and `-nat auto`, maintaining an IPv4 TCP mapping through PCP, NAT-PMP or UPnP. NAT work runs independently of peer connections, publishes `nat` events, and is included in runtime `status`. Cleanup runs after cancellation with a separate timeout. See [automatic router port mapping](../README.md#automatic-router-port-mapping) for configuration and lifecycle. Library `node.DefaultConfig()` uses a loopback listener; the CLI manages router mapping.

## Persistent identities

The CLI uses encrypted key files. The v1 file stores `version`, a random 16-byte `salt`, a random 12-byte `nonce`, and an 80-byte `ciphertext` as JSON. Byte fields use standard padded base64. The plaintext is the 32-byte X25519 secret followed by the 32-byte Ed25519 seed.

The encryption key is derived with scrypt (`N=32768`, `r=8`, `p=1`, 32-byte result), then AES-256-GCM encrypts the 64-byte secret with associated data `DEMP/KEYFILE/v1\0`. Parameters are fixed and parsing is capped at 4 KiB before derivation. A password must have at least 12 bytes; use a long, high-entropy passphrase. Existing key files are never overwritten. Unix mode 0600 is requested; Windows protection also depends on the password and directory ACLs.

The CLI reads `DEMP_KEY_PASSWORD`, removes it from its own process environment, and clears its byte buffer after use. The calling shell retains its copy until it is cleared or the shell exits.
