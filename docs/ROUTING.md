# Weft forwarding design

## Overview

The implementation uses direct delivery when a verified recipient connection is available and bounded gossip through connected peers otherwise. The [custom Weft TCP transport](TRANSPORT.md) supplies authenticated connections and the node runtime executes this router's send/receive actions. The CLI supports [automatic IPv4 router port mapping](../README.md#automatic-router-port-mapping).

| Approach | Strength | Tradeoff |
| --- | --- | --- |
| Flood to every neighbor | Simple initial prototype | Repeated ciphertext transfer; broad metadata exposure |
| Fixed random fanout only | Small immediate send count | Can miss whole branches without repair |
| GossipSub mesh + inventory repair | Maintained propagation mesh and recovery | Topic members still participate in topic-wide distribution |
| Direct / routed unicast | Efficient for one-to-one messages | Requires discovery, NAT handling and route verification |
| Direct first + scoped gossip fallback | Useful path from prototype to larger network | Needs explicit routing, privacy and abuse policies |

[GossipSub v1.0](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md) describes its mesh and gossip mechanisms. [Version 1.1](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md) adds attack-resilience mechanisms such as peer scoring. Weft uses its own eager/lazy dissemination algorithm, described below.

## Routing algorithm

The router accepts a set of authenticated, connected peer IDs from an adapter. The adapter supplies the immediate-peer identity; the original sender in `body.source` is encrypted. `Publish` injects an opaque envelope, and local callers enforce their publishing policy.

For new `DATA`:

1. Apply peer admission/rate checks and call `ValidateEnvelope` to check version, target, ciphertext bounds, public expiry bounds and the envelope content hash.
2. Ignore an already cached envelope.
3. Store the envelope until its public expiry if capacity permits. Return backpressure when full instead of evicting live IDs and reopening the duplicate window.
4. If this node is the recipient, emit one opaque-envelope delivery event and stop forwarding. The application decrypts and authenticates it with `OpenBody` or `Open` before acting on it.
5. If the recipient is a connected peer other than the previous hop, send directly to it.
6. Otherwise shuffle eligible peers using cryptographic randomness, push `DATA` to up to three, and advertise `IHAVE` to up to three additional peers. Exclude the previous hop.

On a caller-driven heartbeat (suggested every second), advertise a rotating batch of up to 64 cached IDs to up to three random peers. For messages whose target is connected, advertise only to that target. Never advertise messages received for this node. Multiple direct targets may therefore produce more than three heartbeat transmissions, bounded by the configured peer limit.

`IHAVE` requests missing IDs via `IWANT`. An `IWANT` reply contains at most one cached message, reducing amplification; later inventories request the remaining missing data. Entries expire at their public expiry.

Repeated eager/lazy propagation can distribute a message throughout a connected component. Envelope-ID deduplication terminates initial full-message forwarding through cycles; periodic advertisements continue until expiry. Envelopes are retained in memory until expiry, with public expiry capped at 24 hours plus clock skew ahead of receipt. The recipient checks that expiry against the signed copy when opening the body.

```text
DATA   { "kind": "DATA",  "message": <public envelope with encrypted signed body> }
IHAVE  { "kind": "IHAVE", "ids": [<messageID>, ...] }
IWANT  { "kind": "IWANT", "ids": [<messageID>, ...] }
```

Defaults: three eager peers, three lazy peers, 64 connected peers, 1,024 cached messages, 8 MiB of serialized message bytes, and 120 accepted frames per peer per one-minute window. Cache accounting excludes Go object/map overhead. Invalid frames consume the peer's allowance too. Inventories contain unique canonical IDs and at most 64 entries. Packet JSON is capped at `MaxPacketBytes`; the transport must cap frames **before** allocating their buffers.

The per-peer limit includes both data and control traffic.

## Adapter contract

- Authenticate a connection and bind its transport peer identity to the advertised Weft ID; use the proof API when both-key possession is required.
- Call `SetPeers` only with admitted peers. Never trust an incoming frame's claimed source as the immediate peer.
- Decode bounded frames with `DecodePacket`, then call `Handle(authenticatedPeer, packet, now)`.
- Execute returned transmissions and call `Gossip` periodically. The adapter owns sockets and timers.
- Decrypt and authenticate delivery events with `Message.OpenBody`; check the returned source against application authorization policy. Persist the verified body's `ContentID()` transactionally with application effects for replay suppression across re-encryption or restarts. Keep this content ID private.
- Enforce connection limits, byte budgets, deadlines, backoff and admission rules outside this state machine.

`node.Node` now implements this adapter using `transport.Session`: mutual TLS 1.3 identity verification, TLS-bound proof of both keys, framed TCP packets, bounded queues, read/write deadlines, keepalive, disconnect cleanup, automatic gossip and private content-ID deduplication. The CLI maintains configured pinned peers with reconnect backoff. The router itself remains usable independently for simulations and other adapters.

Returned outbound sends describe transmissions for the adapter to execute. Once cached, retransmission uses gossip; calling `Publish` again returns a duplicate. Changes made by `SetPeers` take effect at the next routing action or heartbeat. The node removes peers on socket failures, read/write timeouts or queue overflow, so subsequent gossip can use other peers.
