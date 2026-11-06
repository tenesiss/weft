# Weft

**Weft** is a decentralized encrypted messaging protocol implemented in Go, with self-certifying node identities, end-to-end encrypted messages, proof of key ownership, and direct-first hybrid gossip routing.

```text
node ID = base64url(X25519 public key) + "." + base64url(Ed25519 public key)

Alice --> Relay-1 --> Relay-2 --> Bob
          ciphertext only       decrypt + verify
```

This repository implements the protocol, gossip router, and a **real TCP node** with automatic router port mapping. Peer traffic uses custom Weft frames over mutually authenticated TLS 1.3. Router port mapping uses a separate control connection. The original `demp-demo` remains an in-process packet-loss simulation; `cmd/demp` runs independent networked processes.

## Run

Requires Go 1.27 or later.

The examples build the CLI as `weft.exe`. The current source directories (`cmd/demp` and `cmd/demp-demo`), Go module/import paths (`demp/...`), password variable (`DEMP_KEY_PASSWORD`), and wire-format constants retain their implementation names; the commands and protocol specifications below use those exact identifiers.

```sh
go mod download
go test '-overlay=tests/overlay.json' ./...
go vet '-overlay=tests/overlay.json' ./...
go run ./cmd/demp-demo
go build -o bin/weft.exe ./cmd/demp
```

All tests live under `tests/`, mirroring the production package directories. Run the commands above from the repository root. The Go overlay compiles the tests with their original packages so they can still exercise private internals; include `-overlay=tests/overlay.json` for focused tests, coverage, race checks, and fuzzing as well. See [AGENTS.md](AGENTS.md) for the test-placement convention.

On Windows, if Go is installed but absent from `PATH`:

```powershell
& 'C:\Program Files\Go\bin\go.exe' test '-overlay=tests/overlay.json' ./...
& 'C:\Program Files\Go\bin\go.exe' run ./cmd/demp-demo
```

The demo proves ownership of Bob's two private keys, checks that Alice's source identity and signature are hidden on the wire, drops the first relay transmission, recovers it with `IHAVE`/`IWANT`, and lets Bob decrypt and authenticate the body.

## Run two networked nodes

The following PowerShell example creates two local test identities. Use a strong passphrase; each terminal must set `DEMP_KEY_PASSWORD` before loading its key. Go can also be invoked by its full Windows path shown above.

```powershell
go build -o bin/weft.exe ./cmd/demp
$env:DEMP_KEY_PASSWORD = Read-Host 'Key-file passphrase' -MaskInput
.\bin\weft.exe keygen -key alice.key.json
.\bin\weft.exe keygen -key bob.key.json
```

Each command prints its public Weft ID. Key files contain encrypted secrets and cannot be overwritten by `keygen`. This local example uses the same entered passphrase for both test identities.

Start Bob in one terminal:

```powershell
$env:DEMP_KEY_PASSWORD = Read-Host 'Key-file passphrase' -MaskInput
$alice = .\bin\weft.exe id -key alice.key.json
.\bin\weft.exe run -key bob.key.json -listen 127.0.0.1:9002 -allow $alice
```

Start Alice in another terminal:

```powershell
$env:DEMP_KEY_PASSWORD = Read-Host 'Key-file passphrase' -MaskInput
$bob = .\bin\weft.exe id -key bob.key.json
.\bin\weft.exe run -key alice.key.json -listen 127.0.0.1:9001 -peer "$bob@127.0.0.1:9002"
```

In Alice's running process, enter one command line with Bob's actual public ID:

```text
message:{"target":"PASTE_BOB_ID","text":"Hello over encrypted Weft TCP"}
```

Bob prints an authenticated `message` event with Alice's source ID and the decrypted text. Bob can reply by entering the same shape with Alice's ID. `queued` confirms local acceptance. Ctrl+C or `quit` shuts a node down. The CLI reconnects configured peers automatically; input EOF leaves it listening.

`-peer` is repeatable and pins each remote identity; those IDs are also allowed inbound. `-allow ID` admits additional inbound peers. By default, other identities are rejected. `-allow any` admits any peer that completes certificate validation and both-key authentication; identity pins, proofs, message validation, and resource limits still apply. The existing `-allow-unknown` flag remains an alias. The CLI defaults to `-listen 0.0.0.0:9000 -nat auto`; the explicit loopback addresses above keep these examples local.

For example, to let any authenticated peer connect to Bob:

```powershell
.\bin\weft.exe run -key bob.key.json -listen 127.0.0.1:9002 -allow any
```

## Automatic router port mapping

`weft run` defaults to `-nat auto`. It listens on `0.0.0.0:9000` and requests an IPv4 **TCP** port mapping in the background, trying PCP, NAT-PMP, then UPnP IGD (WANIPConnection v1/v2 and WANPPPConnection v1). The router must support and enable one of these protocols.

PCP and NAT-PMP use Weft's Go clients to send mapping requests to the gateway over UDP port 5351. UPnP uses SSDP discovery and HTTP/SOAP requests through `github.com/huin/goupnp`. The `github.com/jackpal/gateway` library finds gateways from the operating system's routing table. This is automatic port forwarding; the mapped port carries Weft's authenticated TCP connections.

```powershell
# Automatic mapping is enabled without an extra flag.
.\bin\weft.exe run -key bob.key.json -allow $alice

# Disable router mapping, or keep the node entirely local.
.\bin\weft.exe run -key bob.key.json -nat off -allow $alice
.\bin\weft.exe run -key bob.key.json -listen 127.0.0.1:9000 -allow $alice

# Connect outbound without opening a listener or requesting a mapping.
.\bin\weft.exe run -key alice.key.json -listen "" -peer "$bob@PUBLIC_IP:PORT"
```

`-nat` accepts only `auto` and `off`. `off` does not change the listen address. Loopback-only, outbound-only and specific IPv6 listeners skip IPv4 mapping. A wildcard listener uses the IPv4 address of the gateway's local interface; an explicit IPv4 bind is mapped only through a matching interface. `-listen 0.0.0.0:0` maps the actual port assigned by the OS.

JSON `nat` events report `discovering`, `mapped`, `unavailable`, `skipped`, or `off`. A successful event includes `protocol`, `external_address`, and, for a finite lease, `expires_at`. The router may assign a different external port. Share that **external address and port**, together with the node's Weft ID, with peers. For example (illustrative address):

```json
{"event":"nat","mode":"auto","state":"mapped","protocol":"PCP","external_address":"203.0.113.10:45678","expires_at":"2026-11-05T18:30:00Z"}
```

`status` includes the latest mapping information in its `nat` object. Mapping failure clears the reported external endpoint, leaves the TCP node and outbound connections running, and retries after one minute. Finite leases request 30 minutes and renew at half the granted lifetime or one minute, whichever is sooner. Renewal recreates rules lost after router restarts; failures trigger fresh gateway discovery. External endpoint changes emit a new event. UPnP port conflicts select another port instead of replacing an existing rule. Routers that allow only permanent UPnP leases are supported and checked every minute.

`quit` and Ctrl+C attempt to remove the mapping with a bounded cleanup timeout. Finite mappings eventually expire if the process crashes or cleanup fails; permanent-only UPnP mappings may require manual removal. Inbound identity admission still requires `-allow` or `-peer` authorization.

The `mapped` event reports the endpoint acknowledged by the router. A private or carrier-grade external address is reported with an upstream-NAT warning. For inbound connections, configure host firewalls and any upstream NAT to allow traffic to that endpoint. Configure reachable peers with `-peer` or `connect`; established connections support traffic in both directions.

If `nat` reports `unavailable`, read its `reason` for the attempted gateway and each protocol's result. PCP/NAT-PMP timeouts mean the gateway did not answer those requests. `UPnP: no compatible router discovered` means discovery found no usable mapping service. Check the router's UPnP/port-mapping setting and whether LAN multicast discovery is allowed. On Windows, application firewall rules must match the executable's current path, including after moving the project or rebuilding a desktop bundle. On networks where you cannot enable mapping, use a manually forwarded endpoint or an outbound connection to a reachable peer; `-nat off` disables the automatic attempts.

## Runtime commands

Enter one `command:JSON` line on the running node's standard input. Commands with no arguments also accept their bare name. These are local CLI commands; the network still uses authenticated binary Weft frames.

| Command | Effect |
| --- | --- |
| `connect:{"id":"PEER_ID","ip":"127.0.0.1:9002"}` | Add a pinned outbound peer and maintain its connection with automatic retries. |
| `message:{"target":"RECIPIENT_ID","text":"Hello"}` | Encrypt and queue a message for direct delivery or gossip routing. |
| `disconnect:{"id":"PEER_ID"}` | Stop this node's retries for that peer and close its current session, including peers configured with `-peer`. |
| `peers` or `peers:{}` | List connected peer IDs and configured outbound endpoints, including peers waiting to reconnect. |
| `status` or `status:{}` | Show this node's ID, listen address, connected peers, configured endpoints, and NAT mapping status. |
| `help` or `help:{}` | List command syntax. |
| `quit` or `quit:{}` | Cancel pending connections and shut down cleanly. |

The `ip` field requires a host and numeric TCP port. DNS names and bracketed IPv6 addresses work too, such as `localhost:9002` or `[::1]:9002`. Each outbound connection still requires the expected full Weft ID. Runtime `connect` does not change the inbound allowlist; the remote listener must authorize this node with `-allow ID`, `-peer`, or `-allow any`. Configure this node's inbound admission separately if the remote should initiate connections back to it.

`connect` returns a `peer_configured` event when the endpoint is registered, and a `connected` event after successful authentication. Repeating the same ID and address is idempotent. To change an address, disconnect that ID first. Configured outbound endpoints are bounded by the node's peer limit (64 by default); runtime changes last only until shutdown.

`disconnect` also works for an inbound-only connection and is idempotent when no session exists. An allowed remote can connect again. Cached messages remain available for delivery through other routes or after a later connection.

Output events are newline-delimited JSON on stdout; command and connection errors go to stderr. Unknown commands, malformed JSON, duplicate/unknown fields, invalid IDs, and invalid endpoints are rejected. Blank lines are ignored. The original bare `{"target":"RECIPIENT_ID","text":"Hello"}` message format remains supported.

See [the custom TCP transport](docs/TRANSPORT.md) for the wire header, authentication exchange and limits. The actual socket paths are `node.Connect` / `acceptLoop`, `transport.Session.Send`, and `transport.Session.Receive`.

## Features

- Independent X25519 encryption and Ed25519 signing keys.
- Recipient-only sealed-box encryption of the **entire body**, including source and signature, using Go's `golang.org/x/crypto/nacl/box` implementation.
- Signatures covering every body field except the signature itself, applied before encryption.
- Public envelope hashes for routing deduplication, recipient-verified signed expiry, strict JSON parsing, and size limits.
- One-use, session-bound proof of possession of both private keys.
- Real TCP exchanges with TLS 1.3, identity pins, mutual key proofs, binary framing, bounded queues, deadlines, heartbeats and connection cleanup.
- Password-encrypted identity files and a CLI for independent node processes.
- Automatic IPv4 TCP port mapping through PCP, NAT-PMP and UPnP, with lease renewal, retry, external endpoint reporting and shutdown cleanup.
- Direct-first delivery, bounded eager fanout, lazy inventory/request repair, peer rate limits, and bounded caches.
- Tampering, replay, impersonation, relay, packet-loss, concurrency, fuzz and simulated-router lifecycle tests.

## Library example

```go
alice, err := protocol.GenerateIdentity()
if err != nil { return err }
bob, err := protocol.GenerateIdentity()
if err != nil { return err }

now := time.Now()
message, err := protocol.NewMessage(
    alice, bob.ID(), []byte("Hello Bob"), now, protocol.DefaultLifetime,
)
if err != nil { return err }

// Relays check structure and the public hash, without learning the source.
if err := message.ValidateEnvelope(now); err != nil { return err }

// Only Bob can decrypt and authenticate the body before it is returned.
body, err := message.OpenBody(bob, now)
if err != nil { return err }
fmt.Println(body.Source, string(body.Payload))
// Use body.ContentID() privately for application-level replay suppression.
```

Imports: `demp/protocol`, `time`, and `fmt`. The local module name is `demp`; choose a repository module path before publishing it.

Version 2 changes `Message.Body` to a ciphertext string and moves `BodySignature` into the encrypted `Body`. The public envelope contains only `version`, `messageID`, `target`, `expires_at`, and `body`. Version 1 messages are rejected. Replace `Message.Verify` with `ValidateEnvelope` for relays and `OpenBody` for recipient authentication. `Open` remains available when only the verified payload is needed; the separate POI exchange stays at version 1.

## Forwarding

Weft implements **direct delivery first, bounded gossip as a fallback** over its authenticated TCP connections. Every node can relay encrypted envelopes through its connected peers. The `routing` package chooses transmissions, and `node.Node` sends them through the transport and runs the gossip timer. Relays inspect the public envelope but cannot decrypt the body or authenticate its encrypted sender signature.

For each locally published or received message:

1. **Validate and cache.** Check the envelope's format, size, public expiry and content hash. Ignore an already cached message ID. Cache new envelopes until expiry, rejecting new entries when capacity is full. Incoming packets also consume the authenticated peer's rate allowance.
2. **Deliver locally or directly.** If this node is the recipient, pass the envelope to the node runtime for decryption, signature verification and private content-ID deduplication before emitting a `message` event. Otherwise, if the recipient is a connected peer other than the previous hop, send the full envelope directly as `DATA`.
3. **Relay through gossip.** For a message addressed to another node without an eligible direct recipient connection, randomly select up to three peers to receive `DATA` and up to three additional peers to receive an `IHAVE` advertisement containing the message ID. Exclude the previous hop from this initial forwarding step.

An `IHAVE` recipient requests IDs missing from its cache with `IWANT`. Each `IWANT` response supplies at most one cached envelope as `DATA`, limiting amplification; later advertisements let the peer request remaining messages. Every second, the node advertises a rotating batch of up to 64 cached IDs to up to three random peers. IDs with a connected recipient are advertised only to that recipient, and messages addressed to the local node are excluded from these periodic advertisements. This repairs missed sends and makes cached messages available to newly connected peers.

The default limits are 64 connected peers, 1,024 cached envelopes, 8 MiB of serialized cache data and 120 incoming routing packets per peer per minute. Deduplication prevents repeated initial forwarding of the same cached envelope. Bounded fanout limits each node's immediate work; repeated gossip can still spread ciphertext throughout the connected network.

Peers are configured with `-peer` or `connect`. NAT mapping makes inbound connections possible on compatible networks, and the router uses its own eager/lazy gossip algorithm to forward messages through connected peers. See [the routing design](docs/ROUTING.md) for packet details and adapter behavior.

## Documentation

- [Wire protocol](docs/PROTOCOL.md)
- [Routing design](docs/ROUTING.md)
- [TCP transport](docs/TRANSPORT.md)
- [Security](SECURITY.md)
