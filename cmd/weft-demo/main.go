// weft-demo exercises four nodes through a lossy in-process transport.
package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"weft/protocol"
	"weft/routing"
)

type node struct {
	name     string
	identity *protocol.Identity
	router   *routing.Router
}
type hop struct {
	from string
	send routing.Transmission
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	now := time.Now()
	nodes := make([]node, 4)
	byID := make(map[string]*node)
	for i, name := range []string{"Alice", "Relay-1", "Relay-2", "Bob"} {
		identity, err := protocol.GenerateIdentity()
		if err != nil {
			return err
		}
		router, err := routing.New(identity.ID(), routing.DefaultConfig())
		if err != nil {
			return err
		}
		nodes[i] = node{name: name, identity: identity, router: router}
		byID[identity.ID()] = &nodes[i]
	}
	for i := range nodes {
		var peers []string
		if i > 0 {
			peers = append(peers, nodes[i-1].identity.ID())
		}
		if i < len(nodes)-1 {
			peers = append(peers, nodes[i+1].identity.ID())
		}
		if err := nodes[i].router.SetPeers(peers); err != nil {
			return err
		}
	}
	fmt.Printf("WEFT v%d: Alice <-> Relay-1 <-> Relay-2 <-> Bob (in-process)\n", protocol.Version)
	// Simulate the session binding that a real authenticated transport supplies.
	var binding [32]byte
	if _, err := rand.Read(binding[:]); err != nil {
		return err
	}
	challenge, pending, err := protocol.NewChallenge(nodes[0].identity, nodes[3].identity.ID(), binding, now)
	if err != nil {
		return err
	}
	proof, err := protocol.AnswerChallenge(nodes[3].identity, challenge, nodes[0].identity.ID(), binding, now)
	if err != nil {
		return err
	}
	if err := pending.Verify(proof, binding, now); err != nil {
		return err
	}
	fmt.Println("PoI: Bob proved possession of both private keys; replay rejected:", pending.Verify(proof, binding, now) != nil)
	message, err := protocol.NewMessage(nodes[0].identity, nodes[3].identity.ID(), []byte("Hello Bob. The relays cannot read this."), now, protocol.DefaultLifetime)
	if err != nil {
		return err
	}
	fmt.Println("Message ID:", message.MessageID)
	wire, err := message.Marshal()
	if err != nil {
		return err
	}
	if bytes.Contains(wire, []byte(nodes[0].identity.ID())) || bytes.Contains(wire, []byte(`"source"`)) || bytes.Contains(wire, []byte(`"body_signature"`)) {
		return fmt.Errorf("private body data leaked into envelope")
	}
	fmt.Println("Wire check: source and signature are inside the encrypted body")
	if _, err := message.Open(nodes[1].identity, now); err == nil {
		return fmt.Errorf("relay unexpectedly decrypted message")
	}
	result, err := nodes[0].router.Publish(message, now)
	if err != nil {
		return err
	}
	var queue []hop
	for _, send := range result.Outbound {
		queue = append(queue, hop{from: nodes[0].identity.ID(), send: send})
	}
	dropped, delivered := false, 0
	for tick := 0; tick < 5; tick++ {
		at := now.Add(time.Duration(tick) * time.Second)
		for steps := 0; len(queue) > 0; steps++ {
			if steps > 500 {
				return fmt.Errorf("forwarding failed to converge")
			}
			h := queue[0]
			queue = queue[1:]
			from, target := byID[h.from], byID[h.send.Peer]
			if !dropped && from.name == "Relay-1" && target.name == "Relay-2" && h.send.Packet.Kind == routing.Data {
				fmt.Println("Dropped Relay-1 -> Relay-2 DATA; waiting for gossip repair")
				dropped = true
				continue
			}
			wire, err := h.send.Packet.Marshal()
			if err != nil {
				return err
			}
			packet, err := routing.DecodePacket(wire)
			if err != nil {
				return err
			}
			fmt.Printf("  %s -> %s: %s\n", from.name, target.name, packet.Kind)
			result, err := target.router.Handle(h.from, packet, at)
			if err != nil {
				return err
			}
			if result.Delivered != nil {
				body, err := result.Delivered.OpenBody(target.identity, at)
				if err != nil {
					return err
				}
				if body.Source != nodes[0].identity.ID() {
					return fmt.Errorf("unexpected authenticated sender")
				}
				delivered++
				fmt.Printf("%s verified Alice and decrypted: %s\n", target.name, body.Payload)
			}
			for _, send := range result.Outbound {
				queue = append(queue, hop{from: h.send.Peer, send: send})
			}
		}
		if delivered == 1 {
			result, err := nodes[3].router.Handle(nodes[2].identity.ID(), routing.Packet{Kind: routing.Data, Message: &message}, at)
			if err != nil || !result.Duplicate {
				return fmt.Errorf("duplicate suppression failed: %v", err)
			}
			fmt.Println("Success: recovered dropped DATA, decrypted at Bob, suppressed duplicate.")
			return nil
		}
		for i := range nodes {
			sends, err := nodes[i].router.Gossip(at)
			if err != nil {
				return err
			}
			for _, send := range sends {
				queue = append(queue, hop{from: nodes[i].identity.ID(), send: send})
			}
		}
	}
	return fmt.Errorf("message was not delivered")
}
