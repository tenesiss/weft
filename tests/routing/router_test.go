package routing

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"demp/protocol"
)

var now = time.Unix(1800000000, 0)

func newIdentity(t testing.TB) *protocol.Identity {
	t.Helper()
	i, err := protocol.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func newRouter(t testing.TB, identity *protocol.Identity, peers ...string) *Router {
	t.Helper()
	r, err := New(identity.ID(), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetPeers(peers); err != nil {
		t.Fatal(err)
	}
	return r
}

func newMessage(t testing.TB, a, b *protocol.Identity, text string) protocol.Message {
	t.Helper()
	m, err := protocol.NewMessage(a, b.ID(), []byte(text), now, protocol.DefaultLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDirectFirst(t *testing.T) {
	a, b, c := newIdentity(t), newIdentity(t), newIdentity(t)
	r := newRouter(t, a, b.ID(), c.ID())
	result, err := r.Publish(newMessage(t, a, b, "direct"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outbound) != 1 || result.Outbound[0].Peer != b.ID() || result.Outbound[0].Packet.Kind != Data {
		t.Fatal("did not prefer recipient", result)
	}
	heartbeat, err := r.Gossip(now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(heartbeat) != 1 || heartbeat[0].Peer != b.ID() {
		t.Fatal("direct message advertised to unrelated peers")
	}
}

func TestPublishCannotInspectEncryptedAuthor(t *testing.T) {
	a, b, c := newIdentity(t), newIdentity(t), newIdentity(t)
	r := newRouter(t, a, b.ID())
	message := newMessage(t, c, b, "opaque origin")
	result, err := r.Publish(message, now)
	if err != nil || len(result.Outbound) != 1 {
		t.Fatal("opaque publish failed", err)
	}
	body, err := result.Outbound[0].Packet.Message.OpenBody(b, now)
	if err != nil || body.Source != c.ID() {
		t.Fatal("forwarding changed the authenticated source", err)
	}
}

type queued struct {
	from         string
	transmission Transmission
}

func drain(t *testing.T, routers map[string]*Router, queue []queued, at time.Time) []protocol.Message {
	t.Helper()
	var delivered []protocol.Message
	for steps := 0; len(queue) > 0; steps++ {
		if steps > 500 {
			t.Fatal("forwarding failed to converge")
		}
		item := queue[0]
		queue = queue[1:]
		wire, err := item.transmission.Packet.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		packet, err := DecodePacket(wire)
		if err != nil {
			t.Fatal(err)
		}
		result, err := routers[item.transmission.Peer].Handle(item.from, packet, at)
		if err != nil {
			t.Fatal(err)
		}
		if result.Delivered != nil {
			delivered = append(delivered, *result.Delivered)
		}
		for _, out := range result.Outbound {
			queue = append(queue, queued{from: item.transmission.Peer, transmission: out})
		}
	}
	return delivered
}

func TestMultiHopGossipRepairsLoss(t *testing.T) {
	a, b, c, d := newIdentity(t), newIdentity(t), newIdentity(t), newIdentity(t)
	ra := newRouter(t, a, b.ID())
	rb := newRouter(t, b, a.ID(), c.ID())
	rc := newRouter(t, c, b.ID(), d.ID())
	rd := newRouter(t, d, c.ID())
	routers := map[string]*Router{a.ID(): ra, b.ID(): rb, c.ID(): rc, d.ID(): rd}
	m := newMessage(t, a, d, "cross the relay chain")
	result, err := ra.Publish(m, now)
	if err != nil {
		t.Fatal(err)
	}
	relayed, err := rb.Handle(a.ID(), result.Outbound[0].Packet, now)
	if err != nil || len(relayed.Outbound) != 1 {
		t.Fatal("relay failed", err)
	}
	// Drop B -> C DATA. The next heartbeat must retrieve it through IHAVE/IWANT.
	heartbeat, err := rb.Gossip(now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var queue []queued
	for _, out := range heartbeat {
		queue = append(queue, queued{from: b.ID(), transmission: out})
	}
	delivered := drain(t, routers, queue, now.Add(time.Second))
	if len(delivered) != 1 {
		t.Fatalf("expected one recovered message, got %d", len(delivered))
	}
	plaintext, err := delivered[0].Open(d, now.Add(time.Second))
	if err != nil || string(plaintext) != "cross the relay chain" {
		t.Fatal("recovered payload failed", err)
	}
	if _, err := delivered[0].Open(b, now); err == nil {
		t.Fatal("relay decrypted payload")
	}
	// Repeated sends and subsequent gossip must not deliver again.
	result, err = rd.Handle(c.ID(), Packet{Kind: Data, Message: &m}, now.Add(2*time.Second))
	if err != nil || !result.Duplicate || result.Delivered != nil {
		t.Fatal("duplicate delivered", err)
	}
}

func TestCycleAndFanoutBounds(t *testing.T) {
	a, b, c, d, e := newIdentity(t), newIdentity(t), newIdentity(t), newIdentity(t), newIdentity(t)
	config := DefaultConfig()
	config.Fanout = 1
	config.LazyFanout = 1
	r, err := New(a.ID(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetPeers([]string{b.ID(), c.ID(), d.ID()}); err != nil {
		t.Fatal(err)
	}
	result, err := r.Publish(newMessage(t, a, e, "bounded"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outbound) != 2 || result.Outbound[0].Packet.Kind != Data || result.Outbound[1].Packet.Kind != IHave {
		t.Fatal("fanout bounds violated")
	}
	// Full triangle: duplicates should terminate the broadcast even with no path
	// to the recipient, without requiring an attacker-editable hop counter.
	ra := newRouter(t, a, b.ID(), c.ID())
	rb := newRouter(t, b, a.ID(), c.ID())
	rc := newRouter(t, c, a.ID(), b.ID())
	result, err = ra.Publish(newMessage(t, a, e, "cycle"), now)
	if err != nil {
		t.Fatal(err)
	}
	var queue []queued
	for _, out := range result.Outbound {
		queue = append(queue, queued{from: a.ID(), transmission: out})
	}
	if delivered := drain(t, map[string]*Router{a.ID(): ra, b.ID(): rb, c.ID(): rc}, queue, now); len(delivered) != 0 {
		t.Fatal("wrong recipient delivered")
	}
}

func TestCapacityRetainsReplayProtection(t *testing.T) {
	a, b := newIdentity(t), newIdentity(t)
	config := DefaultConfig()
	config.MaxMessages = 1
	r, err := New(b.ID(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetPeers([]string{a.ID()}); err != nil {
		t.Fatal(err)
	}
	m := newMessage(t, a, b, "first")
	if _, err := r.Handle(a.ID(), Packet{Kind: Data, Message: &m}, now); err != nil {
		t.Fatal(err)
	}
	second := newMessage(t, a, b, "second")
	if _, err := r.Handle(a.ID(), Packet{Kind: Data, Message: &second}, now); !errors.Is(err, ErrCapacity) {
		t.Fatal("expected backpressure", err)
	}
	result, err := r.Handle(a.ID(), Packet{Kind: Data, Message: &m}, now)
	if err != nil || !result.Duplicate {
		t.Fatal("cache eviction permitted replay", err)
	}
	// Once expired, entries can be removed; expired originals remain invalid.
	later := now.Add(protocol.DefaultLifetime)
	if _, err := r.Handle(a.ID(), Packet{Kind: Data, Message: &m}, later); err == nil {
		t.Fatal("expired replay accepted")
	}
	fresh, err := protocol.NewMessage(a, b.ID(), []byte("fresh"), later, protocol.DefaultLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Handle(a.ID(), Packet{Kind: Data, Message: &fresh}, later); err != nil {
		t.Fatal(err)
	}
}

func TestPeerLimitsAndInvalidData(t *testing.T) {
	a, b, stranger := newIdentity(t), newIdentity(t), newIdentity(t)
	config := DefaultConfig()
	config.MaxFramesPerMinute = 2
	r, err := New(b.ID(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetPeers([]string{a.ID()}); err != nil {
		t.Fatal(err)
	}
	m := newMessage(t, a, b, "valid")
	if _, err := r.Handle(stranger.ID(), Packet{Kind: Data, Message: &m}, now); err == nil {
		t.Fatal("unknown peer accepted")
	}
	tampered := m
	tampered.ExpiresAt++
	if _, err := r.Handle(a.ID(), Packet{Kind: Data, Message: &tampered}, now); err == nil {
		t.Fatal("tampered data accepted")
	}
	result, err := r.Handle(a.ID(), Packet{Kind: Data, Message: &m}, now)
	if err != nil || result.Duplicate || result.Delivered == nil {
		t.Fatal("invalid message poisoned cache", err)
	}
	if _, err := r.Handle(a.ID(), Packet{Kind: Data, Message: &m}, now); !errors.Is(err, ErrRateLimited) {
		t.Fatal("rate limit not applied", err)
	}
}

func TestGossipRotationAndRequestAmplification(t *testing.T) {
	a, b := newIdentity(t), newIdentity(t)
	r := newRouter(t, a, b.ID())
	for i := range MaxBatch + 1 {
		if _, err := r.Publish(newMessage(t, a, b, fmt.Sprint(i)), now); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[string]bool)
	for range 2 {
		out, err := r.Gossip(now)
		if err != nil || len(out) != 1 {
			t.Fatal("gossip failed", err)
		}
		if len(out[0].Packet.IDs) > MaxBatch {
			t.Fatal("oversized inventory")
		}
		for _, id := range out[0].Packet.IDs {
			seen[id] = true
		}
		result, err := r.Handle(b.ID(), Packet{Kind: IWant, IDs: out[0].Packet.IDs}, now)
		if err != nil || len(result.Outbound) != 1 {
			t.Fatal("request amplification limit failed", err)
		}
	}
	if len(seen) != MaxBatch+1 {
		t.Fatal("cache entries starved")
	}
}

func TestConcurrentDuplicateDelivery(t *testing.T) {
	a, b := newIdentity(t), newIdentity(t)
	r := newRouter(t, b, a.ID())
	m := newMessage(t, a, b, "once")
	var wg sync.WaitGroup
	results := make(chan Result, 20)
	for range 20 {
		wg.Go(func() {
			result, err := r.Handle(a.ID(), Packet{Kind: Data, Message: &m}, now)
			if err != nil {
				t.Error(err)
			}
			results <- result
		})
	}
	wg.Wait()
	close(results)
	count := 0
	for result := range results {
		if result.Delivered != nil {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("delivered %d times", count)
	}
}

func FuzzDecodePacket(f *testing.F) {
	f.Add([]byte(`{"kind":"IHAVE","ids":[]}`))
	f.Add([]byte(`{"kind":"DATA","message":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		packet, err := DecodePacket(data)
		if err == nil {
			if err := packet.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	})
}
