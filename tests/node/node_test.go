package node

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"demp/protocol"
)

func identity(t *testing.T) *protocol.Identity {
	t.Helper()
	id, err := protocol.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func start(t *testing.T, id *protocol.Identity, allowed ...string) *Node {
	t.Helper()
	cfg := DefaultConfig()
	cfg.GossipInterval = 100 * time.Millisecond
	cfg.Transport.AllowedPeers = allowed
	n, err := New(id, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func waitPeers(t *testing.T, n *Node, count int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(n.Peers()) == count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("peer count = %d, want %d", len(n.Peers()), count)
}

func TestRealTCPMultiHopDelivery(t *testing.T) {
	a, b, c := identity(t), identity(t), identity(t)
	alice := start(t, a, b.ID())
	relay := start(t, b, a.ID(), c.ID())
	bob := start(t, c, b.ID())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := alice.Connect(ctx, relay.Address(), relay.ID()); err != nil {
		t.Fatal(err)
	}
	if err := bob.Connect(ctx, relay.Address(), relay.ID()); err != nil {
		t.Fatal(err)
	}
	waitPeers(t, relay, 2)
	m, err := protocol.NewMessage(a, c.ID(), []byte("over real TCP relays"), time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Publish(ctx, m); err != nil {
		t.Fatal(err)
	}
	select {
	case delivery := <-bob.Deliveries():
		if delivery.Body.Source != a.ID() || string(delivery.Body.Payload) != "over real TCP relays" {
			t.Fatal("incorrect delivery")
		}
	case <-ctx.Done():
		t.Fatal("delivery timed out")
	}
	select {
	case <-relay.Deliveries():
		t.Fatal("relay got application plaintext")
	default:
	}
	if err := alice.Publish(ctx, m); err != nil {
		t.Fatal(err)
	}
	select {
	case <-bob.Deliveries():
		t.Fatal("duplicate delivered")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestGossipDeliversAfterPeerConnects(t *testing.T) {
	a, b := identity(t), identity(t)
	alice := start(t, a, b.ID())
	bob := start(t, b, a.ID())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := protocol.NewMessage(a, b.ID(), []byte("cached before connection"), time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Publish(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := alice.Connect(ctx, bob.Address(), bob.ID()); err != nil {
		t.Fatal(err)
	}
	select {
	case delivery := <-bob.Deliveries():
		if string(delivery.Body.Payload) != "cached before connection" {
			t.Fatal("wrong content")
		}
	case <-ctx.Done():
		t.Fatal("gossip did not recover cached envelope")
	}
}

func TestPeerRemovalAndConcurrentClose(t *testing.T) {
	a, b := identity(t), identity(t)
	alice := start(t, a, b.ID())
	bob := start(t, b, a.ID())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := alice.Connect(ctx, bob.Address(), bob.ID()); err != nil {
		t.Fatal(err)
	}
	waitPeers(t, bob, 1)
	bob.Close()
	waitPeers(t, alice, 0)
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() { alice.Close() })
	}
	wg.Wait()
	if err := alice.Connect(ctx, bob.Address(), bob.ID()); err != ErrClosed {
		t.Fatal("closed node accepted operation", err)
	}
}

func TestDisconnectRemovesSessionAndAllowsReconnect(t *testing.T) {
	a, b := identity(t), identity(t)
	alice := start(t, a, b.ID())
	bob := start(t, b, a.ID())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := alice.Connect(ctx, bob.Address(), bob.ID()); err != nil {
		t.Fatal(err)
	}
	waitPeers(t, bob, 1)
	if err := alice.Disconnect(b.ID()); err != nil {
		t.Fatal(err)
	}
	if len(alice.Peers()) != 0 {
		t.Fatal("disconnected peer still registered")
	}
	waitPeers(t, bob, 0)
	if err := alice.Disconnect(b.ID()); err != nil {
		t.Fatal("disconnect is not idempotent", err)
	}
	if err := alice.Disconnect("invalid"); err == nil {
		t.Fatal("invalid identity accepted")
	}
	// Cached messages can still reach the peer after an explicit reconnect.
	m, err := protocol.NewMessage(a, b.ID(), []byte("after disconnect"), time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Publish(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := alice.Connect(ctx, bob.Address(), bob.ID()); err != nil {
		t.Fatal(err)
	}
	select {
	case delivery := <-bob.Deliveries():
		if string(delivery.Body.Payload) != "after disconnect" {
			t.Fatal("wrong delivery")
		}
	case <-ctx.Done():
		t.Fatal("reconnected peer could not receive cached message")
	}
	alice.Close()
	if err := alice.Disconnect(b.ID()); err != ErrClosed {
		t.Fatal("closed node accepted disconnect", err)
	}
}

func TestSimultaneousDialConverges(t *testing.T) {
	a, b := identity(t), identity(t)
	alice := start(t, a, b.ID())
	bob := start(t, b, a.ID())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := alice.Connect(ctx, bob.Address(), bob.ID()); err != nil {
			t.Error(err)
		}
	})
	wg.Go(func() {
		if err := bob.Connect(ctx, alice.Address(), alice.ID()); err != nil {
			t.Error(err)
		}
	})
	wg.Wait()
	waitPeers(t, alice, 1)
	waitPeers(t, bob, 1)
	m, err := protocol.NewMessage(a, b.ID(), []byte("simultaneous dial"), time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Publish(ctx, m); err != nil {
		t.Fatal(err)
	}
	select {
	case <-bob.Deliveries():
	case <-ctx.Done():
		t.Fatal("duplicate connection resolution lost both sockets")
	}
}

func TestCloseCancelsPendingHandshake(t *testing.T) {
	id := identity(t)
	n := start(t, id)
	raw, err := net.Dial("tcp", n.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		n.mu.Lock()
		pending := n.pending
		n.mu.Unlock()
		if pending > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan struct{})
	go func() { n.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown left handshake blocked")
	}
}

func TestInvalidRecipientBodyNeverDelivered(t *testing.T) {
	a, b := identity(t), identity(t)
	alice := start(t, a, b.ID())
	bob := start(t, b, a.ID())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := alice.Connect(ctx, bob.Address(), bob.ID()); err != nil {
		t.Fatal(err)
	}
	m, err := protocol.NewMessage(a, b.ID(), []byte("protected"), time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// An altered envelope with a stale hash is rejected before sending.
	m.ExpiresAt++
	if err := alice.Publish(ctx, m); err == nil {
		t.Fatal("invalid envelope published")
	}
	select {
	case <-bob.Deliveries():
		t.Fatal("invalid body delivered")
	default:
	}
}

func TestCloseUnblocksDeliveryBackpressure(t *testing.T) {
	id := identity(t)
	cfg := DefaultConfig()
	cfg.DeliveryQueue = 1
	n, err := New(id, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	first, err := protocol.NewMessage(id, id.ID(), []byte("first"), time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := protocol.NewMessage(id, id.ID(), []byte("second"), time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Publish(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- n.Publish(context.Background(), second) }()
	done := make(chan struct{})
	go func() { n.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("backpressure prevented shutdown")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked delivery unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("publish stayed blocked")
	}
}
