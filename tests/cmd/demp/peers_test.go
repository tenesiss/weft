package main

import (
	"context"
	"net"
	"testing"
	"time"

	"demp/node"
)

func TestPeerManagerCancelsPendingDial(t *testing.T) {
	id := testIdentity(t)
	n, err := node.New(id, node.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// A server that never finishes TLS lets us disconnect during authentication.
	accepted := make(chan net.Conn, 1)
	go func() {
		raw, _ := listener.Accept()
		accepted <- raw
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m := newPeerManager(ctx, n, 1, func(ctx context.Context, _ any) { <-ctx.Done() })
	defer m.Close()
	endpoint := peerEndpoint{ID: testIdentity(t).ID(), Address: listener.Addr().String()}
	if err := m.Connect(endpoint); err != nil {
		t.Fatal(err)
	}
	worker := m.peers[endpoint.ID]
	if err := m.Connect(endpoint); err != nil || m.peers[endpoint.ID] != worker {
		t.Fatal("repeated connect created another worker", err)
	}
	changed := endpoint
	changed.Address = "localhost:1234"
	if err := m.Connect(changed); err == nil {
		t.Fatal("silently replaced the pinned endpoint")
	}
	if err := m.Connect(peerEndpoint{ID: testIdentity(t).ID(), Address: endpoint.Address}); err == nil {
		t.Fatal("configured peer limit not enforced")
	}
	if err := m.Connect(peerEndpoint{ID: id.ID(), Address: endpoint.Address}); err == nil {
		t.Fatal("self connect accepted")
	}
	select {
	case raw := <-accepted:
		if raw == nil {
			t.Fatal("accept failed")
		}
		defer raw.Close()
	case <-ctx.Done():
		t.Fatal("dial never started")
	}
	disconnected := make(chan error, 1)
	go func() { disconnected <- m.Disconnect(endpoint.ID) }()
	select {
	case err := <-disconnected:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("disconnect did not cancel the handshake promptly")
	}
	select {
	case <-worker.done:
	default:
		t.Fatal("retry worker still running after disconnect")
	}
	if len(m.Endpoints()) != 0 || len(n.Peers()) != 0 {
		t.Fatal("disconnect retained peer state")
	}
	if err := m.Disconnect(endpoint.ID); err != nil {
		t.Fatal("disconnect is not idempotent", err)
	}
	m.Close()
	if err := m.Connect(endpoint); err != node.ErrClosed {
		t.Fatal("closed manager accepted a peer", err)
	}
}

func TestDisconnectUnblocksPendingEvent(t *testing.T) {
	n, err := node.New(testIdentity(t), node.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	emitting := make(chan struct{})
	m := newPeerManager(ctx, n, 1, func(ctx context.Context, _ any) {
		close(emitting)
		<-ctx.Done() // Simulate a full CLI output queue.
	})
	defer m.Close()
	// Dial our own listener under a different pin; authentication must fail.
	endpoint := peerEndpoint{ID: testIdentity(t).ID(), Address: n.Address()}
	if err := m.Connect(endpoint); err != nil {
		t.Fatal(err)
	}
	select {
	case <-emitting:
	case <-ctx.Done():
		t.Fatal("connection failure was not reported")
	}
	done := make(chan error, 1)
	go func() { done <- m.Disconnect(endpoint.ID) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("full event queue blocked disconnect")
	}
}
