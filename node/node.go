// Package node connects the DEMP router to real TCP peers and authenticated
// application deliveries. All queues, caches and connection counts are bounded.
package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"demp/protocol"
	"demp/routing"
	"demp/transport"
)

var ErrClosed = errors.New("node closed")

type Config struct {
	ListenAddress  string
	Router         routing.Config
	Transport      transport.Config
	MaxPending     int
	SendQueue      int
	DeliveryQueue  int
	GossipInterval time.Duration
	PingInterval   time.Duration
}

func DefaultConfig() Config {
	return Config{ListenAddress: "127.0.0.1:0", Router: routing.DefaultConfig(), Transport: transport.DefaultConfig(), MaxPending: 8, SendQueue: 8, DeliveryQueue: 32, GossipInterval: time.Second, PingInterval: 10 * time.Second}
}

type Delivery struct {
	MessageID string
	ContentID string
	Body      protocol.Body
}

type peer struct {
	session *transport.Session
	queue   chan routing.Packet
	done    chan struct{}
	once    sync.Once
}

func (p *peer) close() { p.once.Do(func() { close(p.done); p.session.Close() }) }

type Node struct {
	identity   *protocol.Identity
	config     Config
	auth       *transport.Authenticator
	router     *routing.Router
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	listener   net.Listener
	peers      map[string]*peer
	pending    int
	started    bool
	closed     bool
	wg         sync.WaitGroup
	closeOnce  sync.Once
	deliveries chan Delivery
	errors     chan error
	deliveryMu sync.Mutex
	delivered  map[string]int64
}

func New(identity *protocol.Identity, config Config) (*Node, error) {
	if config.MaxPending < 1 || config.MaxPending > 256 || config.SendQueue < 1 || config.SendQueue > 1024 || config.DeliveryQueue < 1 || config.DeliveryQueue > 1024 || config.GossipInterval <= 0 || config.PingInterval <= 0 || config.PingInterval >= config.Transport.ReadTimeout/2 {
		return nil, errors.New("invalid node limits or heartbeat interval")
	}
	auth, err := transport.NewAuthenticator(identity, config.Transport)
	if err != nil {
		return nil, err
	}
	router, err := routing.New(identity.ID(), config.Router)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Node{identity: identity, config: config, auth: auth, router: router, ctx: ctx, cancel: cancel, peers: make(map[string]*peer), deliveries: make(chan Delivery, config.DeliveryQueue), errors: make(chan error, 32), delivered: make(map[string]int64)}, nil
}

// Start listens on TCP. A blank ListenAddress creates an outbound-only node.
func (n *Node) Start() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return ErrClosed
	}
	if n.started {
		return errors.New("node already started")
	}
	if n.config.ListenAddress != "" {
		listener, err := net.Listen("tcp", n.config.ListenAddress)
		if err != nil {
			return err
		}
		n.listener = listener
		n.wg.Add(1)
		go n.acceptLoop(listener)
	}
	n.started = true
	n.wg.Add(1)
	go n.gossipLoop()
	return nil
}

func (n *Node) ID() string                  { return n.identity.ID() }
func (n *Node) Deliveries() <-chan Delivery { return n.deliveries }
func (n *Node) Errors() <-chan error        { return n.errors }

func (n *Node) Address() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.listener == nil {
		return ""
	}
	return n.listener.Addr().String()
}

func (n *Node) Peers() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.peerIDsLocked()
}

// Disconnect removes the current session from routing and closes its socket.
// It is idempotent for absent peers. Callers must cancel and wait for their own
// outstanding Connect calls/retry loops first. This does not ban future inbound
// connections or discard cached messages addressed to the peer.
func (n *Node) Disconnect(id string) error {
	if _, err := protocol.ParseID(id); err != nil {
		return err
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return ErrClosed
	}
	p := n.peers[id]
	if p != nil {
		delete(n.peers, id)
		_ = n.router.SetPeers(n.peerIDsLocked())
	}
	n.mu.Unlock()
	if p != nil {
		p.close()
	}
	return nil
}

func (n *Node) peerIDsLocked() []string {
	ids := make([]string, 0, len(n.peers))
	for id := range n.peers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// begin registers operations before Close can wait, preventing Add/Wait races.
func (n *Node) begin(pending bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return ErrClosed
	}
	if !n.started {
		return errors.New("node not started")
	}
	if pending {
		if n.pending >= n.config.MaxPending {
			return errors.New("pending connection limit reached")
		}
		n.pending++
	}
	n.wg.Add(1)
	return nil
}

func (n *Node) endPending() {
	n.mu.Lock()
	n.pending--
	n.mu.Unlock()
	n.wg.Done()
}

// Connect dials an explicit address and pins the full expected DEMP identity.
// It returns only after mutual TLS and both-key proof complete. It does not
// perform discovery or silently trust a different identity at the same address.
func (n *Node) Connect(ctx context.Context, address, expected string) error {
	if _, err := protocol.ParseID(expected); err != nil {
		return err
	}
	if err := n.begin(true); err != nil {
		return err
	}
	defer n.endPending()
	ctx, cancel := context.WithTimeout(ctx, n.config.Transport.HandshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(n.ctx, cancel)
	defer stop()
	raw, err := (&net.Dialer{Timeout: n.config.Transport.HandshakeTimeout, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	session, err := n.auth.Client(ctx, raw, expected)
	if err != nil {
		return err
	}
	return n.addPeer(session)
}

func (n *Node) acceptLoop(listener net.Listener) {
	defer n.wg.Done()
	for {
		raw, err := listener.Accept()
		if err != nil {
			if n.ctx.Err() != nil {
				return
			}
			n.report(fmt.Errorf("accept: %w", err))
			// Bound retries after a temporary resource failure.
			select {
			case <-time.After(100 * time.Millisecond):
			case <-n.ctx.Done():
				return
			}
			continue
		}
		if err := n.begin(true); err != nil {
			raw.Close()
			continue
		}
		go func() {
			defer n.endPending()
			session, err := n.auth.Server(n.ctx, raw)
			if err == nil {
				err = n.addPeer(session)
			}
			if err != nil && n.ctx.Err() == nil {
				n.report(fmt.Errorf("incoming peer rejected: %w", err))
			}
		}()
	}
}

func (n *Node) addPeer(session *transport.Session) error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		session.Close()
		return ErrClosed
	}
	id := session.PeerID()
	previous := n.peers[id]
	if previous == nil && len(n.peers) >= n.config.Router.MaxPeers {
		n.mu.Unlock()
		session.Close()
		return errors.New("connected peer limit reached")
	}
	if previous != nil {
		// If both nodes dial simultaneously, both keep the same connection:
		// the one initiated by the lexicographically smaller identity.
		preferOutbound := n.ID() < id
		if previous.session.Outbound() == preferOutbound || session.Outbound() != preferOutbound {
			n.mu.Unlock()
			session.Close()
			return nil
		}
	}
	p := &peer{session: session, queue: make(chan routing.Packet, n.config.SendQueue), done: make(chan struct{})}
	n.peers[id] = p
	if err := n.router.SetPeers(n.peerIDsLocked()); err != nil {
		delete(n.peers, id)
		n.mu.Unlock()
		p.close()
		return err
	}
	n.wg.Add(2)
	n.mu.Unlock()
	if previous != nil {
		previous.close()
	}
	go n.readPeer(p)
	go n.writePeer(p)
	return nil
}

func (n *Node) removePeer(p *peer) {
	n.mu.Lock()
	if n.peers[p.session.PeerID()] == p {
		delete(n.peers, p.session.PeerID())
		_ = n.router.SetPeers(n.peerIDsLocked())
	}
	n.mu.Unlock()
	p.close()
}

func (n *Node) writePeer(p *peer) {
	defer n.wg.Done()
	defer n.removePeer(p)
	ticker := time.NewTicker(n.config.PingInterval)
	defer ticker.Stop()
	for {
		var err error
		select {
		case <-n.ctx.Done():
			return
		case <-p.done:
			return
		case packet := <-p.queue:
			err = p.session.Send(packet)
		case <-ticker.C:
			err = p.session.Ping()
		}
		if err != nil {
			n.report(fmt.Errorf("send to %s: %w", p.session.PeerID(), err))
			return
		}
	}
}

func (n *Node) readPeer(p *peer) {
	defer n.wg.Done()
	defer n.removePeer(p)
	ctx, cancel := context.WithCancel(n.ctx)
	defer cancel()
	// A bounded per-peer watcher releases blocked application delivery when this
	// connection is removed (including queue overflow or node shutdown).
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-p.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() { cancel(); <-watchDone }()
	for {
		packet, err := p.session.Receive()
		if err != nil {
			if ctx.Err() == nil {
				n.report(fmt.Errorf("receive from %s: %w", p.session.PeerID(), err))
			}
			return
		}
		result, err := n.router.Handle(p.session.PeerID(), packet, time.Now())
		if err != nil {
			n.report(fmt.Errorf("routing packet rejected: %w", err))
			if errors.Is(err, routing.ErrRateLimited) {
				return
			}
			continue
		}
		if err := n.process(ctx, result); err != nil {
			n.report(err)
		}
	}
}

func (n *Node) gossipLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(n.config.GossipInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case now := <-ticker.C:
			sends, err := n.router.Gossip(now)
			if err != nil {
				n.report(err)
				continue
			}
			n.dispatch(sends)
		}
	}
}

func (n *Node) dispatch(sends []routing.Transmission) {
	for _, send := range sends {
		n.mu.Lock()
		p := n.peers[send.Peer]
		n.mu.Unlock()
		if p == nil {
			continue
		}
		select {
		case <-p.done:
		case p.queue <- send.Packet:
		default:
			n.report(fmt.Errorf("slow peer disconnected: %s", send.Peer))
			n.removePeer(p)
		}
	}
}

// Publish accepts a message into the local router. A successful return is not a
// remote delivery acknowledgment. Network failures are reported through Errors;
// cached envelopes are retried by gossip while connected routes remain.
func (n *Node) Publish(ctx context.Context, message protocol.Message) error {
	if err := n.begin(false); err != nil {
		return err
	}
	defer n.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(n.ctx, cancel)
	defer stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := n.router.Publish(message, time.Now())
	if err != nil {
		return err
	}
	return n.process(ctx, result)
}

func (n *Node) process(ctx context.Context, result routing.Result) error {
	n.dispatch(result.Outbound)
	if result.Delivered == nil {
		return nil
	}
	now := time.Now()
	body, err := result.Delivered.OpenBody(n.identity, now)
	if err != nil {
		return fmt.Errorf("recipient rejected encrypted body: %w", err)
	}
	contentID := body.ContentID()
	n.deliveryMu.Lock()
	defer n.deliveryMu.Unlock()
	for id, expiry := range n.delivered {
		if expiry <= now.UnixMilli() {
			delete(n.delivered, id)
		}
	}
	if _, duplicate := n.delivered[contentID]; duplicate {
		return nil
	}
	if len(n.delivered) >= n.config.Router.MaxMessages {
		return errors.New("recipient replay cache full")
	}
	// Backpressure keeps deliveries bounded. Cancellation may discard a queued
	// delivery; durable mailboxes and recipient acknowledgments are not provided.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case n.deliveries <- Delivery{MessageID: result.Delivered.MessageID, ContentID: contentID, Body: body}:
		n.delivered[contentID] = body.ExpiresAt
		return nil
	}
}

func (n *Node) report(err error) {
	if n.ctx.Err() != nil {
		return
	}
	select {
	case n.errors <- err:
	default:
	}
}

// Close cancels dials/handshakes, closes sockets, waits for workers, and then
// closes delivery/error channels. It is safe and idempotent under concurrency.
func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		n.mu.Lock()
		n.closed = true
		n.cancel()
		if n.listener != nil {
			n.listener.Close()
		}
		for _, p := range n.peers {
			p.close()
		}
		n.mu.Unlock()
		n.wg.Wait()
		close(n.deliveries)
		close(n.errors)
	})
	return nil
}
