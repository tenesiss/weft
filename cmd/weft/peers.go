package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"weft/node"
	"weft/protocol"
)

type peerEndpoint struct {
	ID      string `json:"id"`
	Address string `json:"ip"`
}

func (p peerEndpoint) validate() error {
	if _, err := protocol.ParseID(p.ID); err != nil {
		return fmt.Errorf("invalid peer ID: %w", err)
	}
	host, port, err := net.SplitHostPort(p.Address)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" || strings.ContainsAny(host, " \t\r\n") || len(p.Address) > 1024 || portErr != nil || number == 0 {
		return errors.New("ip must be host:port with a port from 1 to 65535 (IPv6: [address]:port)")
	}
	return nil
}

type managedPeer struct {
	endpoint peerEndpoint
	cancel   context.CancelFunc
	done     chan struct{}
}

type peerManager struct {
	ctx    context.Context
	node   *node.Node
	limit  int
	emit   func(context.Context, any)
	mu     sync.Mutex
	peers  map[string]*managedPeer
	closed bool
}

func newPeerManager(ctx context.Context, n *node.Node, limit int, emit func(context.Context, any)) *peerManager {
	return &peerManager{ctx: ctx, node: n, limit: limit, emit: emit, peers: make(map[string]*managedPeer)}
}

// Connect maintains one retry loop per identity. It never changes the inbound
// allowlist; the remote listener must independently authorize our identity.
func (m *peerManager) Connect(endpoint peerEndpoint) error {
	if err := endpoint.validate(); err != nil {
		return err
	}
	if endpoint.ID == m.node.ID() {
		return errors.New("cannot connect to self")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil {
		return node.ErrClosed
	}
	if existing := m.peers[endpoint.ID]; existing != nil {
		if existing.endpoint == endpoint {
			return nil
		}
		return errors.New("peer already configured at another address; disconnect it first")
	}
	if len(m.peers) >= m.limit {
		return errors.New("configured peer limit reached; disconnect a peer first")
	}
	ctx, cancel := context.WithCancel(m.ctx)
	p := &managedPeer{endpoint: endpoint, cancel: cancel, done: make(chan struct{})}
	m.peers[endpoint.ID] = p
	go m.maintain(ctx, p)
	return nil
}

func (m *peerManager) maintain(ctx context.Context, p *managedPeer) {
	defer close(p.done)
	delay := time.Second
	for ctx.Err() == nil {
		if !slices.Contains(m.node.Peers(), p.endpoint.ID) {
			err := m.node.Connect(ctx, p.endpoint.Address, p.endpoint.ID)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				m.emit(ctx, fmt.Errorf("connect %s (%s): %w", p.endpoint.ID, p.endpoint.Address, err))
				delay = min(30*time.Second, delay*2)
			} else {
				m.emit(ctx, map[string]string{"event": "connected", "peer": p.endpoint.ID})
				delay = time.Second
			}
		} else {
			delay = time.Second
		}
		timer := time.NewTimer(delay + time.Duration(rand.Int64N(int64(delay/2))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (m *peerManager) Disconnect(id string) error {
	if _, err := protocol.ParseID(id); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return node.ErrClosed
	}
	if p := m.peers[id]; p != nil {
		// Wait before closing the session: a dial completing concurrently must
		// not be able to install a new connection after disconnect returns.
		p.cancel()
		<-p.done
		delete(m.peers, id)
	}
	return m.node.Disconnect(id)
}

func (m *peerManager) Endpoints() []peerEndpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	endpoints := make([]peerEndpoint, 0, len(m.peers))
	for _, p := range m.peers {
		endpoints = append(endpoints, p.endpoint)
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].ID < endpoints[j].ID })
	return endpoints
}

func (m *peerManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for _, p := range m.peers {
		p.cancel()
	}
	for id, p := range m.peers {
		<-p.done
		delete(m.peers, id)
	}
}
