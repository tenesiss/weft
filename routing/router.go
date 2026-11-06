// Package routing provides a transport-independent direct-first hybrid gossip
// state machine. It is an experiment, not an implementation of libp2p GossipSub.
package routing

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"demp/protocol"
)

const (
	Data           = "DATA"
	IHave          = "IHAVE"
	IWant          = "IWANT"
	MaxBatch       = 64
	MaxPacketBytes = protocol.MaxWireBytes + 1024
)

var (
	ErrCapacity    = errors.New("router cache is full; retry later")
	ErrRateLimited = errors.New("peer frame rate limit exceeded")
)

type Packet struct {
	Kind    string            `json:"kind"`
	Message *protocol.Message `json:"message,omitempty"`
	IDs     []string          `json:"ids,omitempty"`
}

type Transmission struct {
	Peer   string
	Packet Packet
}

type Result struct {
	Outbound []Transmission
	// Delivered is an opaque envelope for this node, not authenticated content.
	// The recipient must successfully OpenBody before acting on it.
	Delivered *protocol.Message
	Duplicate bool
}

type Config struct {
	Fanout             int
	LazyFanout         int
	MaxPeers           int
	MaxMessages        int
	MaxCacheBytes      int
	MaxFramesPerMinute int
}

func DefaultConfig() Config {
	return Config{Fanout: 3, LazyFanout: 3, MaxPeers: 64, MaxMessages: 1024, MaxCacheBytes: 8 * 1024 * 1024, MaxFramesPerMinute: 120}
}

type entry struct {
	message protocol.Message
	size    int
}
type budget struct {
	start  time.Time
	frames int
}

// Router is safe for concurrent use. The caller must authenticate each peer,
// schedule Gossip (suggested: once per second), and execute returned sends.
type Router struct {
	mu         sync.Mutex
	id         string
	config     Config
	peers      map[string]budget
	cache      map[string]entry
	cacheBytes int
	cursor     int
}

func New(id string, config Config) (*Router, error) {
	if _, err := protocol.ParseID(id); err != nil {
		return nil, err
	}
	if config.Fanout < 1 || config.LazyFanout < 1 || config.MaxPeers < 1 || config.MaxPeers > 256 || config.MaxMessages < 1 || config.MaxCacheBytes < 1 || config.MaxFramesPerMinute < 1 {
		return nil, errors.New("invalid router configuration")
	}
	return &Router{id: id, config: config, peers: make(map[string]budget), cache: make(map[string]entry)}, nil
}

// SetPeers installs identities already authenticated by the transport. It does
// not accept discovery claims or perform authentication itself.
func (r *Router) SetPeers(ids []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(ids) > r.config.MaxPeers {
		return errors.New("too many peers")
	}
	peers := make(map[string]budget)
	for _, id := range ids {
		if id == r.id {
			return errors.New("cannot peer with self")
		}
		if _, err := protocol.ParseID(id); err != nil {
			return err
		}
		peers[id] = r.peers[id]
	}
	r.peers = peers
	return nil
}

// Publish injects an opaque envelope. Authorship is encrypted and cannot be
// checked here; local callers are responsible for their publishing policy.
func (r *Router) Publish(message protocol.Message, now time.Time) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.accept("", message, now)
}

// Handle requires from to be the authenticated immediate peer, not body.source.
func (r *Router) Handle(from string, packet Packet, now time.Time) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	limit, ok := r.peers[from]
	if !ok {
		return Result{}, errors.New("unknown peer")
	}
	if limit.start.IsZero() || now.Sub(limit.start) >= time.Minute {
		limit = budget{start: now}
	}
	if limit.frames >= r.config.MaxFramesPerMinute {
		return Result{}, ErrRateLimited
	}
	limit.frames++
	r.peers[from] = limit
	if err := packet.Validate(); err != nil {
		return Result{}, err
	}
	r.prune(now)
	switch packet.Kind {
	case Data:
		return r.accept(from, *packet.Message, now)
	case IHave:
		var missing []string
		for _, id := range packet.IDs {
			if _, ok := r.cache[id]; !ok {
				missing = append(missing, id)
			}
		}
		if len(missing) == 0 {
			return Result{}, nil
		}
		return Result{Outbound: []Transmission{{Peer: from, Packet: Packet{Kind: IWant, IDs: missing}}}}, nil
	case IWant:
		var result Result
		// A single small request cannot amplify into 64 full payloads. Later
		// heartbeats retry the remaining IDs after the receiver caches this one.
		for _, id := range packet.IDs {
			if e, ok := r.cache[id]; ok {
				result.Outbound = append(result.Outbound, dataTo(from, e.message))
				break
			}
		}
		return result, nil
	}
	return Result{}, errors.New("unsupported packet kind")
}

func (r *Router) accept(from string, message protocol.Message, now time.Time) (Result, error) {
	r.prune(now)
	// Validate the public hash even when an ID is cached. This detects ID
	// substitution, not forgery: the sender's signature is encrypted.
	if err := message.ValidateEnvelope(now); err != nil {
		return Result{}, err
	}
	if _, ok := r.cache[message.MessageID]; ok {
		return Result{Duplicate: true}, nil
	}
	data, err := message.Marshal()
	if err != nil {
		return Result{}, err
	}
	if len(r.cache) >= r.config.MaxMessages || len(data) > r.config.MaxCacheBytes-r.cacheBytes {
		return Result{}, ErrCapacity
	}
	r.cache[message.MessageID] = entry{message: message, size: len(data)}
	r.cacheBytes += len(data)
	if message.Target == r.id {
		return Result{Delivered: &message}, nil
	}
	if _, direct := r.peers[message.Target]; direct && message.Target != from {
		return Result{Outbound: []Transmission{dataTo(message.Target, message)}}, nil
	}
	peers := r.peerList(from)
	if err := shuffle(peers); err != nil {
		return Result{}, err
	}
	var result Result
	for i, peer := range peers {
		if i < r.config.Fanout {
			result.Outbound = append(result.Outbound, dataTo(peer, message))
		} else if i-r.config.Fanout < r.config.LazyFanout {
			result.Outbound = append(result.Outbound, Transmission{Peer: peer, Packet: Packet{Kind: IHave, IDs: []string{message.MessageID}}})
		}
	}
	return result, nil
}

// Gossip repairs dropped sends and connects newly added peers to recent data.
// It advertises a rotating bounded batch so older entries cannot starve forever.
func (r *Router) Gossip(now time.Time) ([]Transmission, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(now)
	ids := make([]string, 0, len(r.cache))
	for id, e := range r.cache {
		if e.message.Target != r.id {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	sort.Strings(ids)
	start := r.cursor % len(ids)
	count := min(MaxBatch, len(ids))
	peers := r.peerList("")
	if err := shuffle(peers); err != nil {
		return nil, err
	}
	peers = peers[:min(r.config.LazyFanout, len(peers))]
	batches := make(map[string][]string)
	for offset := range count {
		id := ids[(start+offset)%len(ids)]
		message := r.cache[id].message
		if _, direct := r.peers[message.Target]; direct {
			batches[message.Target] = append(batches[message.Target], id)
			continue
		}
		for _, peer := range peers {
			batches[peer] = append(batches[peer], id)
		}
	}
	r.cursor = (start + count) % len(ids)
	var outbound []Transmission
	for peer, batch := range batches {
		outbound = append(outbound, Transmission{Peer: peer, Packet: Packet{Kind: IHave, IDs: batch}})
	}
	sort.Slice(outbound, func(i, j int) bool { return outbound[i].Peer < outbound[j].Peer })
	return outbound, nil
}

func (r *Router) prune(now time.Time) {
	for id, e := range r.cache {
		if e.message.ExpiresAt <= now.UnixMilli() {
			delete(r.cache, id)
			r.cacheBytes -= e.size
		}
	}
}

func (r *Router) peerList(exclude string) []string {
	var peers []string
	for id := range r.peers {
		if id != exclude {
			peers = append(peers, id)
		}
	}
	sort.Strings(peers)
	return peers
}

func shuffle(peers []string) error {
	for i := len(peers) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		peers[i], peers[j.Int64()] = peers[j.Int64()], peers[i]
	}
	return nil
}

func dataTo(peer string, message protocol.Message) Transmission {
	return Transmission{Peer: peer, Packet: Packet{Kind: Data, Message: &message}}
}

func (p Packet) Validate() error {
	switch p.Kind {
	case Data:
		if p.Message == nil || len(p.IDs) != 0 {
			return errors.New("invalid DATA packet")
		}
	case IHave, IWant:
		if p.Message != nil || len(p.IDs) == 0 || len(p.IDs) > MaxBatch {
			return errors.New("invalid gossip batch")
		}
		seen := make(map[string]bool)
		for _, id := range p.IDs {
			if !protocol.ValidMessageID(id) || seen[id] {
				return errors.New("invalid or repeated gossip ID")
			}
			seen[id] = true
		}
	default:
		return fmt.Errorf("unknown packet kind: %s", p.Kind)
	}
	return nil
}

func (p Packet) Marshal() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(p)
	if len(data) > MaxPacketBytes {
		return nil, errors.New("packet too large")
	}
	return data, err
}

// DecodePacket enforces the size limit BEFORE parsing; transports must also
// cap framing before allocating the incoming byte buffer.
func DecodePacket(data []byte) (Packet, error) {
	var packet Packet
	if err := protocol.DecodeJSON(data, &packet, MaxPacketBytes); err != nil {
		return packet, err
	}
	return packet, packet.Validate()
}
