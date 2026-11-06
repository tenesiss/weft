// Package portmap maintains a best-effort IPv4 TCP mapping on a local router.
// Mapping success is not proof of Internet reachability or peer discovery.
package portmap

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const (
	leaseTime        = 30 * time.Minute
	operationTimeout = 12 * time.Second
	cleanupTimeout   = 2 * time.Second
	retryInterval    = time.Minute
)

type Status struct {
	Mode            string    `json:"mode"`
	State           string    `json:"state"`
	Protocol        string    `json:"protocol,omitempty"`
	ExternalAddress string    `json:"external_address,omitempty"`
	ExpiresAt       time.Time `json:"expires_at,omitzero"`
	Reason          string    `json:"reason,omitempty"`
}

type lease struct {
	address  netip.AddrPort
	lifetime time.Duration // zero means a permanent UPnP lease
	protocol string
}

type mapping interface {
	renew(context.Context) (lease, error)
	close(context.Context) error
}

type discoverFunc func(context.Context, netip.AddrPort) (mapping, lease, error)

type Manager struct {
	mu       sync.Mutex
	status   Status
	local    netip.AddrPort
	discover discoverFunc
	retry    time.Duration
	onChange func(Status)
}

func ValidateMode(mode string) error {
	if mode != "auto" && mode != "off" {
		return errors.New("-nat must be auto or off")
	}
	return nil
}

// New uses the actual bound listener address (including its assigned port).
// Run must be called exactly once; Status may be called concurrently.
func New(mode, address string, onChange func(Status)) (*Manager, error) {
	if err := ValidateMode(mode); err != nil {
		return nil, err
	}
	// Keep ownership stable across rediscovery when a renewal/deletion response
	// is lost. Otherwise PCP could reject our new nonce until the old lease ends.
	var owner [12]byte
	if _, err := rand.Read(owner[:]); err != nil {
		return nil, err
	}
	m := &Manager{status: Status{Mode: mode, State: "discovering"}, retry: retryInterval, onChange: onChange}
	m.discover = func(ctx context.Context, local netip.AddrPort) (mapping, lease, error) {
		return discover(ctx, local, owner)
	}
	switch {
	case mode == "off":
		m.status.State = "off"
	case address == "":
		m.status.State, m.status.Reason = "skipped", "outbound-only node"
	default:
		addr, err := netip.ParseAddrPort(address)
		if err != nil || addr.Port() == 0 {
			return nil, fmt.Errorf("invalid NAT listener address %q", address)
		}
		m.local = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		if m.local.Addr().IsLoopback() {
			m.status.State, m.status.Reason = "skipped", "loopback-only listener"
		} else if !m.local.Addr().Is4() && !m.local.Addr().IsUnspecified() {
			m.status.State, m.status.Reason = "skipped", "IPv6 listener; automatic mapping supports IPv4 only"
		}
	}
	return m, nil
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *Manager) update(s Status) {
	m.mu.Lock()
	s.Mode = m.status.Mode
	old := m.status
	m.status = s
	m.mu.Unlock()
	// Lease refreshes update status without emitting an event every minute.
	old.ExpiresAt, s.ExpiresAt = time.Time{}, time.Time{}
	if old != s && m.onChange != nil {
		m.onChange(m.Status())
	}
}

func release(mp mapping) error {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	return mp.close(ctx)
}

// Run retries discovery and renews mappings until cancellation. Failures never
// affect the TCP node. Cleanup uses its own bounded context after cancellation.
func (m *Manager) Run(ctx context.Context) (cleanupErr error) {
	if m.onChange != nil {
		m.onChange(m.Status())
	}
	if m.Status().State != "discovering" {
		return nil
	}
	var current mapping
	defer func() {
		if current != nil {
			cleanupErr = release(current)
		}
	}()
	for ctx.Err() == nil {
		opCtx, cancel := context.WithTimeout(ctx, operationTimeout)
		var l lease
		var err error
		if current == nil {
			current, l, err = m.discover(opCtx, m.local)
		} else {
			l, err = current.renew(opCtx)
		}
		cancel()
		if ctx.Err() != nil {
			break
		}
		delay := m.retry
		if err != nil {
			if current != nil {
				_ = release(current)
				current = nil
			}
			m.update(Status{State: "unavailable", Reason: err.Error()})
		} else {
			s := Status{State: "mapped", Protocol: l.protocol, ExternalAddress: l.address.String()}
			if l.lifetime > 0 {
				s.ExpiresAt = time.Now().Add(l.lifetime)
				delay = min(delay, l.lifetime/2)
			}
			if !publicIPv4(l.address.Addr()) {
				s.Reason = "router reports a non-public address; upstream NAT may prevent inbound connections"
			}
			m.update(s)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil
}

func publicIPv4(ip netip.Addr) bool {
	return ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

func usableIPv4(ip netip.Addr) bool {
	return ip.Is4() && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}
