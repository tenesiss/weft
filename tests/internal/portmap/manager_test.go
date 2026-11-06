package portmap

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type fakeMapping struct {
	renewFn     func(context.Context) (lease, error)
	closed      int
	cleanupLive bool
}

func (m *fakeMapping) renew(ctx context.Context) (lease, error) { return m.renewFn(ctx) }
func (m *fakeMapping) close(ctx context.Context) error {
	m.closed++
	m.cleanupLive = ctx.Err() == nil
	return nil
}

func TestDisabledAndIneligibleListenersNeverDiscover(t *testing.T) {
	for _, tc := range []struct{ mode, address, state string }{
		{"off", "0.0.0.0:9000", "off"},
		{"auto", "", "skipped"},
		{"auto", "127.0.0.1:9000", "skipped"},
		{"auto", "[::1]:9000", "skipped"},
		{"auto", "[2001:db8::1]:9000", "skipped"},
	} {
		t.Run(tc.mode+tc.address, func(t *testing.T) {
			m, err := New(tc.mode, tc.address, nil)
			if err != nil {
				t.Fatal(err)
			}
			m.discover = func(context.Context, netip.AddrPort) (mapping, lease, error) {
				t.Fatal("unexpected router discovery")
				return nil, lease{}, nil
			}
			if err := m.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := m.Status(); got.State != tc.state {
				t.Fatal(got)
			}
		})
	}
	if _, err := New("on", "0.0.0.0:9000", nil); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if _, err := New("auto", "0.0.0.0:0", nil); err == nil {
		t.Fatal("unbound port accepted")
	}
}

func TestRenewalFailureClearsEndpointAndRediscovers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first := &fakeMapping{renewFn: func(context.Context) (lease, error) { return lease{}, errors.New("router restarted") }}
	second := &fakeMapping{renewFn: func(context.Context) (lease, error) { t.Fatal("unexpected second renewal"); return lease{}, nil }}
	var states []Status
	m, err := New("auto", "0.0.0.0:4567", func(s Status) {
		states = append(states, s)
		if s.ExternalAddress == "203.0.113.2:5678" {
			cancel()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	m.retry = time.Millisecond
	calls := 0
	m.discover = func(ctx context.Context, local netip.AddrPort) (mapping, lease, error) {
		if local.Port() != 4567 {
			t.Fatal("did not use actual listener port")
		}
		calls++
		if calls == 1 {
			return first, lease{netip.MustParseAddrPort("203.0.113.1:4567"), time.Minute, "PCP"}, nil
		}
		return second, lease{netip.MustParseAddrPort("203.0.113.2:5678"), time.Minute, "NAT-PMP"}, nil
	}
	if err := m.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || first.closed != 1 || second.closed != 1 || !first.cleanupLive || !second.cleanupLive {
		t.Fatalf("lifecycle: calls=%d first=%+v second=%+v", calls, first, second)
	}
	if len(states) != 4 || states[2].State != "unavailable" || states[2].ExternalAddress != "" || !states[2].ExpiresAt.IsZero() {
		t.Fatalf("stale endpoint after failure: %+v", states)
	}
}

func TestGrantedLeaseControlsRenewal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	l := lease{netip.MustParseAddrPort("203.0.113.1:19000"), 100 * time.Millisecond, "PCP"}
	renewed := false
	mp := &fakeMapping{renewFn: func(context.Context) (lease, error) { renewed = true; cancel(); return l, nil }}
	m, _ := New("auto", "[::]:9000", nil)
	m.discover = func(context.Context, netip.AddrPort) (mapping, lease, error) { return mp, l, nil }
	start := time.Now()
	if err := m.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !renewed || time.Since(start) >= time.Second || mp.closed != 1 {
		t.Fatal("short lease was not renewed and removed")
	}
}

func TestUnavailableDiscoveryRetriesUntilCancelled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m, _ := New("auto", "192.168.1.20:9000", nil)
	m.retry = time.Millisecond
	calls := 0
	m.discover = func(context.Context, netip.AddrPort) (mapping, lease, error) {
		calls++
		if calls == 3 {
			cancel()
		}
		return nil, lease{}, errors.New("mapping disabled on router")
	}
	if err := m.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 3 || m.Status().State != "unavailable" {
		t.Fatal("did not retry", calls, m.Status())
	}
}

func TestUpstreamNATIsNotAdvertisedAsPublicReachability(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, _ := New("auto", "0.0.0.0:9000", func(s Status) {
		if s.State == "mapped" {
			cancel()
		}
	})
	mp := &fakeMapping{}
	m.discover = func(context.Context, netip.AddrPort) (mapping, lease, error) {
		return mp, lease{netip.MustParseAddrPort("100.64.1.2:9000"), time.Minute, "UPnP"}, nil
	}
	if err := m.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Status().Reason, "upstream NAT") {
		t.Fatal(m.Status())
	}
	if acceptsLocal(netip.MustParseAddrPort("192.168.1.20:9000"), netip.MustParseAddr("192.168.2.20")) {
		t.Fatal("mapping would target the wrong interface")
	}
}
