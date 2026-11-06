package portmap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jackpal/gateway"
)

// routeLocal chooses the source address the OS uses to reach this gateway.
// Dialing UDP does not send application data.
func routeLocal(ctx context.Context, address string) (netip.Addr, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "udp4", address)
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

func acceptsLocal(listener netip.AddrPort, ip netip.Addr) bool {
	return usableIPv4(ip) && (listener.Addr().IsUnspecified() || listener.Addr() == ip)
}

func discover(ctx context.Context, listener netip.AddrPort, owner [12]byte) (mapping, lease, error) {
	var failures []error
	// Reserve time for UPnP even if there are multiple silent default gateways.
	udpCtx, stopUDP := context.WithTimeout(ctx, 5*time.Second)
	defer stopUDP()
	// The gateway package queries the OS route table. Bound the caller's wait
	// even on a platform whose route command does not accept a context.
	type result struct {
		ips []net.IP
		err error
	}
	gateways := make(chan result, 1)
	go func() { ips, err := gateway.DiscoverGateways(); gateways <- result{ips, err} }()
	select {
	case <-udpCtx.Done():
		failures = append(failures, udpCtx.Err())
	case r := <-gateways:
		if r.err != nil {
			failures = append(failures, r.err)
		}
		for _, ip := range r.ips {
			if udpCtx.Err() != nil {
				break
			}
			gatewayIP, ok := netip.AddrFromSlice(ip.To4())
			if !ok || !usableIPv4(gatewayIP) {
				continue
			}
			remote := netip.AddrPortFrom(gatewayIP, 5351)
			local, err := routeLocal(udpCtx, remote.String())
			if err != nil {
				failures = append(failures, fmt.Errorf("gateway %s: determine local address: %w", gatewayIP, err))
				continue
			}
			if !acceptsLocal(listener, local) {
				failures = append(failures, fmt.Errorf("gateway %s uses local address %s, which does not match listener %s", gatewayIP, local, listener))
				continue
			}
			for _, protocol := range []string{"PCP", "NAT-PMP"} {
				mp := &udpMapping{gateway: remote, local: netip.AddrPortFrom(local, listener.Port()), protocol: protocol, externalPort: listener.Port(), nonce: owner}
				attempt, cancel := context.WithTimeout(udpCtx, 2*time.Second)
				l, err := mp.renew(attempt)
				cancel()
				if err == nil {
					return mp, l, nil
				}
				failures = append(failures, fmt.Errorf("%s gateway %s: %w", protocol, remote, err))
			}
		}
	}
	stopUDP()
	clients, err := discoverUPnP(ctx, listener, owner)
	if err != nil {
		failures = append(failures, fmt.Errorf("UPnP: %w", err))
	}
	for _, mp := range clients {
		l, err := mp.renew(ctx)
		if err == nil {
			return mp, l, nil
		}
		failures = append(failures, fmt.Errorf("UPnP: %w", err))
		_ = release(mp)
	}
	if len(failures) == 0 {
		failures = append(failures, errors.New("no compatible gateway found for listener"))
	}
	return nil, lease{}, fmt.Errorf("automatic TCP mapping failed: %w", errors.Join(failures...))
}
