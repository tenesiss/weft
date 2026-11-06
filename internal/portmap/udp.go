package portmap

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Only TCP MAP operations are used. See RFC 6887 section 11 and RFC 6886
// sections 3.2-3.4. A mapping's nonce, internal port and assigned external port
// are retained across renewals and deletion.
type udpMapping struct {
	gateway      netip.AddrPort
	local        netip.AddrPort
	protocol     string
	nonce        [12]byte
	externalPort uint16
	externalIP   netip.Addr
}

func (m *udpMapping) renew(ctx context.Context) (lease, error) {
	return m.mapPort(ctx, uint32(leaseTime/time.Second))
}
func (m *udpMapping) close(ctx context.Context) error { _, err := m.mapPort(ctx, 0); return err }

func (m *udpMapping) mapPort(ctx context.Context, lifetime uint32) (lease, error) {
	if m.protocol == "PCP" {
		return m.pcp(ctx, lifetime)
	}
	return m.pmp(ctx, lifetime)
}

func (m *udpMapping) pcp(ctx context.Context, lifetime uint32) (lease, error) {
	request := make([]byte, 60)
	request[0], request[1] = 2, 1 // PCP v2, MAP
	binary.BigEndian.PutUint32(request[4:8], lifetime)
	client := m.local.Addr().As16()
	copy(request[8:24], client[:])
	copy(request[24:36], m.nonce[:])
	request[36] = 6 // TCP
	binary.BigEndian.PutUint16(request[40:42], m.local.Port())
	binary.BigEndian.PutUint16(request[42:44], m.externalPort)
	suggested := netip.IPv4Unspecified().As16()
	if m.externalIP.IsValid() {
		suggested = m.externalIP.As16()
	}
	copy(request[44:60], suggested[:])
	response, err := m.exchange(ctx, request)
	if err != nil {
		return lease{}, err
	}
	if len(response) < 24 || response[0] != 2 || response[1] != 0x81 {
		return lease{}, errors.New("invalid PCP response header")
	}
	if response[3] != 0 {
		return lease{}, fmt.Errorf("PCP result code %d", response[3])
	}
	if len(response) < 60 || !bytes.Equal(response[24:36], m.nonce[:]) || response[36] != 6 || binary.BigEndian.Uint16(response[40:42]) != m.local.Port() {
		return lease{}, errors.New("PCP response does not match TCP mapping request")
	}
	ip := netip.AddrFrom16([16]byte(response[44:60])).Unmap()
	return m.accept(ip, binary.BigEndian.Uint16(response[42:44]), binary.BigEndian.Uint32(response[4:8]), lifetime)
}

func (m *udpMapping) pmp(ctx context.Context, lifetime uint32) (lease, error) {
	ip := m.externalIP
	if lifetime != 0 {
		response, err := m.exchange(ctx, []byte{0, 0})
		if err != nil {
			return lease{}, err
		}
		if err := pmpResponse(response, 128, 12); err != nil {
			return lease{}, err
		}
		ip = netip.AddrFrom4([4]byte(response[8:12]))
		if !usableIPv4(ip) {
			return lease{}, errors.New("invalid NAT-PMP external IPv4 address")
		}
	}
	request := make([]byte, 12)
	request[1] = 2 // NAT-PMP TCP
	binary.BigEndian.PutUint16(request[4:6], m.local.Port())
	if lifetime != 0 {
		binary.BigEndian.PutUint16(request[6:8], m.externalPort)
	}
	binary.BigEndian.PutUint32(request[8:12], lifetime)
	response, err := m.exchange(ctx, request)
	if err != nil {
		return lease{}, err
	}
	if err := pmpResponse(response, 130, 16); err != nil {
		return lease{}, err
	}
	if binary.BigEndian.Uint16(response[8:10]) != m.local.Port() {
		return lease{}, errors.New("NAT-PMP response has wrong internal port")
	}
	return m.accept(ip, binary.BigEndian.Uint16(response[10:12]), binary.BigEndian.Uint32(response[12:16]), lifetime)
}

func pmpResponse(response []byte, opcode byte, size int) error {
	if len(response) < 8 || response[0] != 0 || response[1] != opcode {
		return errors.New("invalid NAT-PMP response header")
	}
	if code := binary.BigEndian.Uint16(response[2:4]); code != 0 {
		return fmt.Errorf("NAT-PMP result code %d", code)
	}
	if len(response) != size {
		return errors.New("invalid NAT-PMP response size")
	}
	return nil
}

func (m *udpMapping) accept(ip netip.Addr, port uint16, seconds, requested uint32) (lease, error) {
	if requested == 0 {
		if seconds != 0 {
			return lease{}, errors.New("router did not delete mapping")
		}
		return lease{}, nil
	}
	if !usableIPv4(ip) || port == 0 || seconds == 0 {
		return lease{}, errors.New("router returned an invalid TCP mapping")
	}
	m.externalIP, m.externalPort = ip, port
	return lease{netip.AddrPortFrom(ip, port), time.Duration(seconds) * time.Second, m.protocol}, nil
}

// A connected UDP socket restricts replies to the selected gateway. Retries
// handle packet loss; deadlines and cancellation bound silent gateways.
func (m *udpMapping) exchange(ctx context.Context, request []byte) ([]byte, error) {
	dialer := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.IP(m.local.Addr().AsSlice())}}
	c, err := dialer.DialContext(ctx, "udp4", m.gateway.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	for retry := 250 * time.Millisecond; ; retry *= 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := c.SetDeadline(minTime(time.Now().Add(retry), deadline)); err != nil {
			return nil, err
		}
		if _, err := c.Write(request); err != nil {
			return nil, err
		}
		response := make([]byte, 1100)
		n, err := c.Read(response)
		if err == nil {
			return response[:n], nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() || !time.Now().Before(deadline) {
			return nil, err
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
