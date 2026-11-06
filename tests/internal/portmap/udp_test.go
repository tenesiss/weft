package portmap

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func udpRouter(t *testing.T, handle func([]byte) []byte) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if response := handle(bytes.Clone(buf[:n])); response != nil {
				_, _ = c.WriteToUDP(response, addr)
			}
		}
	}()
	t.Cleanup(func() { c.Close(); <-done })
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func pcpReply(request []byte) []byte {
	response := make([]byte, 60)
	response[0], response[1] = 2, 0x81
	copy(response[24:], request[24:])
	if binary.BigEndian.Uint32(request[4:8]) != 0 {
		binary.BigEndian.PutUint32(response[4:8], 120)
	}
	binary.BigEndian.PutUint16(response[42:44], 45678)
	ip := netip.MustParseAddr("203.0.113.10").As16()
	copy(response[44:60], ip[:])
	return response
}

func TestPCPCreateRenewAndDelete(t *testing.T) {
	requests := make(chan []byte, 3)
	remote := udpRouter(t, func(request []byte) []byte { requests <- request; return pcpReply(request) })
	m := &udpMapping{gateway: remote, local: netip.MustParseAddrPort("127.0.0.1:9000"), protocol: "PCP", externalPort: 9000, nonce: [12]byte{1, 2, 3}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for range 2 {
		l, err := m.renew(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if l.address.String() != "203.0.113.10:45678" || l.lifetime != 120*time.Second {
			t.Fatal(l)
		}
	}
	if err := m.close(ctx); err != nil {
		t.Fatal(err)
	}
	first, renewal, deletion := <-requests, <-requests, <-requests
	if first[36] != 6 || binary.BigEndian.Uint16(first[40:42]) != 9000 || binary.BigEndian.Uint16(renewal[42:44]) != 45678 || binary.BigEndian.Uint32(deletion[4:8]) != 0 || !bytes.Equal(first[24:36], deletion[24:36]) {
		t.Fatal("incorrect PCP mapping lifecycle")
	}
}

func TestNATPMPUsesAssignedPortAndDeletesOnlyThisMapping(t *testing.T) {
	requests := make(chan []byte, 5)
	remote := udpRouter(t, func(request []byte) []byte {
		requests <- request
		if request[1] == 0 {
			return []byte{0, 128, 0, 0, 0, 0, 0, 1, 203, 0, 113, 20}
		}
		response := make([]byte, 16)
		response[1] = 130
		copy(response[8:10], request[4:6])
		binary.BigEndian.PutUint16(response[10:12], 45679)
		if binary.BigEndian.Uint32(request[8:12]) != 0 {
			binary.BigEndian.PutUint32(response[12:16], 90)
		}
		return response
	})
	m := &udpMapping{gateway: remote, local: netip.MustParseAddrPort("127.0.0.1:9001"), protocol: "NAT-PMP", externalPort: 9001}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for range 2 {
		l, err := m.renew(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if l.address.String() != "203.0.113.20:45679" || l.lifetime != 90*time.Second {
			t.Fatal(l)
		}
	}
	if err := m.close(ctx); err != nil {
		t.Fatal(err)
	}
	<-requests
	first := <-requests
	<-requests
	renewal, deletion := <-requests, <-requests
	if first[1] != 2 || binary.BigEndian.Uint16(renewal[6:8]) != 45679 || binary.BigEndian.Uint16(deletion[4:6]) != 9001 || binary.BigEndian.Uint32(deletion[8:12]) != 0 {
		t.Fatal("incorrect NAT-PMP lifecycle")
	}
}

func TestRejectsMalformedPCPResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"short", func(b []byte) []byte { return b[:23] }},
		{"nonce", func(b []byte) []byte { b[24] ^= 1; return b }},
		{"udp", func(b []byte) []byte { b[36] = 17; return b }},
		{"internal port", func(b []byte) []byte { b[40] ^= 1; return b }},
		{"external port", func(b []byte) []byte { clear(b[42:44]); return b }},
		{"zero lease", func(b []byte) []byte { clear(b[4:8]); return b }},
		{"denied", func(b []byte) []byte { b[3] = 2; return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remote := udpRouter(t, func(r []byte) []byte { return tc.mutate(pcpReply(r)) })
			m := &udpMapping{gateway: remote, local: netip.MustParseAddrPort("127.0.0.1:9000"), protocol: "PCP"}
			if _, err := m.renew(context.Background()); err == nil {
				t.Fatal("invalid reply accepted")
			}
		})
	}
}

func TestSilentRouterCancellationAndPacketLoss(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		remote := udpRouter(t, func([]byte) []byte { return nil })
		m := &udpMapping{gateway: remote, local: netip.MustParseAddrPort("127.0.0.1:9000"), protocol: "PCP"}
		ctx, cancel := context.WithCancel(context.Background())
		timer := time.AfterFunc(20*time.Millisecond, cancel)
		defer timer.Stop()
		start := time.Now()
		if _, err := m.renew(ctx); err == nil || time.Since(start) > time.Second {
			t.Fatal("unbounded router operation", err)
		}
	})
	t.Run("lost first request", func(t *testing.T) {
		count := 0
		remote := udpRouter(t, func(r []byte) []byte {
			count++
			if count == 1 {
				return nil
			}
			return pcpReply(r)
		})
		m := &udpMapping{gateway: remote, local: netip.MustParseAddrPort("127.0.0.1:9000"), protocol: "PCP"}
		if _, err := m.renew(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}
