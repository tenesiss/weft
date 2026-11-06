package portmap

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/huin/goupnp/soap"
)

type upnpClient interface {
	GetExternalIPAddressCtx(context.Context) (string, error)
	GetSpecificPortMappingEntryCtx(context.Context, string, uint16, string) (uint16, string, bool, string, uint32, error)
	AddPortMappingCtx(context.Context, string, uint16, string, uint16, string, bool, string, uint32) error
	DeletePortMappingCtx(context.Context, string, uint16, string) error
}

type upnpMapping struct {
	client       upnpClient
	local        netip.AddrPort
	externalPort uint16
	description  string
	permanent    bool
	candidate    int
}

func discoverUPnP(ctx context.Context, listener netip.AddrPort, owner [12]byte) ([]*upnpMapping, error) {
	return discoverUPnPWithSearch(ctx, listener, owner, goupnp.NewServiceClientsCtx)
}

func discoverUPnPWithSearch(ctx context.Context, listener netip.AddrPort, owner [12]byte, search func(context.Context, string) ([]goupnp.ServiceClient, []error, error)) ([]*upnpMapping, error) {
	type result struct {
		clients []goupnp.ServiceClient
		err     error
	}
	results := make(chan result, 3)
	for _, urn := range []string{internetgateway2.URN_WANIPConnection_2, internetgateway2.URN_WANIPConnection_1, internetgateway2.URN_WANPPPConnection_1} {
		go func() {
			clients, perDevice, err := search(ctx, urn)
			results <- result{clients, errors.Join(append(perDevice, err)...)}
		}()
	}
	var mappings []*upnpMapping
	var failures []error
	servicesFound := 0
	for range 3 {
		select {
		case <-ctx.Done():
			return mappings, ctx.Err()
		case r := <-results:
			servicesFound += len(r.clients)
			if r.err != nil {
				failures = append(failures, r.err)
			}
			for _, service := range r.clients {
				ip, ok := netip.AddrFromSlice(service.LocalAddr())
				if !ok || !acceptsLocal(listener, ip.Unmap()) {
					continue
				}
				var client upnpClient
				switch service.Service.ServiceType {
				case internetgateway2.URN_WANIPConnection_2:
					client = &internetgateway2.WANIPConnection2{ServiceClient: service}
				case internetgateway2.URN_WANIPConnection_1:
					client = &internetgateway2.WANIPConnection1{ServiceClient: service}
				case internetgateway2.URN_WANPPPConnection_1:
					client = &internetgateway2.WANPPPConnection1{ServiceClient: service}
				default:
					continue
				}
				mappings = append(mappings, &upnpMapping{client: client, local: netip.AddrPortFrom(ip.Unmap(), listener.Port()), externalPort: listener.Port(), description: fmt.Sprintf("DEMP-%x", owner)})
			}
		}
	}
	// An SSDP search with no replies is successful at the transport layer, but
	// provides no mapping service. Report this even when PCP/NAT-PMP failed too.
	if len(mappings) == 0 {
		if servicesFound > 0 {
			failures = append(failures, fmt.Errorf("discovered services have no usable local IPv4 address matching listener %s", listener))
		} else if len(failures) == 0 {
			failures = append(failures, errors.New("no compatible router discovered; check router UPnP settings and local multicast/firewall access"))
		}
	}
	return mappings, errors.Join(failures...)
}

func upnpCode(err error, code int) bool {
	var fault *soap.SOAPFaultError
	return errors.As(err, &fault) && fault.Detail.UPnPError.Errorcode == code
}

func (m *upnpMapping) entry(ctx context.Context) (exists, owned bool, err error) {
	port, host, _, description, _, err := m.client.GetSpecificPortMappingEntryCtx(ctx, "", m.externalPort, "TCP")
	if upnpCode(err, 714) {
		return false, false, nil
	} // NoSuchEntryInArray
	if err != nil {
		return false, false, err
	}
	ip, err := netip.ParseAddr(host)
	return true, err == nil && ip.Unmap() == m.local.Addr() && port == m.local.Port() && description == m.description, nil
}

func (m *upnpMapping) renew(ctx context.Context) (lease, error) {
	host, err := m.client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return lease{}, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !usableIPv4(ip.Unmap()) {
		return lease{}, errors.New("invalid UPnP external IPv4 address")
	}
	for range 8 {
		exists, owned, err := m.entry(ctx)
		if err != nil {
			return lease{}, err
		}
		if exists && !owned {
			m.nextPort()
			continue
		}
		seconds := uint32(leaseTime / time.Second)
		if m.permanent {
			seconds = 0
		}
		err = m.client.AddPortMappingCtx(ctx, "", m.externalPort, "TCP", m.local.Port(), m.local.Addr().String(), true, m.description, seconds)
		if upnpCode(err, 725) && seconds != 0 { // OnlyPermanentLeasesSupported
			m.permanent = true
			continue
		}
		if upnpCode(err, 718) { // ConflictInMappingEntry: never overwrite it.
			m.nextPort()
			continue
		}
		if err != nil {
			return lease{}, err
		}
		// Query the actual lease; routers may shorten the requested duration.
		port, local, enabled, description, granted, err := m.client.GetSpecificPortMappingEntryCtx(ctx, "", m.externalPort, "TCP")
		localIP, parseErr := netip.ParseAddr(local)
		if err != nil {
			return lease{}, err
		}
		if parseErr != nil || localIP.Unmap() != m.local.Addr() || port != m.local.Port() || !enabled || description != m.description {
			return lease{}, errors.New("router did not install the requested UPnP mapping")
		}
		return lease{netip.AddrPortFrom(ip.Unmap(), m.externalPort), time.Duration(granted) * time.Second, "UPnP"}, nil
	}
	return lease{}, errors.New("no available UPnP external TCP port")
}

func (m *upnpMapping) nextPort() {
	// The random ownership token also gives a stable candidate sequence. After
	// lost responses, rediscovery can find and reuse our own mapping instead of
	// leaking a new permanent rule on every retry.
	m.candidate++
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", m.description, m.candidate)))
	m.externalPort = 49152 + binary.BigEndian.Uint16(sum[:2])%16384
}

func (m *upnpMapping) close(ctx context.Context) error {
	_, owned, err := m.entry(ctx)
	if err != nil || !owned {
		return err
	}
	return m.client.DeletePortMappingCtx(ctx, "", m.externalPort, "TCP")
}
