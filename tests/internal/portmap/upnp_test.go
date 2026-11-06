package portmap

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/huin/goupnp/soap"
)

func TestUPnPDiscoveryReportsNoReplies(t *testing.T) {
	searched := make(chan string, 3)
	search := func(_ context.Context, target string) ([]goupnp.ServiceClient, []error, error) {
		searched <- target
		return nil, nil, nil
	}
	mappings, err := discoverUPnPWithSearch(context.Background(), netip.MustParseAddrPort("0.0.0.0:9000"), [12]byte{}, search)
	if len(mappings) != 0 || err == nil || !strings.Contains(err.Error(), "no compatible router discovered") {
		t.Fatalf("empty discovery must explain why UPnP is unavailable: mappings=%v error=%v", mappings, err)
	}
	wanted := map[string]bool{
		internetgateway2.URN_WANIPConnection_1:  true,
		internetgateway2.URN_WANIPConnection_2:  true,
		internetgateway2.URN_WANPPPConnection_1: true,
	}
	for range 3 {
		delete(wanted, <-searched)
	}
	if len(wanted) != 0 {
		t.Fatal("missing UPnP discovery targets", wanted)
	}
}

func TestUPnPDiscoveryExplainsUnusableInterface(t *testing.T) {
	search := func(context.Context, string) ([]goupnp.ServiceClient, []error, error) {
		// A discovered client with no usable local address must not disappear
		// silently or be mistaken for a search that received no router replies.
		return []goupnp.ServiceClient{{}}, nil, nil
	}
	mappings, err := discoverUPnPWithSearch(context.Background(), netip.MustParseAddrPort("192.168.1.20:9000"), [12]byte{}, search)
	if len(mappings) != 0 || err == nil || !strings.Contains(err.Error(), "matching listener 192.168.1.20:9000") || strings.Contains(err.Error(), "no compatible router discovered") {
		t.Fatalf("missing interface diagnostic: mappings=%v error=%v", mappings, err)
	}
}

func TestUPnPDiscoveryPreservesDeviceErrors(t *testing.T) {
	deviceErr := errors.New("cannot fetch router description")
	search := func(context.Context, string) ([]goupnp.ServiceClient, []error, error) {
		return nil, []error{deviceErr}, nil
	}
	_, err := discoverUPnPWithSearch(context.Background(), netip.MustParseAddrPort("0.0.0.0:9000"), [12]byte{}, search)
	if !errors.Is(err, deviceErr) || strings.Contains(err.Error(), "no compatible router discovered") {
		t.Fatal("device error was hidden by generic discovery diagnostic", err)
	}
}

type upnpEntry struct {
	port        uint16
	host        string
	enabled     bool
	description string
	duration    uint32
}
type fakeUPnP struct {
	entries       map[uint16]upnpEntry
	onlyPermanent bool
	adds, deletes int
}

func fault(code int) error {
	e := &soap.SOAPFaultError{}
	e.Detail.UPnPError.Errorcode = code
	return e
}
func (f *fakeUPnP) GetExternalIPAddressCtx(context.Context) (string, error) {
	return "203.0.113.30", nil
}
func (f *fakeUPnP) GetSpecificPortMappingEntryCtx(_ context.Context, _ string, external uint16, _ string) (uint16, string, bool, string, uint32, error) {
	e, ok := f.entries[external]
	if !ok {
		return 0, "", false, "", 0, fault(714)
	}
	return e.port, e.host, e.enabled, e.description, e.duration, nil
}
func (f *fakeUPnP) AddPortMappingCtx(_ context.Context, _ string, external uint16, protocol string, internal uint16, host string, enabled bool, description string, duration uint32) error {
	f.adds++
	if protocol != "TCP" {
		return fmt.Errorf("expected TCP")
	}
	if f.onlyPermanent && duration != 0 {
		return fault(725)
	}
	if duration != 0 {
		duration = 60
	}
	f.entries[external] = upnpEntry{internal, host, enabled, description, duration}
	return nil
}
func (f *fakeUPnP) DeletePortMappingCtx(_ context.Context, _ string, external uint16, _ string) error {
	f.deletes++
	delete(f.entries, external)
	return nil
}

func TestUPnPCollisionRenewalAndOwnedCleanup(t *testing.T) {
	f := &fakeUPnP{entries: map[uint16]upnpEntry{9000: {8000, "192.168.1.99", true, "other app", 100}}}
	m := &upnpMapping{client: f, local: netip.MustParseAddrPort("192.168.1.20:9000"), externalPort: 9000, description: "DEMP-test"}
	l, err := m.renew(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l.address.Port() == 9000 || f.entries[9000].description != "other app" || l.lifetime != time.Minute {
		t.Fatal("mapping collision or shortened lease mishandled", l)
	}
	// Losing the creation/deletion response and rediscovering must recover the
	// same owned rule, even when the original requested external port was busy.
	recovered := &upnpMapping{client: f, local: m.local, externalPort: 9000, description: m.description}
	if recoveredLease, err := recovered.renew(context.Background()); err != nil || recoveredLease.address != l.address || len(f.entries) != 2 {
		t.Fatal("rediscovery leaked another rule", recoveredLease, err)
	}
	if _, err := m.renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.entries) != 1 || f.entries[9000].description != "other app" || f.deletes != 1 {
		t.Fatal("deleted someone else's mapping", f)
	}
}

func TestUPnPPermanentLeaseAndReplacement(t *testing.T) {
	f := &fakeUPnP{entries: map[uint16]upnpEntry{}, onlyPermanent: true}
	m := &upnpMapping{client: f, local: netip.MustParseAddrPort("192.168.1.20:9000"), externalPort: 9000, description: "DEMP-test"}
	l, err := m.renew(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l.lifetime != 0 || f.adds != 2 {
		t.Fatal("permanent-only router unsupported", l, f)
	}
	f.entries[9000] = upnpEntry{8000, "192.168.1.99", true, "replacement", 0}
	if err := m.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.deletes != 0 {
		t.Fatal("deleted replaced mapping")
	}
}

// Exercise generated goupnp SOAP calls against a local HTTP router simulator,
// including actual fault decoding. No discovery or real router is involved.
func TestUPnPSOAPLifecycle(t *testing.T) {
	var entry *upnpEntry
	var handlerErr error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		action := strings.TrimSuffix(strings.Split(r.Header.Get("SOAPAction"), "#")[1], `"`)
		payload := ""
		switch action {
		case "GetExternalIPAddress":
			payload = "<NewExternalIPAddress>203.0.113.40</NewExternalIPAddress>"
		case "GetSpecificPortMappingEntry":
			if entry == nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>714</errorCode><errorDescription>NoSuchEntryInArray</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`)
				return
			}
			payload = fmt.Sprintf("<NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>60</NewLeaseDuration>", entry.port, entry.host, entry.description)
		case "AddPortMapping":
			var envelope struct {
				Body struct {
					Add struct {
						External    uint16 `xml:"NewExternalPort"`
						Protocol    string `xml:"NewProtocol"`
						Internal    uint16 `xml:"NewInternalPort"`
						Host        string `xml:"NewInternalClient"`
						Description string `xml:"NewPortMappingDescription"`
					} `xml:"AddPortMapping"`
				} `xml:"Body"`
			}
			if err := xml.Unmarshal(data, &envelope); err != nil {
				handlerErr = err
			}
			add := envelope.Body.Add
			if add.External != 9000 || add.Internal != 9000 || add.Protocol != "TCP" || add.Host != "192.168.1.20" {
				handlerErr = fmt.Errorf("unexpected mapping request: %s", data)
			}
			entry = &upnpEntry{add.Internal, add.Host, true, add.Description, 60}
		case "DeletePortMapping":
			entry = nil
		default:
			handlerErr = fmt.Errorf("unexpected SOAP action: %s", action)
		}
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:%sResponse xmlns:u="%s">%s</u:%sResponse></s:Body></s:Envelope>`, action, internetgateway2.URN_WANIPConnection_1, payload, action)
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	client := &internetgateway2.WANIPConnection1{ServiceClient: goupnp.ServiceClient{SOAPClient: soap.NewSOAPClient(*endpoint)}}
	m := &upnpMapping{client: client, local: netip.MustParseAddrPort("192.168.1.20:9000"), externalPort: 9000, description: "DEMP-test"}
	if l, err := m.renew(context.Background()); err != nil || l.address.String() != "203.0.113.40:9000" {
		t.Fatal(l, err)
	}
	if err := m.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	server.Close() // join handlers before inspecting simulator state
	if handlerErr != nil || entry != nil {
		t.Fatal("SOAP lifecycle", handlerErr, entry)
	}
}
