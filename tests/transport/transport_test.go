package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"weft/protocol"
	"weft/routing"
)

func identity(t testing.TB) *protocol.Identity {
	t.Helper()
	id, err := protocol.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func auth(t testing.TB, id *protocol.Identity, allowed ...string) *Authenticator {
	t.Helper()
	cfg := DefaultConfig()
	cfg.HandshakeTimeout = 2 * time.Second
	cfg.ReadTimeout = time.Second
	cfg.AllowedPeers = allowed
	a, err := NewAuthenticator(id, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type authResult struct {
	session *Session
	err     error
}
type recorder struct {
	net.Conn
	mu   sync.Mutex
	data bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	n, err := r.Conn.Write(p)
	r.mu.Lock()
	r.data.Write(p[:n])
	r.mu.Unlock()
	return n, err
}
func (r *recorder) snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.data.Bytes())
}

func connect(t *testing.T, server, client *Authenticator, pin string) (*Session, *Session, *recorder, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	accepted := make(chan authResult, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			accepted <- authResult{err: err}
			return
		}
		s, err := server.Server(ctx, raw)
		accepted <- authResult{s, err}
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	recorded := &recorder{Conn: raw}
	cs, clientErr := client.Client(ctx, recorded, pin)
	result := <-accepted
	if cs != nil {
		t.Cleanup(func() { cs.Close() })
	}
	if result.session != nil {
		t.Cleanup(func() { result.session.Close() })
	}
	if clientErr != nil {
		return cs, result.session, recorded, clientErr
	}
	return cs, result.session, recorded, result.err
}

func TestMutualAuthenticationAndEncryptedTCPExchange(t *testing.T) {
	alice, bob := identity(t), identity(t)
	client, server, wire, err := connect(t, auth(t, bob, alice.ID()), auth(t, alice, bob.ID()), bob.ID())
	if err != nil {
		t.Fatal(err)
	}
	if client.PeerID() != bob.ID() || server.PeerID() != alice.ID() {
		t.Fatal("wrong authenticated peers")
	}
	now := time.Now()
	message, err := protocol.NewMessage(alice, bob.ID(), []byte("private TCP payload"), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send(routing.Packet{Kind: routing.Data, Message: &message}); err != nil {
		t.Fatal(err)
	}
	packet, err := server.Receive()
	if err != nil {
		t.Fatal(err)
	}
	body, err := packet.Message.OpenBody(bob, now)
	if err != nil || string(body.Payload) != "private TCP payload" || body.Source != alice.ID() {
		t.Fatal("TCP delivery failed", err)
	}
	if err := server.Send(routing.Packet{Kind: routing.IHave, IDs: []string{message.MessageID}}); err != nil {
		t.Fatal(err)
	}
	response, err := client.Receive()
	if err != nil || response.Kind != routing.IHave {
		t.Fatal("response failed", err)
	}
	for _, plaintext := range []string{alice.ID(), bob.ID(), message.MessageID, "private TCP payload"} {
		if bytes.Contains(wire.snapshot(), []byte(plaintext)) {
			t.Fatalf("plaintext leaked onto TCP wire: %q", plaintext)
		}
	}
}

func TestRejectWrongPinAndUnapprovedPeer(t *testing.T) {
	alice, bob, mallory := identity(t), identity(t), identity(t)
	if _, _, _, err := connect(t, auth(t, bob, alice.ID()), auth(t, alice), mallory.ID()); err == nil {
		t.Fatal("wrong server pin accepted")
	}
	if _, _, _, err := connect(t, auth(t, bob), auth(t, alice), bob.ID()); err == nil {
		t.Fatal("unapproved client accepted")
	}
}

func TestOpenAdmissionStillPinsOutboundIdentity(t *testing.T) {
	alice, bob, mallory := identity(t), identity(t), identity(t)
	cfg := DefaultConfig()
	cfg.AllowUnknownPeers = true
	server, err := NewAuthenticator(bob, cfg)
	if err != nil {
		t.Fatal(err)
	}
	client, accepted, _, err := connect(t, server, auth(t, alice), bob.ID())
	if err != nil {
		t.Fatal("open admission rejected an authenticated peer", err)
	}
	if client.PeerID() != bob.ID() || accepted.PeerID() != alice.ID() {
		t.Fatal("incorrect authenticated identities")
	}
	if _, _, _, err := connect(t, server, auth(t, alice), mallory.ID()); err == nil {
		t.Fatal("open admission bypassed the outbound pin")
	}
}

func TestCertificateIdentityBinding(t *testing.T) {
	alice, bob := identity(t), identity(t)
	cert, err := alice.TransportCertificate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificateID([]*x509.Certificate{cert.Leaf}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := certificateID([]*x509.Certificate{cert.Leaf}, cert.Leaf.NotAfter); err == nil {
		t.Fatal("expired certificate accepted")
	}
	// Sign a new certificate carrying Bob's ID using Alice's actual signing key.
	template := *cert.Leaf
	uri := *template.URIs[0]
	uri.Opaque = bob.ID()
	template.URIs = append(template.URIs[:0:0], &uri)
	key := cert.PrivateKey.(ed25519.PrivateKey)
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificateID([]*x509.Certificate{forged}, time.Now()); err == nil {
		t.Fatal("identity/certificate key mismatch accepted")
	}
}

func TestTLSAloneCannotSendRoutingPackets(t *testing.T) {
	for _, open := range []bool{false, true} {
		name := "allowlist"
		if open {
			name = "open admission"
		}
		t.Run(name, func(t *testing.T) { testTLSAloneCannotSendRoutingPackets(t, open) })
	}
}

func testTLSAloneCannotSendRoutingPackets(t *testing.T, open bool) {
	alice, bob := identity(t), identity(t)
	a, b := auth(t, alice), auth(t, bob, alice.ID())
	if open {
		b.config.AllowUnknownPeers = true
		b.allowed = make(map[string]bool)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		session, err := b.Server(context.Background(), raw)
		if session != nil {
			session.Close()
		}
		result <- err
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	client := tls.Client(raw, a.tlsConfig(bob.ID(), false))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(client, framePacket, []byte(`{"kind":"DATA"}`)); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("routing accepted before both-key proof")
	}
}

func TestCapturedProofCannotAuthenticateAnotherTLSSession(t *testing.T) {
	alice, bob := identity(t), identity(t)
	a, b := auth(t, alice), auth(t, bob, alice.ID())
	var captured protocol.Proof
	for attempt := 0; attempt < 2; attempt++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serverResult := make(chan error, 1)
		go func() {
			raw, err := listener.Accept()
			if err != nil {
				serverResult <- err
				return
			}
			s, err := b.Server(context.Background(), raw)
			if s != nil {
				s.Close()
			}
			serverResult <- err
		}()
		raw, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		client := tls.Client(raw, a.tlsConfig(bob.ID(), false))
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := client.HandshakeContext(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		state := client.ConnectionState()
		material, err := state.ExportKeyingMaterial("EXPORTER-WEFT-POI-v1", []byte(ALPN), 32)
		if err != nil {
			t.Fatal(err)
		}
		var binding [32]byte
		copy(binding[:], material)
		challenge, pending, err := protocol.NewChallenge(alice, bob.ID(), binding, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := sendJSON(client, frameChallenge, challenge); err != nil {
			t.Fatal(err)
		}
		var proof protocol.Proof
		if err := receiveJSON(client, frameProof, &proof); err != nil {
			t.Fatal(err)
		}
		if err := pending.Verify(proof, binding, time.Now()); err != nil {
			t.Fatal(err)
		}
		var serverChallenge protocol.Challenge
		if err := receiveJSON(client, frameChallenge, &serverChallenge); err != nil {
			t.Fatal(err)
		}
		if attempt == 0 {
			captured, err = protocol.AnswerChallenge(alice, serverChallenge, bob.ID(), binding, time.Now())
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := sendJSON(client, frameProof, captured); err != nil {
			t.Fatal(err)
		}
		kind, _, readErr := readFrame(client)
		serverErr := <-serverResult
		cancel()
		raw.Close()
		listener.Close()
		if attempt == 0 && (readErr != nil || kind != frameReady || serverErr != nil) {
			t.Fatal("valid proof rejected", readErr, serverErr)
		}
		if attempt == 1 && (readErr == nil || serverErr == nil) {
			t.Fatal("captured proof accepted in a new TLS session")
		}
	}
}

func TestRejectTransportDowngradeAndWrongALPN(t *testing.T) {
	for _, name := range []string{"old TLS", "wrong ALPN"} {
		t.Run(name, func(t *testing.T) {
			alice, bob := identity(t), identity(t)
			a, b := auth(t, alice), auth(t, bob, alice.ID())
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			result := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					result <- err
					return
				}
				s, err := b.Server(context.Background(), raw)
				if s != nil {
					s.Close()
				}
				result <- err
			}()
			raw, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			config := a.tlsConfig(bob.ID(), false)
			if name == "old TLS" {
				config.MinVersion = tls.VersionTLS12
				config.MaxVersion = tls.VersionTLS12
			} else {
				config.NextProtos = []string{"other/1"}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := tls.Client(raw, config).HandshakeContext(ctx); err == nil {
				t.Fatal("incompatible transport accepted")
			}
			if err := <-result; err == nil {
				t.Fatal("server accepted incompatible transport")
			}
		})
	}
}

func TestHandshakeDeadlineAndCancellation(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		a := auth(t, identity(t))
		a.config.HandshakeTimeout = 150 * time.Millisecond
		local, remote := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		if cancelEarly {
			cancel()
		}
		start := time.Now()
		_, err := a.Server(ctx, local)
		cancel()
		remote.Close()
		if err == nil || time.Since(start) > time.Second {
			t.Fatal("stalled handshake not bounded", err)
		}
	}
}

func TestOversizedFrameAndIdlePeerClosed(t *testing.T) {
	alice, bob := identity(t), identity(t)
	client, server, _, err := connect(t, auth(t, bob, alice.ID()), auth(t, alice), bob.ID())
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, headerSize)
	copy(header, "WEFT")
	header[4], header[5] = wireVersion, framePacket
	binary.BigEndian.PutUint32(header[8:], uint32(routing.MaxPacketBytes+1))
	if _, err := client.conn.Write(header); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Receive(); err == nil {
		t.Fatal("oversized frame accepted")
	}
	client, server, _, err = connect(t, auth(t, bob, alice.ID()), auth(t, alice), bob.ID())
	if err != nil {
		t.Fatal(err)
	}
	server.config.ReadTimeout = 100 * time.Millisecond
	if _, err := server.Receive(); err == nil {
		t.Fatal("idle connection did not time out")
	}
}

func TestControlFramesAreRateLimited(t *testing.T) {
	alice, bob := identity(t), identity(t)
	client, server, _, err := connect(t, auth(t, bob, alice.ID()), auth(t, alice), bob.ID())
	if err != nil {
		t.Fatal(err)
	}
	server.config.MaxFramesPerMinute = 1
	if err := client.send(framePong, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.send(framePong, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Receive(); err == nil || !strings.Contains(err.Error(), "rate") {
		t.Fatal("control flood not limited", err)
	}
}

func TestFrameFragmentationAndTruncation(t *testing.T) {
	var wire bytes.Buffer
	data, _ := json.Marshal(map[string]string{"test": "framing"})
	if err := writeFrame(&wire, frameChallenge, data); err != nil {
		t.Fatal(err)
	}
	encoded := bytes.Clone(wire.Bytes())
	for size := 0; size < len(encoded); size++ {
		if _, _, err := readFrame(bytes.NewReader(encoded[:size])); err == nil {
			t.Fatal("truncated frame accepted")
		}
	}
	kind, parsed, err := readFrame(&byteReader{reader: bytes.NewReader(encoded)})
	if err != nil || kind != frameChallenge || !bytes.Equal(parsed, data) {
		t.Fatal("fragmentation failed", err)
	}
	for _, offset := range []int{0, 4, 5, 6, 7} {
		bad := bytes.Clone(encoded)
		bad[offset] = 255
		if _, _, err := readFrame(bytes.NewReader(bad)); err == nil {
			t.Fatal("bad header accepted")
		}
	}
}

type byteReader struct{ reader io.Reader }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.reader.Read(p)
}

func FuzzReadFrame(f *testing.F) {
	var valid bytes.Buffer
	_ = writeFrame(&valid, framePing, nil)
	f.Add(valid.Bytes())
	f.Add([]byte("WEFT"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _ = readFrame(bytes.NewReader(data)) })
}
