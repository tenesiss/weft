package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"demp/protocol"
	"demp/routing"
)

type Config struct {
	HandshakeTimeout   time.Duration
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	MaxFramesPerMinute int
	AllowedPeers       []string
	AllowUnknownPeers  bool
}

func DefaultConfig() Config {
	return Config{HandshakeTimeout: 10 * time.Second, ReadTimeout: 45 * time.Second, WriteTimeout: 5 * time.Second, MaxFramesPerMinute: 240}
}

// Authenticator uses pinned identities for outbound connections and an explicit
// inbound allowlist (unless AllowUnknownPeers is deliberately enabled).
type Authenticator struct {
	identity    *protocol.Identity
	config      Config
	allowed     map[string]bool
	mu          sync.Mutex
	certificate tls.Certificate
}

func NewAuthenticator(identity *protocol.Identity, config Config) (*Authenticator, error) {
	if identity.ID() == "" || config.HandshakeTimeout <= 0 || config.ReadTimeout <= 0 || config.WriteTimeout <= 0 || config.MaxFramesPerMinute < 1 {
		return nil, errors.New("invalid transport configuration")
	}
	a := &Authenticator{identity: identity, config: config, allowed: make(map[string]bool)}
	for _, id := range config.AllowedPeers {
		if _, err := protocol.ParseID(id); err != nil {
			return nil, err
		}
		if id == identity.ID() {
			return nil, errors.New("cannot allow self as peer")
		}
		a.allowed[id] = true
	}
	if _, err := a.getCertificate(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Authenticator) getCertificate() (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.certificate.Leaf == nil || time.Until(a.certificate.Leaf.NotAfter) < time.Hour {
		certificate, err := a.identity.TransportCertificate(time.Now())
		if err != nil {
			return nil, err
		}
		a.certificate = certificate
	}
	copy := a.certificate
	return &copy, nil
}

// certificateID replaces Web PKI validation with DEMP's self-certifying ID.
// TLS subsequently verifies possession of this certificate's Ed25519 key.
func certificateID(certificates []*x509.Certificate, now time.Time) (string, error) {
	if len(certificates) != 1 {
		return "", errors.New("expected exactly one DEMP certificate")
	}
	cert := certificates[0]
	if len(cert.Raw) > 4096 || cert.IsCA || len(cert.UnhandledCriticalExtensions) != 0 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return "", errors.New("invalid or expired DEMP certificate")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 2 {
		return "", errors.New("invalid DEMP certificate usage")
	}
	server, client := false, false
	for _, usage := range cert.ExtKeyUsage {
		server = server || usage == x509.ExtKeyUsageServerAuth
		client = client || usage == x509.ExtKeyUsageClientAuth
	}
	if !server || !client {
		return "", errors.New("DEMP certificate must allow both peer roles")
	}
	if len(cert.URIs) != 1 || cert.URIs[0].Scheme != "demp" || cert.URIs[0].String() != "demp:"+cert.URIs[0].Opaque {
		return "", errors.New("missing DEMP identity in certificate")
	}
	id := cert.URIs[0].Opaque
	public, err := protocol.ParseID(id)
	if err != nil {
		return "", err
	}
	key, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(key, public.SigningKey) || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return "", errors.New("certificate key does not match DEMP identity")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return "", fmt.Errorf("invalid self-signature: %w", err)
	}
	return id, nil
}

func (a *Authenticator) tlsConfig(expected string, server bool) *tls.Config {
	config := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{ALPN}, SessionTicketsDisabled: true,
		GetCertificate:       func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return a.getCertificate() },
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return a.getCertificate() },
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != ALPN {
				return errors.New("TLS 1.3 and DEMP ALPN required")
			}
			id, err := certificateID(state.PeerCertificates, time.Now())
			if err != nil {
				return err
			}
			if id == a.identity.ID() {
				return errors.New("self connection rejected")
			}
			if expected != "" && id != expected {
				return errors.New("peer identity does not match pin")
			}
			if server && !a.allowed[id] && !a.config.AllowUnknownPeers {
				return errors.New("peer is not allowed")
			}
			return nil
		},
	}
	if server {
		config.ClientAuth = tls.RequireAnyClientCert
	} else {
		// Hostname/CA checks are intentionally replaced by mandatory identity
		// pinning and full self-certificate validation in VerifyConnection above.
		config.InsecureSkipVerify = true
	}
	return config
}

// Client takes ownership of raw, closing it on any authentication failure.
// expected is mandatory and must be obtained through trusted contact exchange.
func (a *Authenticator) Client(ctx context.Context, raw net.Conn, expected string) (*Session, error) {
	if _, err := protocol.ParseID(expected); err != nil {
		raw.Close()
		return nil, err
	}
	return a.authenticate(ctx, raw, expected, false)
}

// Server takes ownership of raw and admits it only after mutual TLS and POI.
func (a *Authenticator) Server(ctx context.Context, raw net.Conn) (*Session, error) {
	return a.authenticate(ctx, raw, "", true)
}

func (a *Authenticator) authenticate(ctx context.Context, raw net.Conn, expected string, server bool) (_ *Session, err error) {
	ctx, cancel := context.WithTimeout(ctx, a.config.HandshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	defer func() {
		if err != nil {
			raw.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	if err = raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	var conn *tls.Conn
	if server {
		conn = tls.Server(raw, a.tlsConfig(expected, true))
	} else {
		conn = tls.Client(raw, a.tlsConfig(expected, false))
	}
	if err = conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	state := conn.ConnectionState()
	id, err := certificateID(state.PeerCertificates, time.Now())
	if err != nil {
		return nil, err
	}
	material, err := state.ExportKeyingMaterial("EXPORTER-DEMP-POI-v1", []byte(ALPN), 32)
	if err != nil {
		return nil, err
	}
	var binding [32]byte
	copy(binding[:], material)
	if err = a.proveKeys(conn, id, binding, server); err != nil {
		return nil, fmt.Errorf("DEMP authentication: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if !stop() {
		return nil, errors.New("authentication canceled")
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &Session{conn: conn, peer: id, outbound: !server, config: a.config}, nil
}

func sendJSON(conn net.Conn, kind byte, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeFrame(conn, kind, data)
}

func receiveJSON(conn net.Conn, expected byte, value any) error {
	kind, data, err := readFrame(conn)
	if err != nil {
		return err
	}
	if kind != expected {
		return errors.New("unexpected authentication frame")
	}
	limit, _ := frameLimit(kind)
	return protocol.DecodeJSON(data, value, limit)
}

func (a *Authenticator) proveKeys(conn net.Conn, peer string, binding [32]byte, server bool) error {
	challenge, pending, err := protocol.NewChallenge(a.identity, peer, binding, time.Now())
	if err != nil {
		return err
	}
	var incoming protocol.Challenge
	var proof protocol.Proof
	if !server {
		if err := sendJSON(conn, frameChallenge, challenge); err != nil {
			return err
		}
		if err := receiveJSON(conn, frameProof, &proof); err != nil {
			return err
		}
		if err := pending.Verify(proof, binding, time.Now()); err != nil {
			return err
		}
		if err := receiveJSON(conn, frameChallenge, &incoming); err != nil {
			return err
		}
		answer, err := protocol.AnswerChallenge(a.identity, incoming, peer, binding, time.Now())
		if err != nil {
			return err
		}
		if err := sendJSON(conn, frameProof, answer); err != nil {
			return err
		}
		kind, data, err := readFrame(conn)
		if err != nil {
			return err
		}
		if kind != frameReady || len(data) != 0 {
			return errors.New("missing authentication completion")
		}
		return nil
	}
	if err := receiveJSON(conn, frameChallenge, &incoming); err != nil {
		return err
	}
	answer, err := protocol.AnswerChallenge(a.identity, incoming, peer, binding, time.Now())
	if err != nil {
		return err
	}
	if err := sendJSON(conn, frameProof, answer); err != nil {
		return err
	}
	if err := sendJSON(conn, frameChallenge, challenge); err != nil {
		return err
	}
	if err := receiveJSON(conn, frameProof, &proof); err != nil {
		return err
	}
	if err := pending.Verify(proof, binding, time.Now()); err != nil {
		return err
	}
	return writeFrame(conn, frameReady, nil)
}

// Session exposes routing packets only after both peers prove both keys. One
// goroutine may Receive at a time; Send and Ping may be called concurrently.
type Session struct {
	conn     *tls.Conn
	peer     string
	outbound bool
	config   Config
	writeMu  sync.Mutex
	window   time.Time
	frames   int
}

func (s *Session) PeerID() string { return s.peer }
func (s *Session) Outbound() bool { return s.outbound }
func (s *Session) Close() error   { return s.conn.NetConn().Close() }

func (s *Session) send(kind byte, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout)); err != nil {
		return err
	}
	if err := writeFrame(s.conn, kind, data); err != nil {
		s.Close()
		return err
	}
	return nil
}

func (s *Session) Send(packet routing.Packet) error {
	data, err := packet.Marshal()
	if err != nil {
		return err
	}
	return s.send(framePacket, data)
}

func (s *Session) Ping() error { return s.send(framePing, nil) }

func (s *Session) Receive() (routing.Packet, error) {
	for {
		if err := s.conn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout)); err != nil {
			return routing.Packet{}, err
		}
		kind, data, err := readFrame(s.conn)
		if err != nil {
			s.Close()
			return routing.Packet{}, err
		}
		now := time.Now()
		if s.window.IsZero() || now.Sub(s.window) >= time.Minute {
			s.window, s.frames = now, 0
		}
		s.frames++
		if s.frames > s.config.MaxFramesPerMinute {
			s.Close()
			return routing.Packet{}, errors.New("transport frame rate exceeded")
		}
		switch kind {
		case framePacket:
			packet, err := routing.DecodePacket(data)
			if err != nil {
				s.Close()
			}
			return packet, err
		case framePing:
			if err := s.send(framePong, nil); err != nil {
				return routing.Packet{}, err
			}
		case framePong:
		default:
			s.Close()
			return routing.Packet{}, errors.New("authentication frame after session established")
		}
	}
}
