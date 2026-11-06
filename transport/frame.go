// Package transport carries DEMP frames over mutually authenticated TLS 1.3/TCP.
// It does not use HTTP, HTTPS, WebSockets, or an external messaging protocol.
package transport

import (
	"encoding/binary"
	"errors"
	"io"

	"demp/routing"
)

const (
	ALPN                = "demp/1"
	wireVersion    byte = 1
	frameChallenge byte = 1
	frameProof     byte = 2
	frameReady     byte = 3
	framePacket    byte = 16
	framePing      byte = 17
	framePong      byte = 18
	headerSize          = 12
)

func frameLimit(kind byte) (int, bool) {
	switch kind {
	case frameChallenge:
		return 4096, true
	case frameProof:
		return 1024, true
	case frameReady, framePing, framePong:
		return 0, true
	case framePacket:
		return routing.MaxPacketBytes, true
	default:
		return 0, false
	}
}

// readFrame validates type/length before allocating a payload. A deadline on
// the underlying connection must bound the whole frame, including slow reads.
func readFrame(r io.Reader) (byte, []byte, error) {
	var header [headerSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	if string(header[:4]) != "DEMP" || header[4] != wireVersion || header[6] != 0 || header[7] != 0 {
		return 0, nil, errors.New("invalid DEMP frame header")
	}
	kind := header[5]
	limit, known := frameLimit(kind)
	size := binary.BigEndian.Uint32(header[8:])
	if !known || uint64(size) > uint64(limit) {
		return 0, nil, errors.New("unknown or oversized DEMP frame")
	}
	if limit > 0 && size == 0 {
		return 0, nil, errors.New("empty DEMP data frame")
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(r, data); err != nil {
		return 0, nil, err
	}
	return kind, data, nil
}

func writeFrame(w io.Writer, kind byte, data []byte) error {
	limit, known := frameLimit(kind)
	if !known || len(data) > limit || (limit > 0 && len(data) == 0) {
		return errors.New("invalid outbound DEMP frame")
	}
	var header [headerSize]byte
	copy(header[:4], "DEMP")
	header[4], header[5] = wireVersion, kind
	binary.BigEndian.PutUint32(header[8:], uint32(len(data)))
	for _, part := range [][]byte{header[:], data} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n <= 0 || n > len(part) {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
