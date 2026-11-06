package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

var encoding = base64.RawURLEncoding.Strict()

func encode(b []byte) string { return encoding.EncodeToString(b) }

func decode(s string, size int) ([]byte, error) {
	if len(s) != encoding.EncodedLen(size) {
		return nil, errors.New("invalid encoded length")
	}
	b, err := encoding.DecodeString(s)
	if err != nil || len(b) != size || encode(b) != s {
		return nil, errors.New("invalid canonical base64url")
	}
	return b, nil
}

// field encodes a byte string as an unsigned big-endian uint32 length and bytes.
func field(dst *bytes.Buffer, value []byte) {
	_ = binary.Write(dst, binary.BigEndian, uint32(len(value)))
	dst.Write(value)
}

// DecodeJSON rejects oversized input, duplicate keys (including case aliases),
// unknown fields, invalid UTF-8, excessive nesting, and trailing JSON values.
func DecodeJSON(data []byte, dst any, limit int) error {
	if len(data) > limit || !utf8.Valid(data) {
		return errors.New("invalid JSON size or UTF-8")
	}
	scanner := json.NewDecoder(bytes.NewReader(data))
	if err := scanValue(scanner, 0); err != nil {
		return err
	}
	if _, err := scanner.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

func scanValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			name = strings.ToLower(name)
			if seen[name] {
				return fmt.Errorf("duplicate JSON key: %s", name)
			}
			seen[name] = true
			if err := scanValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := scanValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}
