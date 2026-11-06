package main

import (
	"fmt"
	"strings"
	"testing"

	"demp/protocol"
)

func testIdentity(t *testing.T) *protocol.Identity {
	t.Helper()
	id, err := protocol.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestParseCommands(t *testing.T) {
	id := testIdentity(t).ID()
	for _, test := range []struct {
		line string
		name string
	}{
		{" \t", ""},
		{`connect:{"id":"` + id + `","ip":"127.0.0.1:9000"}`, "connect"},
		{` connect : {"id":"` + id + `","ip":"[::1]:9000"} `, "connect"},
		{`connect:{"id":"` + id + `","ip":"localhost:9000"}`, "connect"},
		{`disconnect:{"id":"` + id + `"}`, "disconnect"},
		{`message:{"target":"` + id + `","text":"hello: 世界\nnext line"}`, "message"},
		{`{"target":"` + id + `","text":"legacy: message"}`, "message"},
		{`message:{"target":"` + id + `","text":""}`, "message"},
		{"peers", "peers"}, {"status:{}", "status"}, {"help", "help"}, {"quit:{}", "quit"},
	} {
		t.Run(test.line, func(t *testing.T) {
			command, err := parseCommand([]byte(test.line))
			if err != nil || command.name != test.name {
				t.Fatalf("parse = %+v, %v", command, err)
			}
			if command.name == "message" && command.target != id {
				t.Fatal("lost message target")
			}
			if command.name == "connect" && command.peer.ID != id {
				t.Fatal("lost peer identity")
			}
		})
	}
	command, err := parseCommand([]byte(`message:{"target":"` + id + `","text":"hello: 世界\nnext line"}`))
	if err != nil || command.text != "hello: 世界\nnext line" {
		t.Fatal("message text did not survive parsing", err)
	}
}

func TestRejectInvalidCommands(t *testing.T) {
	id := testIdentity(t).ID()
	for i, line := range []string{
		`connect`, `connect:`, `connect:null`, `connect:[]`, `unknown:{}`,
		`connect:{}`, `connect:{"id":"bad","ip":"127.0.0.1:9000"}`,
		`connect:{"id":"` + id + `","ip":"127.0.0.1"}`,
		`connect:{"id":"` + id + `","ip":":9000"}`,
		`connect:{"id":"` + id + `","ip":"localhost:0"}`,
		`connect:{"id":"` + id + `","ip":"localhost:65536"}`,
		`connect:{"id":"` + id + `","ip":"localhost:+9000"}`,
		`connect:{"id":"` + id + `","ip":"localhost:http"}`,
		`connect:{"id":"` + id + `","ip":"127.0.0.1:9000","text":"extra"}`,
		`connect:{"id":"` + id + `","ID":"` + id + `","ip":"127.0.0.1:9000"}`,
		`disconnect:{}`, `disconnect:{"id":"` + id + `","ip":"127.0.0.1:9000"}`,
		`message:{"target":"` + id + `"}`,
		`message:{"target":"` + id + `","text":null}`,
		`message:{"target":"` + id + `","text":12}`,
		`message:{"target":"bad","text":"hello"}`,
		`message:{"target":"` + id + `","text":"hello","text":"again"}`,
		`message:{"target":"` + id + `","text":"hello"} {}`,
		`message:{"target":"` + id + `","text":"` + strings.Repeat("x", protocol.MaxPayloadBytes+1) + `"}`,
		`message:{"target":"` + id + `","text":"` + string([]byte{255}) + `"}`,
		`peers:null`, `peers:{"id":"` + id + `"}`, `status:`, `quit:{"force":true}`,
		strings.Repeat(" ", commandLimit+1),
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := parseCommand([]byte(line)); err == nil {
				t.Fatal("invalid command accepted")
			}
		})
	}
}
