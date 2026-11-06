package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"weft/internal/portmap"
	"weft/node"
	"weft/protocol"
)

// JSON escaping can require six bytes per payload byte, plus command metadata.
const commandLimit = 6*protocol.MaxPayloadBytes + 1024

type localCommand struct {
	name   string
	peer   peerEndpoint
	target string
	text   string
}

type quitEvent struct{}

func parseCommand(line []byte) (localCommand, error) {
	var command localCommand
	if len(line) > commandLimit {
		return command, errors.New("command too large")
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return command, nil
	}
	var payload []byte
	if line[0] == '{' {
		// Retain compatibility with the original bare message JSON syntax.
		command.name, payload = "message", line
	} else {
		name, data, hasPayload := strings.Cut(string(line), ":")
		command.name = strings.TrimSpace(name)
		payload = []byte(data)
		if !hasPayload {
			switch command.name {
			case "peers", "status", "help", "quit":
				payload = []byte("{}")
			default:
				return command, errors.New("expected command:JSON; type help for commands")
			}
		}
	}
	// Require an object even for commands with no arguments. JSON null would
	// otherwise silently decode into an empty struct.
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 || payload[0] != '{' {
		return command, errors.New("command payload must be a JSON object")
	}
	switch command.name {
	case "connect":
		if err := protocol.DecodeJSON(payload, &command.peer, commandLimit); err != nil {
			return command, err
		}
		return command, command.peer.validate()
	case "disconnect":
		var data struct {
			ID string `json:"id"`
		}
		if err := protocol.DecodeJSON(payload, &data, commandLimit); err != nil {
			return command, err
		}
		command.peer.ID = data.ID
		_, err := protocol.ParseID(data.ID)
		return command, err
	case "message":
		var data struct {
			Target string  `json:"target"`
			Text   *string `json:"text"`
		}
		if err := protocol.DecodeJSON(payload, &data, commandLimit); err != nil {
			return command, err
		}
		if _, err := protocol.ParseID(data.Target); err != nil {
			return command, err
		}
		if data.Text == nil {
			return command, errors.New("message requires a text string")
		}
		if len(*data.Text) > protocol.MaxPayloadBytes {
			return command, errors.New("message text exceeds payload limit")
		}
		command.target, command.text = data.Target, *data.Text
	case "peers", "status", "help", "quit":
		if err := protocol.DecodeJSON(payload, &struct{}{}, commandLimit); err != nil {
			return command, err
		}
	default:
		return command, fmt.Errorf("unknown command %q; type help for commands", command.name)
	}
	return command, nil
}

func executeCommand(ctx context.Context, command localCommand, id *protocol.Identity, n *node.Node, manager *peerManager, mapper *portmap.Manager, emit func(context.Context, any)) error {
	switch command.name {
	case "":
		return nil
	case "connect":
		if err := manager.Connect(command.peer); err != nil {
			return err
		}
		emit(ctx, map[string]string{"event": "peer_configured", "peer": command.peer.ID, "ip": command.peer.Address})
	case "disconnect":
		if err := manager.Disconnect(command.peer.ID); err != nil {
			return err
		}
		emit(ctx, map[string]string{"event": "disconnected", "peer": command.peer.ID})
	case "message":
		message, err := protocol.NewMessage(id, command.target, []byte(command.text), time.Now(), protocol.DefaultLifetime)
		if err != nil {
			return err
		}
		if err := n.Publish(ctx, message); err != nil {
			return err
		}
		emit(ctx, map[string]string{"event": "queued", "messageID": message.MessageID, "target": message.Target})
	case "peers":
		emit(ctx, map[string]any{"event": "peers", "peers": n.Peers(), "configured": manager.Endpoints()})
	case "status":
		emit(ctx, map[string]any{"event": "status", "id": n.ID(), "address": n.Address(), "peers": n.Peers(), "configured": manager.Endpoints(), "nat": mapper.Status()})
	case "help":
		emit(ctx, map[string]any{"event": "help", "commands": []string{
			`connect:{"id":"<peer ID>","ip":"<host:port>"}`,
			`disconnect:{"id":"<peer ID>"}`,
			`message:{"target":"<recipient ID>","text":"<message>"}`,
			"peers", "status", "help", "quit",
		}})
	case "quit":
		emit(ctx, quitEvent{})
	}
	return nil
}
