package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"weft/node"
	"weft/protocol"
)

// Run the actual CLI entry point in a subprocess so flags, password handling,
// stdin cancellation, and JSON events are tested without replacing global I/O.
func TestCLIProcess(t *testing.T) {
	if os.Getenv("WEFT_CLI_TEST") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if err := run(context.Background(), os.Args[separator+1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

type cliProcess struct {
	input  io.WriteCloser
	events chan map[string]json.RawMessage
	done   chan struct{}
	cancel context.CancelFunc
	stderr bytes.Buffer
	err    error
}

func startCLI(t *testing.T, id *protocol.Identity, flags ...string) *cliProcess {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.key.json")
	const passphrase = "test CLI passphrase"
	if err := id.SaveEncrypted(path, []byte(passphrase)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	args := append([]string{"-test.run=^TestCLIProcess$", "--", "run", "-key", path, "-listen", "127.0.0.1:0"}, flags...)
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(os.Environ(), "WEFT_CLI_TEST=1", "WEFT_KEY_PASSWORD="+passphrase)
	p := &cliProcess{events: make(chan map[string]json.RawMessage, 64), done: make(chan struct{}), cancel: cancel}
	cmd.Stderr = &p.stderr
	var err error
	p.input, err = cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() {
		defer close(p.done)
		defer close(p.events)
		decoder := json.NewDecoder(output)
		for {
			var event map[string]json.RawMessage
			if err := decoder.Decode(&event); err != nil {
				break
			}
			select {
			case p.events <- event:
			case <-ctx.Done():
			}
		}
		p.err = cmd.Wait()
	}()
	t.Cleanup(func() {
		cancel()
		p.input.Close()
		<-p.done
	})
	return p
}

func (p *cliProcess) send(t *testing.T, line string) {
	t.Helper()
	if _, err := fmt.Fprintln(p.input, line); err != nil {
		t.Fatal(err)
	}
}

func (p *cliProcess) event(t *testing.T, name string) map[string]json.RawMessage {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event, ok := <-p.events:
			if !ok {
				<-p.done
				t.Fatalf("CLI exited waiting for %s: %v; stderr: %s", name, p.err, &p.stderr)
			}
			if string(event["event"]) == `"`+name+`"` {
				return event
			}
		case <-timer.C:
			p.cancel()
			<-p.done
			t.Fatalf("timeout waiting for %s; stderr: %s", name, &p.stderr)
		}
	}
}

func (p *cliProcess) quit(t *testing.T) {
	t.Helper()
	p.send(t, "quit")
	p.event(t, "stopping")
	select {
	case <-p.done:
		if p.err != nil {
			t.Fatalf("CLI quit: %v; stderr: %s", p.err, &p.stderr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("quit did not stop the CLI")
	}
}

func TestRuntimeCommandsAndOpenAdmission(t *testing.T) {
	alice, bob := testIdentity(t), testIdentity(t)
	// A specific allow entry must remain valid alongside the any sentinel.
	server := startCLI(t, bob, "-allow", testIdentity(t).ID(), "-allow", "any")
	listening := server.event(t, "listening")
	var address string
	if err := json.Unmarshal(listening["address"], &address); err != nil {
		t.Fatal(err)
	}
	client := startCLI(t, alice)
	client.event(t, "listening")
	client.send(t, `connect:{"id":"`+bob.ID()+`","ip":"`+address+`"}`)
	client.event(t, "connected")
	client.send(t, "peers:{}")
	peers := client.event(t, "peers")
	var ids []string
	var configured []peerEndpoint
	if err := json.Unmarshal(peers["peers"], &ids); err != nil || !slices.Equal(ids, []string{bob.ID()}) {
		t.Fatal("wrong connected peer list", string(peers["peers"]), err)
	}
	if err := json.Unmarshal(peers["configured"], &configured); err != nil || len(configured) != 1 || configured[0].Address != address {
		t.Fatal("wrong configured endpoints", string(peers["configured"]), err)
	}
	client.send(t, `message:{"target":"`+bob.ID()+`","text":"hello: 世界"}`)
	client.event(t, "queued")
	delivery := server.event(t, "message")
	if string(delivery["source"]) != `"`+alice.ID()+`"` || string(delivery["text"]) != `"hello: 世界"` {
		t.Fatal("incorrect authenticated delivery", delivery)
	}
	// The original JSON-only message syntax remains usable in both directions.
	server.send(t, `{"target":"`+alice.ID()+`","text":"reply"}`)
	server.event(t, "queued")
	if got := client.event(t, "message"); string(got["text"]) != `"reply"` {
		t.Fatal("legacy message was lost", got)
	}
	// Removing the inbound session exercises the client's automatic retry loop.
	server.send(t, `disconnect:{"id":"`+alice.ID()+`"}`)
	server.event(t, "disconnected")
	client.event(t, "connected")
	client.send(t, `disconnect:{"id":"`+bob.ID()+`"}`)
	client.event(t, "disconnected")
	client.send(t, "peers")
	peers = client.event(t, "peers")
	if string(peers["peers"]) != "[]" || string(peers["configured"]) != "[]" {
		t.Fatal("disconnect retained active/configured peers", peers)
	}
	// A malformed command must not stop subsequent commands.
	client.send(t, `message:{"target":"bad","text":"invalid"}`)
	client.send(t, "help")
	client.event(t, "help")
	client.send(t, "status:{}")
	status := client.event(t, "status")
	if string(status["id"]) != `"`+alice.ID()+`"` {
		t.Fatal("status has wrong identity")
	}
	client.quit(t)
	if client.stderr.Len() == 0 {
		t.Fatal("invalid command was not reported")
	}
	server.quit(t)
}

func TestDisconnectStartupPeerAndKeepListeningAfterEOF(t *testing.T) {
	id, remote := testIdentity(t), testIdentity(t)
	cfg := node.DefaultConfig()
	cfg.Transport.AllowedPeers = []string{id.ID()}
	n, err := node.New(remote, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	client := startCLI(t, id, "-peer", remote.ID()+"@"+n.Address())
	listening := client.event(t, "listening")
	client.event(t, "connected")
	client.send(t, `disconnect:{"id":"`+remote.ID()+`"}`)
	client.event(t, "disconnected")
	client.send(t, "peers")
	if peers := client.event(t, "peers"); string(peers["configured"]) != "[]" || string(peers["peers"]) != "[]" {
		t.Fatal("startup retry loop was not removed", peers)
	}
	client.input.Close()
	var address string
	if err := json.Unmarshal(listening["address"], &address); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for len(n.Peers()) != 0 {
		select {
		case <-ctx.Done():
			t.Fatal("remote did not observe the disconnected session")
		case <-time.After(10 * time.Millisecond):
		}
	}
	// Disconnect does not ban an allowed peer, and EOF does not stop listening.
	if err := n.Connect(ctx, address, id.ID()); err != nil {
		t.Fatal("CLI stopped listening after EOF", err)
	}
	m, err := protocol.NewMessage(remote, id.ID(), []byte("after EOF"), time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Publish(ctx, m); err != nil {
		t.Fatal(err)
	}
	if got := client.event(t, "message"); string(got["text"]) != `"after EOF"` {
		t.Fatal("did not deliver after EOF", got)
	}
}

func TestCLINATModesAndStatus(t *testing.T) {
	for _, tc := range []struct{ name, listen, mode, state string }{
		{"default auto skips loopback", "127.0.0.1:0", "", "skipped"},
		{"explicit auto skips loopback", "127.0.0.1:0", "auto", "skipped"},
		{"outbound only", "", "", "skipped"},
		{"off with wildcard listener", "0.0.0.0:0", "off", "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := []string{"-listen", tc.listen}
			if tc.mode != "" {
				flags = append(flags, "-nat", tc.mode)
			}
			p := startCLI(t, testIdentity(t), flags...)
			p.event(t, "listening")
			event := p.event(t, "nat")
			mode := tc.mode
			if mode == "" {
				mode = "auto"
			}
			if string(event["mode"]) != `"`+mode+`"` || string(event["state"]) != `"`+tc.state+`"` {
				t.Fatal(event)
			}
			p.send(t, "status")
			status := p.event(t, "status")
			var nat struct{ Mode, State string }
			if err := json.Unmarshal(status["nat"], &nat); err != nil || nat.Mode != mode || nat.State != tc.state {
				t.Fatal("NAT state missing from status", string(status["nat"]), err)
			}
			p.quit(t)
		})
	}
}

func TestCLINATFlagValidationAndDefaults(t *testing.T) {
	// Check validation before password/key-file access.
	if err := run(context.Background(), []string{"run", "-key", "unused", "-nat", "invalid"}); err == nil || !strings.Contains(err.Error(), "-nat must be auto or off") {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIProcess$", "--", "run", "-h")
	cmd.Env = append(os.Environ(), "WEFT_CLI_TEST=1")
	help, _ := cmd.CombinedOutput()
	if !bytes.Contains(help, []byte(`default "0.0.0.0:9000"`)) || !bytes.Contains(help, []byte(`default "auto"`)) {
		t.Fatalf("wrong defaults: %s", help)
	}
}
