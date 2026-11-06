// demp runs a real DEMP TCP node. Local commands use command:JSON lines on
// stdin; the network uses TLS-secured DEMP binary frames, never HTTP.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"demp/internal/portmap"
	"demp/node"
	"demp/protocol"
)

type stringsFlag []string

func (s *stringsFlag) String() string         { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(value string) error { *s = append(*s, value); return nil }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func password() ([]byte, error) {
	value := []byte(os.Getenv("DEMP_KEY_PASSWORD"))
	_ = os.Unsetenv("DEMP_KEY_PASSWORD")
	if len(value) < 12 {
		return nil, errors.New("set DEMP_KEY_PASSWORD to a strong passphrase of at least 12 bytes")
	}
	return value, nil
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: demp keygen|id|run -key FILE (run: -listen ADDR -nat auto|off -allow ID|any -peer ID@ADDR)")
	}
	command := args[0]
	if command != "keygen" && command != "id" && command != "run" {
		return errors.New("unknown command; use keygen, id, or run")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	path := fs.String("key", "", "encrypted identity key file")
	listen := fs.String("listen", "0.0.0.0:9000", "TCP listen address; empty for outbound-only")
	natMode := fs.String("nat", "auto", "router TCP port mapping: auto or off")
	var allowed, peers stringsFlag
	fs.Var(&allowed, "allow", "allowed inbound DEMP ID, or any for open admission with both-key authentication (repeatable)")
	fs.Var(&peers, "peer", "pinned peer ID@host:port to maintain (repeatable)")
	allowUnknown := fs.Bool("allow-unknown", false, "alias for -allow any; still requires both-key authentication")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" || fs.NArg() != 0 {
		return errors.New("a -key file is required; unexpected positional arguments are rejected")
	}
	if err := portmap.ValidateMode(*natMode); err != nil {
		return err
	}
	secret, err := password()
	if err != nil {
		return err
	}
	defer clear(secret)
	if command == "keygen" {
		id, err := protocol.GenerateIdentity()
		if err != nil {
			return err
		}
		if err := id.SaveEncrypted(*path, secret); err != nil {
			return err
		}
		fmt.Println(id.ID())
		return nil
	}
	id, err := protocol.LoadIdentity(*path, secret)
	if err != nil {
		return err
	}
	clear(secret)
	if command == "id" {
		fmt.Println(id.ID())
		return nil
	}
	cfg := node.DefaultConfig()
	cfg.ListenAddress = *listen
	cfg.Transport.AllowUnknownPeers = *allowUnknown
	for _, value := range allowed {
		if value == "any" {
			cfg.Transport.AllowUnknownPeers = true
		} else {
			cfg.Transport.AllowedPeers = append(cfg.Transport.AllowedPeers, value)
		}
	}
	var endpoints []peerEndpoint
	for _, value := range peers {
		peer, address, ok := strings.Cut(value, "@")
		if !ok {
			return errors.New("peer must be ID@host:port")
		}
		endpoint := peerEndpoint{ID: peer, Address: address}
		if err := endpoint.validate(); err != nil {
			return err
		}
		endpoints = append(endpoints, endpoint)
		cfg.Transport.AllowedPeers = append(cfg.Transport.AllowedPeers, peer)
	}
	return runNode(ctx, id, cfg, endpoints, *natMode, os.Stdin, os.Stdout, os.Stderr)
}

// runNode owns input and closes it to unblock the scanner during shutdown.
func runNode(ctx context.Context, id *protocol.Identity, cfg node.Config, endpoints []peerEndpoint, natMode string, input io.ReadCloser, stdout, stderr io.Writer) error {
	n, err := node.New(id, cfg)
	if err != nil {
		return err
	}
	if err := n.Start(); err != nil {
		n.Close()
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	events := make(chan any, 16)
	emit := func(eventCtx context.Context, event any) {
		select {
		case events <- event:
		case <-eventCtx.Done():
		}
	}
	manager := newPeerManager(ctx, n, cfg.Router.MaxPeers, emit)
	var natCleanupErr error
	defer func() {
		cancel()
		input.Close()
		manager.Close()
		n.Close()
		workers.Wait()
		if natCleanupErr != nil {
			fmt.Fprintln(stderr, "NAT cleanup:", natCleanupErr)
		}
	}()
	mapper, err := portmap.New(natMode, n.Address(), func(status portmap.Status) {
		emit(ctx, struct {
			Event string `json:"event"`
			portmap.Status
		}{"nat", status})
	})
	if err != nil {
		return err
	}
	output := json.NewEncoder(stdout)
	if err := output.Encode(map[string]any{"event": "listening", "id": n.ID(), "address": n.Address()}); err != nil {
		return err
	}
	for _, endpoint := range endpoints {
		if err := manager.Connect(endpoint); err != nil {
			return err
		}
	}
	workers.Go(func() { natCleanupErr = mapper.Run(ctx) })
	workers.Go(func() {
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 4096), commandLimit)
		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}
			command, err := parseCommand(scanner.Bytes())
			if err == nil {
				err = executeCommand(ctx, command, id, n, manager, mapper, emit)
			}
			if err != nil {
				emit(ctx, err)
			}
			if err == nil && command.name == "quit" {
				return
			}
		}
		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			emit(ctx, err)
		}
	})
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-n.Errors():
			fmt.Fprintln(stderr, err)
		case delivery := <-n.Deliveries():
			if err := output.Encode(map[string]any{"event": "message", "messageID": delivery.MessageID, "source": delivery.Body.Source, "text": string(delivery.Body.Payload)}); err != nil {
				return err
			}
		case event := <-events:
			switch event := event.(type) {
			case error:
				fmt.Fprintln(stderr, event)
			case quitEvent:
				return output.Encode(map[string]string{"event": "stopping"})
			default:
				if err := output.Encode(event); err != nil {
					return err
				}
			}
		}
	}
}
