package hyperswarm

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	types "github.com/HORNET-Storage/hdk-nostr-go/lib"
	hsClient "github.com/hornet-storage/hornets-hyperswarm/clients/go/hyperswarm"
)

// StreamHandler is a callback for incoming protocol streams, matching the
// pattern used by the libp2p SetStreamHandler API.
type StreamHandler func(stream types.Stream)

// HyperswarmListener replaces a libp2p host for accepting incoming connections.
// It creates a DHT server via the sidecar and accepts incoming mux streams,
// routing them to registered protocol handlers via local TCP listeners.
type HyperswarmListener struct {
	client   *hsClient.Client
	serverID string

	handlers  map[string]StreamHandler
	listeners map[string]net.Listener // protocol -> local TCP listener
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	nextPort  int // next available port for protocol listeners
	portMu    sync.Mutex
}

// NewHyperswarmListener creates a listener backed by a hyperswarm sidecar.
// The client should already be connected to the sidecar and DHT initialized.
func NewHyperswarmListener(client *hsClient.Client) *HyperswarmListener {
	ctx, cancel := context.WithCancel(context.Background())
	return &HyperswarmListener{
		client:    client,
		handlers:  make(map[string]StreamHandler),
		listeners: make(map[string]net.Listener),
		ctx:       ctx,
		cancel:    cancel,
		nextPort:  0, // 0 = OS picks a port
	}
}

// CreateServer creates a DHT server on the sidecar with the given keypair.
// publicKey and secretKey are hex-encoded ed25519 keys.
// Returns the server ID.
func (hl *HyperswarmListener) CreateServer(publicKey, secretKey string) (string, error) {
	hl.mu.Lock()
	defer hl.mu.Unlock()

	result, err := hl.client.CreateServer(hsClient.CreateServerParams{
		PublicKey: publicKey,
		SecretKey: secretKey,
	})
	if err != nil {
		return "", fmt.Errorf("hyperswarm create server: %w", err)
	}
	hl.serverID = result.ServerID
	return result.ServerID, nil
}

// CreateServerFromSeed creates a DHT server using a deterministic seed.
func (hl *HyperswarmListener) CreateServerFromSeed(seed string) (string, string, error) {
	hl.mu.Lock()
	defer hl.mu.Unlock()

	kp, err := hl.client.GenerateKeyPair(seed)
	if err != nil {
		return "", "", fmt.Errorf("hyperswarm generate keypair: %w", err)
	}

	result, err := hl.client.CreateServer(hsClient.CreateServerParams{
		PublicKey: kp.PublicKey,
		SecretKey: kp.SecretKey,
	})
	if err != nil {
		return "", "", fmt.Errorf("hyperswarm create server: %w", err)
	}

	hl.serverID = result.ServerID
	return result.ServerID, kp.PublicKey, nil
}

// Reattach re-establishes the listener's sidecar-side state on a new client
// after the previous sidecar process or connection was lost. It recreates the
// DHT server from the deterministic seed (yielding the same public key as the
// original CreateServerFromSeed call) and re-registers every known protocol
// with the new sidecar, reusing the existing local TCP listeners so accept
// loops and registered handlers keep running untouched.
//
// The sidecar makes this safe to retry: create-server replaces a stale server
// entry holding the same public key, and register-protocol is an idempotent
// overwrite of the protocol -> local-port mapping. If any step fails, the
// listener keeps pointing at the previous client and the caller may retry.
func (hl *HyperswarmListener) Reattach(client *hsClient.Client, seed string) (string, string, error) {
	if client == nil {
		return "", "", fmt.Errorf("hyperswarm reattach: client is nil")
	}

	hl.mu.Lock()
	defer hl.mu.Unlock()

	select {
	case <-hl.ctx.Done():
		return "", "", fmt.Errorf("hyperswarm reattach: listener is closed")
	default:
	}

	kp, err := client.GenerateKeyPair(seed)
	if err != nil {
		return "", "", fmt.Errorf("hyperswarm reattach generate keypair: %w", err)
	}

	result, err := client.CreateServer(hsClient.CreateServerParams{
		PublicKey: kp.PublicKey,
		SecretKey: kp.SecretKey,
	})
	if err != nil {
		return "", "", fmt.Errorf("hyperswarm reattach create server: %w", err)
	}

	for protocol, listener := range hl.listeners {
		port := listener.Addr().(*net.TCPAddr).Port
		if _, err := client.RegisterProtocol(result.ServerID, protocol, port); err != nil {
			return "", "", fmt.Errorf("hyperswarm reattach register protocol %s: %w", protocol, err)
		}
		log.Printf("[hyperswarm] Re-registered protocol handler: %s on port %d", protocol, port)
	}

	hl.client = client
	hl.serverID = result.ServerID

	log.Printf("[hyperswarm] Listener reattached to sidecar: server %s, %d protocol(s)", result.ServerID, len(hl.listeners))
	return result.ServerID, kp.PublicKey, nil
}

// SetStreamHandler registers a handler for a named protocol. When a remote peer
// opens a stream with this protocol name, the handler will be called with a
// Stream wrapping the TCP connection.
//
// This starts a local TCP listener for the protocol and registers it with the
// sidecar. Incoming mux streams for this protocol get proxied to the listener.
func (hl *HyperswarmListener) SetStreamHandler(protocol string, handler StreamHandler) error {
	hl.mu.Lock()
	defer hl.mu.Unlock()

	if hl.serverID == "" {
		return fmt.Errorf("hyperswarm: must call CreateServer before SetStreamHandler")
	}

	// Start a local TCP listener that accepts proxied streams from the sidecar
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("hyperswarm listen for %s: %w", protocol, err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	// Register the protocol with the sidecar so it proxies incoming streams here
	_, err = hl.client.RegisterProtocol(hl.serverID, protocol, port)
	if err != nil {
		listener.Close()
		return fmt.Errorf("hyperswarm register protocol %s: %w", protocol, err)
	}

	hl.handlers[protocol] = handler
	hl.listeners[protocol] = listener

	// Accept loop for this protocol
	go hl.acceptLoop(protocol, listener, handler)

	log.Printf("[hyperswarm] Registered protocol handler: %s on port %d", protocol, port)
	return nil
}

// acceptLoop accepts incoming TCP connections from the sidecar's stream proxy
// and dispatches them to the registered handler.
func (hl *HyperswarmListener) acceptLoop(protocol string, listener net.Listener, handler StreamHandler) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-hl.ctx.Done():
				return
			default:
				log.Printf("[hyperswarm] Accept error for %s: %v", protocol, err)
				return
			}
		}

		go handler(&HyperswarmIncomingStream{
			conn:     conn,
			ctx:      hl.ctx,
			protocol: protocol,
		})
	}
}

// Announce advertises the server on a DHT topic so peers can discover it.
func (hl *HyperswarmListener) Announce(topic string) error {
	hl.mu.RLock()
	client, serverID := hl.client, hl.serverID
	hl.mu.RUnlock()

	_, err := client.Announce(serverID, topic)
	return err
}

// ServerID returns the sidecar server ID.
func (hl *HyperswarmListener) ServerID() string {
	hl.mu.RLock()
	defer hl.mu.RUnlock()
	return hl.serverID
}

// Client returns the underlying sidecar RPC client.
func (hl *HyperswarmListener) Client() *hsClient.Client {
	hl.mu.RLock()
	defer hl.mu.RUnlock()
	return hl.client
}

// Close shuts down all protocol listeners and the DHT server.
func (hl *HyperswarmListener) Close() error {
	hl.cancel()

	hl.mu.Lock()
	defer hl.mu.Unlock()

	for protocol, listener := range hl.listeners {
		hl.client.UnregisterProtocol(hl.serverID, protocol)
		listener.Close()
	}

	if hl.serverID != "" {
		return hl.client.CloseServer(hl.serverID)
	}
	return nil
}

// HyperswarmIncomingStream wraps an incoming TCP connection from the sidecar
// as a hdk-nostr-go Stream for use by protocol handlers.
type HyperswarmIncomingStream struct {
	conn     net.Conn
	ctx      context.Context
	protocol string
}

func (his *HyperswarmIncomingStream) Read(p []byte) (int, error) {
	return his.conn.Read(p)
}

func (his *HyperswarmIncomingStream) Write(p []byte) (int, error) {
	return his.conn.Write(p)
}

func (his *HyperswarmIncomingStream) Close() error {
	return his.conn.Close()
}

func (his *HyperswarmIncomingStream) Context() context.Context {
	return his.ctx
}
