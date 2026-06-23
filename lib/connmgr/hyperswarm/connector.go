package hyperswarm

import (
	"context"
	"fmt"
	"net"
	"sync"

	types "github.com/HORNET-Storage/go-hornet-storage-lib/lib"
	hsClient "github.com/hornet-storage/hornets-hyperswarm/clients/go/hyperswarm"
)

// HyperswarmConnector implements the Connector interface using the
// hornets-hyperswarm sidecar for NAT-punching P2P connections.
type HyperswarmConnector struct {
	client       *hsClient.Client
	connectionID string // mux connection ID from sidecar
	remoteKey    string // remote peer's ed25519 public key (hex)
	mu           sync.Mutex
	connected    bool
}

// NewHyperswarmConnector creates a connector that will connect to a remote peer
// via the hyperswarm sidecar. The client must already be connected to the sidecar.
// remotePublicKey is the remote peer's ed25519 DHT public key (hex-encoded).
func NewHyperswarmConnector(client *hsClient.Client, remotePublicKey string) *HyperswarmConnector {
	return &HyperswarmConnector{
		client:    client,
		remoteKey: remotePublicKey,
	}
}

// Connect establishes a mux connection to the remote peer via HyperDHT.
func (hc *HyperswarmConnector) Connect(ctx context.Context) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if hc.connected {
		return nil
	}

	result, err := hc.client.ConnectMuxContext(ctx, hsClient.ConnectParams{
		PublicKey: hc.remoteKey,
	})
	if err != nil {
		return fmt.Errorf("hyperswarm connect to %s: %w", hc.remoteKey[:16], err)
	}

	hc.connectionID = result.ConnectionID
	hc.connected = true
	return nil
}

// Disconnect tears down the mux connection.
func (hc *HyperswarmConnector) Disconnect() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if !hc.connected {
		return nil
	}

	err := hc.client.CloseMuxConnection(hc.connectionID)
	hc.connected = false
	hc.connectionID = ""
	return err
}

// OpenStream opens a named protocol stream over the mux connection and returns
// a Stream that satisfies the go-hornet-storage-lib Stream interface.
// The protocolID maps directly to the sidecar's protocol name (e.g. "/push", "/upload").
func (hc *HyperswarmConnector) OpenStream(ctx context.Context, protocolID string) (types.Stream, error) {
	hc.mu.Lock()
	connID := hc.connectionID
	connected := hc.connected
	hc.mu.Unlock()

	if !connected {
		return nil, fmt.Errorf("hyperswarm: not connected")
	}

	stream, err := hc.client.OpenStreamContext(ctx, connID, protocolID)
	if err != nil {
		return nil, fmt.Errorf("hyperswarm open stream %s: %w", protocolID, err)
	}

	// Get the underlying TCP connection (triggers lazy connect to local proxy port).
	conn, err := stream.Conn()
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("hyperswarm stream proxy connect: %w", err)
	}

	return &HyperswarmStream{
		stream: stream,
		conn:   conn,
		ctx:    ctx,
	}, nil
}

// ConnectionID returns the sidecar's mux connection ID, useful for diagnostics.
func (hc *HyperswarmConnector) ConnectionID() string {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	return hc.connectionID
}

// HyperswarmStream wraps a sidecar mux stream as a go-hornet-storage-lib Stream.
type HyperswarmStream struct {
	stream *hsClient.Stream
	conn   net.Conn
	ctx    context.Context
}

func (hs *HyperswarmStream) Read(p []byte) (int, error) {
	return hs.conn.Read(p)
}

func (hs *HyperswarmStream) Write(p []byte) (int, error) {
	return hs.conn.Write(p)
}

func (hs *HyperswarmStream) Close() error {
	return hs.stream.Close()
}

func (hs *HyperswarmStream) Context() context.Context {
	return hs.ctx
}
