package websocket

import (
	"context"
	"fmt"

	"github.com/gorilla/websocket"

	types "github.com/HORNET-Storage/go-hornet-storage-lib/lib"
)

type WebSocketConnector struct {
	URL  string
	Conn *websocket.Conn
}

func NewWebSocketConnector(url string) *WebSocketConnector {
	return &WebSocketConnector{URL: fmt.Sprintf("%s/scionic", url)}
}

func (wsc *WebSocketConnector) Connect(ctx context.Context) error {
	// WebSocket connections are established per-stream in OpenStream.
	// This is a no-op for compatibility with the Connector interface.
	return nil
}

func (wsc *WebSocketConnector) Disconnect() error {
	return wsc.Conn.Close()
}

func (wsc *WebSocketConnector) OpenStream(ctx context.Context, protocolID string) (types.Stream, error) {
	var d websocket.Dialer
	conn, _, err := d.DialContext(ctx, fmt.Sprintf("%s/%s", wsc.URL, protocolID), nil)
	if err != nil {
		return nil, err
	}
	wsc.Conn = conn

	return &WebSocketStream{conn: wsc.Conn, ctx: ctx}, nil
}
