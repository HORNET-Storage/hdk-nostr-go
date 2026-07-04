package libp2p

import (
	"context"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"

	types "github.com/HORNET-Storage/hdk-nostr-go/lib"
)

type Libp2pConnector struct {
	Host          host.Host
	ServerAddress *multiaddr.Multiaddr
	Peer          *peer.AddrInfo
}

func NewLibp2pConnector(serverAddress string, opts ...libp2p.Option) (*Libp2pConnector, error) {
	maddr, err := multiaddr.NewMultiaddr(serverAddress)
	if err != nil {
		return nil, err
	}
	serverInfo, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return nil, err
	}
	host, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}

	return &Libp2pConnector{
		Host:          host,
		ServerAddress: &maddr,
		Peer:          serverInfo,
	}, nil
}

func (lc *Libp2pConnector) Connect(ctx context.Context) error {
	if err := lc.Host.Connect(ctx, *lc.Peer); err != nil {
		return err
	}
	return nil
}

func (lc *Libp2pConnector) Disconnect() error {
	return lc.Host.Close()
}

func (lc *Libp2pConnector) OpenStream(ctx context.Context, protocolID string) (types.Stream, error) {
	stream, err := lc.Host.NewStream(ctx, lc.Peer.ID, protocol.ID(protocolID))
	if err != nil {
		return nil, err
	}
	return &Libp2pStream{stream: stream, ctx: ctx}, nil
}
