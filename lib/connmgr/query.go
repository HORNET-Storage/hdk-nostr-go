package connmgr

import (
	"context"
	"fmt"

	types "github.com/HORNET-Storage/hdk-nostr-go/lib"
)

func QueryDag(ctx context.Context, connectionManager ConnectionManager, connectionID string, query types.QueryFilter) ([]string, error) {
	stream, err := connectionManager.GetStream(ctx, connectionID, QueryID)
	if err != nil {
		return nil, fmt.Errorf("failed to get stream for connection %s: %w", connectionID, err)
	}
	defer stream.Close()

	queryMessage := types.AdvancedQueryMessage{
		Filter: query,
	}

	if err := WriteMessageToStream(stream, queryMessage); err != nil {
		return nil, err
	}

	message, err := ReadMessageFromStream[types.QueryResponse](stream)
	if err != nil {
		return nil, err
	}

	return message.Hashes, nil
}
