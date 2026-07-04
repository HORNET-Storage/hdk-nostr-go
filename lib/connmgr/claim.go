package connmgr

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	types "github.com/HORNET-Storage/hdk-nostr-go/lib"
	"github.com/HORNET-Storage/hdk-nostr-go/lib/signing"
)

// ClaimOwnership claims ownership of an existing DAG root on a relay.
// The DAG must already exist on the relay. This is useful when a DAG was uploaded
// by another user and you want to claim ownership (e.g., for preventing garbage collection).
// The function signs the root hash with the provided private key to prove ownership.
func ClaimOwnership(ctx context.Context, connectionManager ConnectionManager, connectionID string, root string, privateKey *secp256k1.PrivateKey) (*types.ResponseMessage, error) {
	stream, err := connectionManager.GetStream(ctx, connectionID, ClaimOwnershipID)
	if err != nil {
		return nil, fmt.Errorf("failed to get stream for connection %s: %w", connectionID, err)
	}
	defer stream.Close()

	if privateKey == nil {
		return nil, fmt.Errorf("private key is required to claim ownership")
	}

	// Sign the root hash with the private key
	signature, err := signing.SignSerializedCid(root, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign root hash: %w", err)
	}

	// Serialize the public key
	serializedPubkey, err := signing.SerializePublicKey(privateKey.PubKey())
	if err != nil {
		return nil, fmt.Errorf("failed to serialize public key: %w", err)
	}

	// Create and send the claim ownership message
	message := types.ClaimOwnershipMessage{
		Root:      root,
		PublicKey: *serializedPubkey,
		Signature: hex.EncodeToString(signature.Serialize()),
	}

	if err := WriteMessageToStream(stream, message); err != nil {
		return nil, fmt.Errorf("failed to send claim ownership message: %w", err)
	}

	// Read the response
	response, err := ReadMessageFromStream[types.ResponseMessage](stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read claim ownership response: %w", err)
	}

	if !response.Ok {
		return response, fmt.Errorf("claim ownership failed: %s", response.Message)
	}

	return response, nil
}

// ClaimOwnershipAll claims ownership of a DAG root on all connected relays.
// Returns a map of connection IDs to their responses or errors.
func ClaimOwnershipAll(ctx context.Context, connectionManager ConnectionManager, root string, privateKey *secp256k1.PrivateKey) map[string]*ClaimOwnershipResult {
	results := make(map[string]*ClaimOwnershipResult)

	for connectionID := range connectionManager.ListConnections() {
		response, err := ClaimOwnership(ctx, connectionManager, connectionID, root, privateKey)
		results[connectionID] = &ClaimOwnershipResult{
			Response: response,
			Error:    err,
		}
	}

	return results
}

// ClaimOwnershipResult holds the result of a claim ownership operation for a single connection.
type ClaimOwnershipResult struct {
	Response *types.ResponseMessage
	Error    error
}
