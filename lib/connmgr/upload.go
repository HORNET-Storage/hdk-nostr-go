package connmgr

import (
	"context"

	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	merkle_dag "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
	types "github.com/HORNET-Storage/hdk-nostr-go/lib"
	"github.com/HORNET-Storage/hdk-nostr-go/lib/signing"
)

func UploadDag(ctx context.Context, connectionManager ConnectionManager, dag *merkle_dag.Dag, privatekey *secp256k1.PrivateKey, progressChan chan<- types.UploadProgress) error {
	for connectionID := range connectionManager.ListConnections() {
		err := UploadDagSingle(ctx, connectionManager, connectionID, dag, privatekey, progressChan)
		if err != nil {
			return fmt.Errorf("failed to upload DAG to node %s: %w", connectionID, err)
		}
	}

	return nil
}

func UploadDagSingle(ctx context.Context, connectionManager ConnectionManager, connectionID string, dag *merkle_dag.Dag, privatekey *secp256k1.PrivateKey, progressChan chan<- types.UploadProgress) error {
	stream, err := connectionManager.GetStream(ctx, connectionID, UploadID)
	if err != nil {
		return fmt.Errorf("failed to get stream for connection %s: %w", connectionID, err)
	}
	defer stream.Close()

	if privatekey == nil {
		return fmt.Errorf("unable to sign data due to missing private key")
	}

	signature, err := signing.SignSerializedCid(dag.Root, privatekey)
	if err != nil {
		return fmt.Errorf("failed to sign dag root")
	}

	serializedSignature := signature.Serialize()

	serializedPubkey, err := signing.SerializePublicKey(privatekey.PubKey())
	if err != nil {
		return fmt.Errorf("failed to serialize pubkey")
	}

	err = signing.VerifySerializedCIDSignature(signature, dag.Root, privatekey.PubKey())
	if err != nil {
		return fmt.Errorf("failed to verify signature")
	}

	totalLeafs := len(dag.Leafs)
	leafsSent := 0
	sequence := dag.GetBatchedLeafSequence()
	cumulativeLeafs := make([]int, len(sequence))
	for index, packet := range sequence {
		if packet != nil {
			leafsSent += len(packet.Leaves)
		}
		cumulativeLeafs[index] = leafsSent
	}
	leafsSent = 0

	_, err = sendBatchedUpload(ctx, stream, dag.Root, sequence, *serializedPubkey, fmt.Sprintf("%x", serializedSignature), func(packetIndex int) {
		leafsSent = cumulativeLeafs[packetIndex]
		if progressChan != nil {
			progressChan <- types.UploadProgress{ConnectionID: connectionID, LeafsSent: leafsSent, TotalLeafs: totalLeafs}
		}
	})
	if err != nil {
		if progressChan != nil {
			progressChan <- types.UploadProgress{ConnectionID: connectionID, LeafsSent: leafsSent, TotalLeafs: totalLeafs, Error: err}
		}
		return err
	}
	return nil
}
