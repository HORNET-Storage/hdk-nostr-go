package connmgr

import (
	"context"
	"encoding/hex"
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
	total := len(sequence)

	for i, packet := range sequence {
		message := types.UploadMessage{
			Root:          dag.Root,
			Packet:        *packet.ToSerializable(),
			IsFinalPacket: i == total-1, // Mark the last packet
		}

		// Only add the pub key and signature to the first packet as that's what contains the root
		if i == 0 {
			message.PublicKey = *serializedPubkey
			message.Signature = hex.EncodeToString(serializedSignature)
		}

		if err := WriteMessageToStream(stream, message); err != nil {
			if progressChan != nil {
				progressChan <- types.UploadProgress{ConnectionID: connectionID, LeafsSent: leafsSent, TotalLeafs: totalLeafs, Error: err}
			}

			return err
		}

		response, err := WaitForResponse(stream)
		if err != nil {
			err = fmt.Errorf("failed to receive response: %w", err)

			if progressChan != nil {
				progressChan <- types.UploadProgress{ConnectionID: connectionID, LeafsSent: leafsSent, TotalLeafs: totalLeafs, Error: err}
			}

			return err
		}

		if !response.Ok {
			err = fmt.Errorf("did not receive a valid response: %w", err)

			if progressChan != nil {
				progressChan <- types.UploadProgress{ConnectionID: connectionID, LeafsSent: leafsSent, TotalLeafs: totalLeafs, Error: err}
			}

			return err
		}

		leafsSent += len(packet.Leaves)

		if progressChan != nil {
			progressChan <- types.UploadProgress{ConnectionID: connectionID, LeafsSent: leafsSent, TotalLeafs: totalLeafs}
		}
	}

	return nil
}
