package connmgr

import (
	"context"
	"encoding/hex"
	"fmt"

	merkle_dag "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
	types "github.com/HORNET-Storage/hdk-nostr-go/lib"
	"github.com/HORNET-Storage/hdk-nostr-go/lib/signing"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func DownloadDag(ctx context.Context, connectionManager ConnectionManager, connectionID string, root string, privatekey *secp256k1.PrivateKey, filter *types.DownloadFilter, progressChan chan<- types.DownloadProgress) (context.Context, *types.DagData, error) {
	stream, err := connectionManager.GetStream(ctx, connectionID, DownloadID)
	if err != nil {
		return ctx, nil, fmt.Errorf("failed to get stream for connection %s: %w", connectionID, err)
	}
	defer stream.Close()

	downloadMessage := types.DownloadMessage{Root: root}
	if privatekey != nil {
		sig, signErr := signing.SignSerializedCid(root, privatekey)
		if signErr != nil {
			return ctx, nil, signErr
		}
		serializedPubkey, serializeErr := signing.SerializePublicKey(privatekey.PubKey())
		if serializeErr != nil {
			return ctx, nil, serializeErr
		}
		if verifyErr := signing.VerifySerializedCIDSignature(sig, root, privatekey.PubKey()); verifyErr != nil {
			return ctx, nil, verifyErr
		}
		downloadMessage.PublicKey = *serializedPubkey
		downloadMessage.Signature = hex.EncodeToString(sig.Serialize())
	}
	if filter != nil {
		downloadMessage.Filter = filter
	}
	if err := WriteMessageToStream(stream, downloadMessage); err != nil {
		return ctx, nil, err
	}

	reject := func(cause error) {
		_ = WriteMessageToStream(stream, BuildResponseMessage(false, cause.Error()))
	}

	messageReader := NewMessageReader(stream)
	uploadMessage, err := WaitForUploadMessageFromReader(messageReader)
	if err != nil {
		return ctx, nil, fmt.Errorf("WaitForUploadMessage failed: %w", err)
	}
	if uploadMessage.Root != root {
		err = fmt.Errorf("downloaded DAG root %q does not match requested root %q (possible relay substitution)", uploadMessage.Root, root)
		reject(err)
		return ctx, nil, err
	}
	dagPublicKey, err := signing.DeserializePublicKey(uploadMessage.PublicKey)
	if err != nil {
		err = fmt.Errorf("DeserializePublicKey failed: %w", err)
		reject(err)
		return ctx, nil, err
	}
	signatureBytes, err := hex.DecodeString(uploadMessage.Signature)
	if err != nil {
		err = fmt.Errorf("hex.DecodeString signature failed: %w", err)
		reject(err)
		return ctx, nil, err
	}
	dagSignature, err := schnorr.ParseSignature(signatureBytes)
	if err != nil {
		err = fmt.Errorf("ParseSignature failed: %w", err)
		reject(err)
		return ctx, nil, err
	}
	if err = signing.VerifySerializedCIDSignature(dagSignature, uploadMessage.Root, dagPublicKey); err != nil {
		err = fmt.Errorf("VerifySerializedCIDSignature failed for root %s: %w", uploadMessage.Root, err)
		reject(err)
		return ctx, nil, err
	}

	dag := &merkle_dag.Dag{Root: uploadMessage.Root, Leafs: make(map[string]*merkle_dag.DagLeaf)}
	receiveState := newPacketReceiveState(uploadMessage.Root, uploadMessage.PublicKey, uploadMessage.Signature)
	for {
		packet := merkle_dag.BatchedTransmissionPacketFromSerializable(&uploadMessage.Packet)
		if err = receiveState.validate(uploadMessage, packet); err != nil {
			err = fmt.Errorf("invalid transmission packet: %w", err)
			reject(err)
			return ctx, nil, err
		}
		if err = dag.ApplyAndVerifyBatchedTransmissionPacket(packet); err != nil {
			err = fmt.Errorf("ApplyAndVerifyBatchedTransmissionPacket failed: %w", err)
			reject(err)
			return ctx, nil, err
		}
		receiveState.commit(uploadMessage, packet)

		if uploadMessage.IsFinalPacket {
			if receiveState.windowed && receiveState.next != receiveState.total {
				err = fmt.Errorf("incomplete packet stream: verified %d of %d packets", receiveState.next, receiveState.total)
				reject(err)
				return ctx, nil, err
			}
			if err = dag.Verify(); err != nil {
				reject(err)
				return ctx, nil, err
			}
		}
		if err = WriteMessageToStream(stream, BuildResponseMessage(true, receiveState.acknowledgment())); err != nil {
			return ctx, nil, fmt.Errorf("failed to acknowledge verified packet: %w", err)
		}
		if progressChan != nil {
			progressChan <- types.DownloadProgress{ConnectionID: connectionID, LeafsRetreived: len(dag.Leafs)}
		}
		if uploadMessage.IsFinalPacket {
			break
		}
		uploadMessage, err = WaitForUploadMessageFromReader(messageReader)
		if err != nil {
			return ctx, nil, err
		}
	}

	dagData := &types.DagData{
		PublicKey: *dagPublicKey,
		Signature: *dagSignature,
		Dag:       *dag,
	}
	return ctx, dagData, nil
}
