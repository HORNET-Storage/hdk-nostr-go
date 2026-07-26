package connmgr

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	merkle_dag "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
	types "github.com/HORNET-Storage/hdk-nostr-go/lib"
)

type bufferedMessageStream struct {
	bytes.Buffer
	ctx context.Context
}

func (stream *bufferedMessageStream) Close() error             { return nil }
func (stream *bufferedMessageStream) Context() context.Context { return stream.ctx }

type transferTestStream struct {
	net.Conn
	ctx context.Context
}

func (stream *transferTestStream) Context() context.Context { return stream.ctx }

func transferTestSequence(total int) []*merkle_dag.BatchedTransmissionPacket {
	packets := make([]*merkle_dag.BatchedTransmissionPacket, total)
	for index := range packets {
		hash := fmt.Sprintf("leaf-%d", index)
		parent := "root"
		if index == 0 {
			hash = "root"
			parent = ""
		}
		packets[index] = &merkle_dag.BatchedTransmissionPacket{
			Leaves:        []*merkle_dag.DagLeaf{{Hash: hash}},
			Relationships: map[string]string{hash: parent},
			PacketIndex:   index,
			TotalPackets:  total,
		}
	}
	return packets
}

func TestSendBatchedUploadPipelinesAfterVerifiedRootAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	clientConn, serverConn := net.Pipe()
	client := &transferTestStream{Conn: clientConn, ctx: ctx}
	server := &transferTestStream{Conn: serverConn, ctx: ctx}
	defer client.Close()
	defer server.Close()

	peerErr := make(chan error, 1)
	go func() {
		root, err := WaitForUploadMessage(server)
		if err != nil {
			peerErr <- err
			return
		}
		if root.PublicKey == "" || root.Signature == "" {
			peerErr <- fmt.Errorf("root packet was not authenticated")
			return
		}
		if err := WriteMessageToStream(server, BuildResponseMessage(true, "scionic-window/1 0 2 33554432")); err != nil {
			peerErr <- err
			return
		}
		second, err := WaitForUploadMessage(server)
		if err != nil {
			peerErr <- err
			return
		}
		third, err := WaitForUploadMessage(server)
		if err != nil {
			peerErr <- err
			return
		}
		if second.PublicKey != "" || third.PublicKey != "" {
			peerErr <- fmt.Errorf("authentication was repeated after root packet")
			return
		}
		if err := WriteMessageToStream(server, BuildResponseMessage(true, "scionic-window/1 1 2 33554432")); err != nil {
			peerErr <- err
			return
		}
		peerErr <- WriteMessageToStream(server, BuildResponseMessage(true, "scionic-window/1 2 2 33554432"))
	}()

	stats, err := sendBatchedUpload(ctx, client, "root", transferTestSequence(3), "pub", "sig", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-peerErr; err != nil {
		t.Fatal(err)
	}
	if !stats.Enabled || stats.Packets != 2 {
		t.Fatalf("sliding window was not negotiated: %+v", stats)
	}
}

func TestSendBatchedUploadFallsBackForLegacyPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	clientConn, serverConn := net.Pipe()
	client := &transferTestStream{Conn: clientConn, ctx: ctx}
	server := &transferTestStream{Conn: serverConn, ctx: ctx}
	defer client.Close()
	defer server.Close()

	peerErr := make(chan error, 1)
	go func() {
		for range 3 {
			if _, err := WaitForUploadMessage(server); err != nil {
				peerErr <- err
				return
			}
			if err := WriteMessageToStream(server, BuildResponseMessage(true)); err != nil {
				peerErr <- err
				return
			}
		}
		peerErr <- nil
	}()

	stats, err := sendBatchedUpload(ctx, client, "root", transferTestSequence(3), "pub", "sig", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-peerErr; err != nil {
		t.Fatal(err)
	}
	if stats.Enabled {
		t.Fatal("legacy peer unexpectedly negotiated a sliding window")
	}
}

func TestPacketReceiveStateRejectsOrderingAndDuplicateLeaves(t *testing.T) {
	state := newPacketReceiveState("root", "pub", "sig")
	rootMessage := &types.UploadMessage{Root: "root", PublicKey: "pub", Signature: "sig"}
	rootPacket := transferTestSequence(2)[0]
	if err := state.validate(rootMessage, rootPacket); err != nil {
		t.Fatal(err)
	}
	state.commit(rootMessage, rootPacket)
	if got := state.acknowledgment(); got != "scionic-window/1 0 16 33554432" {
		t.Fatalf("unexpected root ACK: %q", got)
	}

	duplicate := &merkle_dag.BatchedTransmissionPacket{
		Leaves: []*merkle_dag.DagLeaf{{Hash: "root"}}, Relationships: map[string]string{"root": ""}, PacketIndex: 1, TotalPackets: 2,
	}
	if err := state.validate(&types.UploadMessage{Root: "root", IsFinalPacket: true}, duplicate); err == nil {
		t.Fatal("duplicate leaf was accepted")
	}
	gap := &merkle_dag.BatchedTransmissionPacket{
		Leaves: []*merkle_dag.DagLeaf{{Hash: "leaf"}}, Relationships: map[string]string{"leaf": "root"}, PacketIndex: 2, TotalPackets: 2,
	}
	if err := state.validate(&types.UploadMessage{Root: "root", IsFinalPacket: true}, gap); err == nil {
		t.Fatal("out-of-order packet was accepted")
	}
}

func TestParseTransferWindowAckRejectsMalformedMetadata(t *testing.T) {
	if _, supported, err := parseTransferWindowAck(""); err != nil || supported {
		t.Fatalf("legacy ACK misparsed: supported=%v err=%v", supported, err)
	}
	if _, supported, err := parseTransferWindowAck("scionic-window/1 0 65 1"); err == nil || !supported {
		t.Fatal("oversized packet window was accepted")
	}
	if _, supported, err := parseTransferWindowAck("scionic-window/2 0 16 33554432"); err == nil || !supported {
		t.Fatal("unknown window protocol was accepted")
	}
}

func TestMessageReaderPreservesPipelinedEnvelopeBytes(t *testing.T) {
	stream := &bufferedMessageStream{ctx: context.Background()}
	if err := WriteMessageToStream(stream, BuildResponseMessage(true, "first")); err != nil {
		t.Fatal(err)
	}
	if err := WriteMessageToStream(stream, BuildResponseMessage(true, "second")); err != nil {
		t.Fatal(err)
	}

	reader := NewMessageReader(stream)
	first, err := WaitForResponseFromReader(reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := WaitForResponseFromReader(reader)
	if err != nil {
		t.Fatal(err)
	}
	if first.Message != "first" || second.Message != "second" {
		t.Fatalf("pipelined messages were not decoded in order: first=%q second=%q", first.Message, second.Message)
	}
}
