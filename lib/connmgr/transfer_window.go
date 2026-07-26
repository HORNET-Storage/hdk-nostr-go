package connmgr

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	merkle_dag "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
	types "github.com/HORNET-Storage/hdk-nostr-go/lib"
)

const (
	transferWindowProtocol       = "scionic-window/1"
	transferWindowPackets        = 16
	transferWindowBytes    int64 = 32 * 1024 * 1024
	maximumWindowPackets         = 64
	maximumWindowBytes     int64 = 256 * 1024 * 1024
)

type transferWindowAck struct {
	Index   int
	Packets int
	Bytes   int64
}

type transferWindowStats struct {
	AckWait time.Duration
	Enabled bool
	Packets int
	Bytes   int64
}

func encodeTransferWindowAck(index int) string {
	return fmt.Sprintf("%s %d %d %d", transferWindowProtocol, index, transferWindowPackets, transferWindowBytes)
}

func parseTransferWindowAck(message string) (transferWindowAck, bool, error) {
	if !strings.HasPrefix(message, "scionic-window/") {
		return transferWindowAck{}, false, nil
	}
	parts := strings.Fields(message)
	if len(parts) != 4 || parts[0] != transferWindowProtocol {
		return transferWindowAck{}, true, fmt.Errorf("unsupported or malformed Scionic transfer acknowledgment %q", message)
	}
	index, err := strconv.Atoi(parts[1])
	if err != nil || index < 0 {
		return transferWindowAck{}, true, fmt.Errorf("invalid cumulative acknowledgment index %q", parts[1])
	}
	packets, err := strconv.Atoi(parts[2])
	if err != nil || packets < 1 || packets > maximumWindowPackets {
		return transferWindowAck{}, true, fmt.Errorf("invalid transfer window packet limit %q", parts[2])
	}
	bytes, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || bytes < 1 || bytes > maximumWindowBytes {
		return transferWindowAck{}, true, fmt.Errorf("invalid transfer window byte limit %q", parts[3])
	}
	return transferWindowAck{Index: index, Packets: packets, Bytes: bytes}, true, nil
}

func transferPacketSize(packet *merkle_dag.BatchedTransmissionPacket) int64 {
	if packet == nil {
		return 0
	}
	size := int64(128)
	for _, leaf := range packet.Leaves {
		if leaf != nil {
			size += int64(leaf.EstimateSize()) + 256
		}
	}
	for child, parent := range packet.Relationships {
		size += int64(len(child) + len(parent) + 32)
	}
	return size
}

type transferAckResult struct {
	response *types.ResponseMessage
	err      error
}

func sendBatchedUpload(
	ctx context.Context,
	stream types.Stream,
	root string,
	sequence []*merkle_dag.BatchedTransmissionPacket,
	publicKey string,
	signature string,
	onAck func(int),
) (transferWindowStats, error) {
	stats := transferWindowStats{}
	if len(sequence) == 0 {
		return stats, fmt.Errorf("DAG %s produced no transmission packets", root)
	}
	for index, packet := range sequence {
		if packet == nil {
			return stats, fmt.Errorf("transmission packet %d is nil", index)
		}
		if packet.PacketIndex != index || packet.TotalPackets != len(sequence) {
			return stats, fmt.Errorf("transmission packet counters are inconsistent at %d: index=%d total=%d expected_total=%d", index, packet.PacketIndex, packet.TotalPackets, len(sequence))
		}
	}

	writePacket := func(index int) error {
		packet := sequence[index]
		message := types.UploadMessage{
			Root:          root,
			Packet:        *packet.ToSerializable(),
			IsFinalPacket: index == len(sequence)-1,
		}
		if index == 0 {
			message.PublicKey = publicKey
			message.Signature = signature
		}
		return WriteMessageToStream(stream, message)
	}
	waitResponse := func() (*types.ResponseMessage, error) {
		started := time.Now()
		response, err := WaitForResponse(stream)
		stats.AckWait += time.Since(started)
		return response, err
	}
	validateResponse := func(response *types.ResponseMessage) error {
		if response == nil {
			return fmt.Errorf("peer returned no upload acknowledgment")
		}
		if !response.Ok {
			if response.Message != "" {
				return fmt.Errorf("upload rejected: %s", response.Message)
			}
			return fmt.Errorf("upload rejected by peer")
		}
		return nil
	}

	if err := writePacket(0); err != nil {
		return stats, err
	}
	response, err := waitResponse()
	if err != nil {
		return stats, fmt.Errorf("failed to receive root packet acknowledgment: %w", err)
	}
	if err := validateResponse(response); err != nil {
		return stats, err
	}
	ack, supported, err := parseTransferWindowAck(response.Message)
	if err != nil {
		return stats, err
	}
	if onAck != nil {
		onAck(0)
	}
	if !supported {
		for index := 1; index < len(sequence); index++ {
			if err := writePacket(index); err != nil {
				return stats, err
			}
			response, err := waitResponse()
			if err != nil {
				return stats, fmt.Errorf("failed to receive packet %d acknowledgment: %w", index, err)
			}
			if err := validateResponse(response); err != nil {
				return stats, err
			}
			if onAck != nil {
				onAck(index)
			}
		}
		return stats, nil
	}
	if ack.Index != 0 {
		return stats, fmt.Errorf("root acknowledgment advanced to packet %d instead of 0", ack.Index)
	}
	stats.Enabled = true
	stats.Packets = ack.Packets
	stats.Bytes = ack.Bytes
	if len(sequence) == 1 {
		return stats, nil
	}

	done := make(chan struct{})
	defer close(done)
	ackResults := make(chan transferAckResult, ack.Packets+1)
	go func() {
		responseReader := NewMessageReader(stream)
		for remaining := len(sequence) - 1; remaining > 0; remaining-- {
			response, readErr := WaitForResponseFromReader(responseReader)
			select {
			case ackResults <- transferAckResult{response: response, err: readErr}:
			case <-done:
				return
			}
			if readErr != nil || response == nil || !response.Ok {
				return
			}
		}
	}()

	highestAck := 0
	nextPacket := 1
	inFlightBytes := int64(0)
	inFlightSizes := make(map[int]int64)

	readAck := func() error {
		started := time.Now()
		var result transferAckResult
		select {
		case result = <-ackResults:
		case <-ctx.Done():
			return ctx.Err()
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		stats.AckWait += time.Since(started)
		if result.err != nil {
			return fmt.Errorf("failed to receive cumulative acknowledgment: %w", result.err)
		}
		if err := validateResponse(result.response); err != nil {
			return err
		}
		current, stillSupported, err := parseTransferWindowAck(result.response.Message)
		if err != nil {
			return err
		}
		if !stillSupported {
			return fmt.Errorf("peer removed sliding-window metadata after negotiation")
		}
		if current.Packets != ack.Packets || current.Bytes != ack.Bytes {
			return fmt.Errorf("peer changed negotiated transfer window")
		}
		if current.Index <= highestAck {
			return fmt.Errorf("duplicate or regressing cumulative acknowledgment %d after %d", current.Index, highestAck)
		}
		if current.Index >= nextPacket || current.Index >= len(sequence) {
			return fmt.Errorf("cumulative acknowledgment %d covers an unsent or out-of-range packet", current.Index)
		}
		for index := highestAck + 1; index <= current.Index; index++ {
			size, ok := inFlightSizes[index]
			if !ok {
				return fmt.Errorf("cumulative acknowledgment %d skipped unknown packet %d", current.Index, index)
			}
			inFlightBytes -= size
			delete(inFlightSizes, index)
		}
		highestAck = current.Index
		if onAck != nil {
			onAck(highestAck)
		}
		return nil
	}

	for highestAck < len(sequence)-1 {
		for nextPacket < len(sequence) {
			size := transferPacketSize(sequence[nextPacket])
			packetCapacity := len(inFlightSizes) < ack.Packets
			byteCapacity := inFlightBytes+size <= ack.Bytes || len(inFlightSizes) == 0
			if !packetCapacity || !byteCapacity {
				break
			}
			if err := writePacket(nextPacket); err != nil {
				return stats, err
			}
			inFlightSizes[nextPacket] = size
			inFlightBytes += size
			nextPacket++
		}
		if err := readAck(); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

type packetReceiveState struct {
	root       string
	publicKey  string
	signature  string
	total      int
	next       int
	windowed   bool
	finalized  bool
	seenLeaves map[string]struct{}
}

func newPacketReceiveState(root, publicKey, signature string) *packetReceiveState {
	return &packetReceiveState{
		root:       root,
		publicKey:  publicKey,
		signature:  signature,
		seenLeaves: make(map[string]struct{}),
	}
}

func (state *packetReceiveState) validate(message *types.UploadMessage, packet *merkle_dag.BatchedTransmissionPacket) error {
	if state.finalized {
		return fmt.Errorf("received a packet after finalization")
	}
	if message == nil || packet == nil || len(packet.Leaves) == 0 {
		return fmt.Errorf("received an empty transmission packet")
	}
	if message.Root != state.root {
		return fmt.Errorf("transmission root changed from %s to %s", state.root, message.Root)
	}
	if state.next == 0 {
		if packet.TotalPackets < 0 || packet.PacketIndex != 0 {
			return fmt.Errorf("invalid root packet counters index=%d total=%d", packet.PacketIndex, packet.TotalPackets)
		}
		if packet.TotalPackets > 0 {
			state.windowed = true
			state.total = packet.TotalPackets
		}
		rootLeaf := packet.GetRootLeaf()
		if rootLeaf == nil || rootLeaf.Hash != state.root {
			return fmt.Errorf("first packet does not contain the declared root leaf")
		}
	} else {
		if message.PublicKey != "" && message.PublicKey != state.publicKey {
			return fmt.Errorf("DAG public key changed after the root packet")
		}
		if message.Signature != "" && message.Signature != state.signature {
			return fmt.Errorf("DAG signature changed after the root packet")
		}
	}
	if state.windowed {
		if packet.TotalPackets != state.total {
			return fmt.Errorf("packet total changed from %d to %d", state.total, packet.TotalPackets)
		}
		if packet.PacketIndex != state.next {
			return fmt.Errorf("expected packet %d, received %d", state.next, packet.PacketIndex)
		}
		if packet.PacketIndex < 0 || packet.PacketIndex >= state.total {
			return fmt.Errorf("packet index %d is out of range for total %d", packet.PacketIndex, state.total)
		}
		shouldBeFinal := packet.PacketIndex == state.total-1
		if message.IsFinalPacket != shouldBeFinal {
			return fmt.Errorf("packet %d final marker is inconsistent with total %d", packet.PacketIndex, state.total)
		}
	} else if packet.TotalPackets != 0 || packet.PacketIndex != 0 {
		return fmt.Errorf("legacy packet counters changed during transfer")
	}
	packetLeaves := make(map[string]struct{}, len(packet.Leaves))
	for _, leaf := range packet.Leaves {
		if leaf == nil || leaf.Hash == "" {
			return fmt.Errorf("packet contains a nil or unhashed leaf")
		}
		if _, duplicate := packetLeaves[leaf.Hash]; duplicate {
			return fmt.Errorf("packet repeats leaf %s", leaf.Hash)
		}
		if _, duplicate := state.seenLeaves[leaf.Hash]; duplicate {
			return fmt.Errorf("transfer repeats previously verified leaf %s", leaf.Hash)
		}
		parent, exists := packet.Relationships[leaf.Hash]
		if !exists {
			return fmt.Errorf("packet omits relationship for leaf %s", leaf.Hash)
		}
		if parent == "" && leaf.Hash != state.root {
			return fmt.Errorf("empty DAG parent declared for non-root leaf %s", leaf.Hash)
		}
		packetLeaves[leaf.Hash] = struct{}{}
	}
	return nil
}

func (state *packetReceiveState) commit(message *types.UploadMessage, packet *merkle_dag.BatchedTransmissionPacket) {
	for _, leaf := range packet.Leaves {
		state.seenLeaves[leaf.Hash] = struct{}{}
	}
	state.next++
	state.finalized = message.IsFinalPacket
}

func (state *packetReceiveState) acknowledgment() string {
	if !state.windowed {
		return ""
	}
	return encodeTransferWindowAck(state.next - 1)
}
