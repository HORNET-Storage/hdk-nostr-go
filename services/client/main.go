package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	merkle_dag "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
	types "github.com/HORNET-Storage/hdk-nostr-go/lib"
	"github.com/HORNET-Storage/hdk-nostr-go/lib/connmgr"
	"github.com/HORNET-Storage/hdk-nostr-go/lib/signing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/nbd-wtf/go-nostr"
)

// These are example keys generated for the purpose of this test client
// Please do not use them for anything other than this
const npub string = "npub128qpftun6mzv3gh7pfcsq3sefgqwruz43kuhhu78hq99jeak5a0sstnu23"
const nsec string = "nsec1yas03jagdjsr8su00g92jurf7am3dldvu9tckyz796z8efpa594qp2nelz"

func main() {
	ctx := context.Background()

	RunCommandWatcher(ctx)
}

func RunCommandWatcher(ctx context.Context) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan

		Cleanup(ctx)
		os.Exit(0)
	}()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		scanner.Scan()

		command := strings.TrimSpace(scanner.Text())
		segments := strings.Split(command, " ")

		switch segments[0] {
		case "help":
			log.Println("Available Commands:")
			log.Println("upload <path>                                    - Upload a directory/file as DAG")
			log.Println("download <root> <includeContent>                 - Download entire DAG (e.g., download <root> true)")
			log.Println("download-range <root> <from> <to> <content>      - Download leaf range (e.g., download-range <root> 5 10 true)")
			log.Println("download-hashes <root> <hash1,hash2,...> <content> - Download specific leaves (e.g., download-hashes <root> hash1,hash2 true)")
			log.Println("reconstruct <root> <output_path>                 - Download DAG and reconstruct directory structure")
			log.Println("query                                            - Query for DAGs")
			log.Println("event                                            - Upload test event")
			log.Println("keys                                             - Test key serialization")
			log.Println("shutdown                                         - Shutdown client")
		case "upload":
			if len(segments) < 2 {
				log.Println("Usage: upload <path>")
				continue
			}
			UploadDag(ctx, segments[1])
		case "download":
			if len(segments) < 3 {
				log.Println("Usage: download <root> <includeContent>")
				log.Println("Example: download bafyreiabc123... true")
				continue
			}
			DownloadDag(ctx, segments[1], segments[2])
		case "download-range":
			if len(segments) < 5 {
				log.Println("Usage: download-range <root> <from> <to> <includeContent>")
				log.Println("Example: download-range bafyreiabc123... 5 10 true")
				continue
			}
			DownloadDagWithRange(ctx, segments[1], segments[2], segments[3], segments[4])
		case "download-hashes":
			if len(segments) < 4 {
				log.Println("Usage: download-hashes <root> <hash1,hash2,...> <includeContent>")
				log.Println("Example: download-hashes bafyreiabc123... hash1,hash2,hash3 true")
				continue
			}
			DownloadDagWithHashes(ctx, segments[1], segments[2], segments[3])
		case "reconstruct":
			if len(segments) < 3 {
				log.Println("Usage: reconstruct <root> <output_path>")
				log.Println("Example: reconstruct bafyreiabc123... ./output")
				continue
			}
			ReconstructDirectory(ctx, segments[1], segments[2])
		case "query":
			QueryDag()
		case "event":
			UploadEvent(ctx)
		case "keys":
			TestKeys(ctx)
		case "shutdown":
			log.Println("Shutting down")
			Cleanup(ctx)
			return
		default:
			log.Printf("Unknown command: %s\n", command)
		}
	}
}

func Cleanup(ctx context.Context) {

}

// FileMetadataProcessor captures file metadata and adds it to additional data
func FileMetadataProcessor(path string, relPath string, entry os.DirEntry, isRoot bool, leafType merkle_dag.LeafType) map[string]string {
	metadata := make(map[string]string)

	// Get file info
	info, err := entry.Info()
	if err != nil {
		// If we can't get info, return empty metadata
		return metadata
	}

	// Add common metadata
	metadata["relative_path"] = relPath
	metadata["leaf_type"] = string(leafType)

	// Add file-specific metadata
	if leafType == merkle_dag.FileLeafType {
		metadata["size"] = fmt.Sprintf("%d", info.Size())
		metadata["modified_time"] = info.ModTime().Format(time.RFC3339)
		metadata["mode"] = info.Mode().String()

		// Add file extension if present
		if ext := filepath.Ext(entry.Name()); ext != "" {
			metadata["extension"] = ext
		}
	} else if leafType == merkle_dag.DirectoryLeafType {
		metadata["modified_time"] = info.ModTime().Format(time.RFC3339)
		metadata["mode"] = info.Mode().String()
	}

	// For root, add creation timestamp
	if isRoot {
		metadata["dag_created"] = time.Now().Format(time.RFC3339)
	}

	return metadata
}

func UploadDag(ctx context.Context, path string) {
	// Create a new dag from a directory using parallel processing
	log.Println("Creating DAG with parallel processing...")
	startTime := time.Now()

	config := merkle_dag.ParallelConfig()
	config.Processor = FileMetadataProcessor
	dag, err := merkle_dag.CreateDagWithConfig(path, config)

	dagCreationTime := time.Since(startTime)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	log.Printf("DAG created in %v (%d leaves)", dagCreationTime, len(dag.Leafs))

	// Verify the entire dag
	log.Println("Verifying DAG...")
	verifyStartTime := time.Now()
	err = dag.Verify()
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	verifyTime := time.Since(verifyStartTime)

	log.Printf("DAG verified correctly in %v", verifyTime)

	publicKey, err := signing.DeserializePublicKey(npub)
	if err != nil {
		log.Fatal(err)
	}

	_, pubKeyTest, err := signing.DeserializePrivateKey(nsec)
	if err != nil {
		log.Fatal(err)
	}

	test1, err := signing.SerializePublicKey(pubKeyTest)
	if err != nil {
		log.Fatal(err)
	}

	test2, err := signing.SerializePublicKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(*test1)
	fmt.Println(*test2)

	libp2pPubKey, err := signing.ConvertPubKeyToLibp2pPubKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	peerId, err := peer.IDFromPublicKey(*libp2pPubKey)
	if err != nil {
		log.Fatal(err)
	}

	conMgr := connmgr.NewGenericConnectionManager()

	err = conMgr.ConnectWithLibp2p(ctx, "default", fmt.Sprintf("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/%s", peerId.String()), libp2p.Transport(libp2pquic.NewTransport))
	if err != nil {
		log.Fatal(err)
	}

	jsonData, _ := dag.ToJSON()
	os.WriteFile("before_upload.json", jsonData, 0644)

	privateKey, _, err := signing.DeserializePrivateKey(nsec)
	if err != nil {
		log.Fatal(err)
	}

	progressChan := make(chan types.UploadProgress)

	go func() {
		for progress := range progressChan {
			if progress.Error != nil {
				fmt.Printf("Error uploading to %s: %v\n", progress.ConnectionID, progress.Error)
			} else {
				fmt.Printf("Progress for %s: %d/%d leafs uploaded\n", progress.ConnectionID, progress.LeafsSent, progress.TotalLeafs)
			}
		}
	}()

	// Upload the dag to the hornet storage node
	err = connmgr.UploadDagSingle(ctx, conMgr, "default", dag, privateKey, progressChan)
	if err != nil {
		log.Fatal(err)
	}

	close(progressChan)

	conMgr.Disconnect("default")
}

func DownloadDag(ctx context.Context, root string, includeContentStr string) {
	includeContent := includeContentStr == "true" || includeContentStr == "1"

	// Connect to a hornet storage node
	publicKey, err := signing.DeserializePublicKey(npub)
	if err != nil {
		log.Fatal(err)
	}

	libp2pPubKey, err := signing.ConvertPubKeyToLibp2pPubKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	peerId, err := peer.IDFromPublicKey(*libp2pPubKey)
	if err != nil {
		log.Fatal(err)
	}

	conMgr := connmgr.NewGenericConnectionManager()

	err = conMgr.ConnectWithLibp2p(ctx, "default", fmt.Sprintf("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/%s", peerId.String()), libp2p.Transport(libp2pquic.NewTransport))
	if err != nil {
		log.Fatal(err)
	}

	progressChan := make(chan types.DownloadProgress)

	go func() {
		for progress := range progressChan {
			if progress.Error != nil {
				fmt.Printf("Error uploading to %s: %v\n", progress.ConnectionID, progress.Error)
			} else {
				fmt.Printf("Progress for %s: %d leafs downloaded\n", progress.ConnectionID, progress.LeafsRetreived)
			}
		}
	}()

	filter := &types.DownloadFilter{
		IncludeContent: includeContent,
	}

	_, dag, err := connmgr.DownloadDag(ctx, conMgr, "default", root, nil, filter, progressChan)
	if err != nil {
		log.Fatal(err)
	}

	close(progressChan)

	filename := "after_download.json"
	if includeContent {
		filename = "after_download_with_content.json"
	}

	jsonData, _ := json.Marshal(dag.Dag.ToSerializable())
	os.WriteFile(filename, jsonData, 0644)

	log.Printf("DAG saved to %s", filename)

	conMgr.Disconnect("default")
}

func DownloadDagWithRange(ctx context.Context, root string, fromStr string, toStr string, includeContentStr string) {
	from, err := strconv.Atoi(fromStr)
	if err != nil {
		log.Fatalf("Invalid 'from' value: %v", err)
	}

	to, err := strconv.Atoi(toStr)
	if err != nil {
		log.Fatalf("Invalid 'to' value: %v", err)
	}

	includeContent := includeContentStr == "true" || includeContentStr == "1"

	// Connect to a hornet storage node
	publicKey, err := signing.DeserializePublicKey(npub)
	if err != nil {
		log.Fatal(err)
	}

	libp2pPubKey, err := signing.ConvertPubKeyToLibp2pPubKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	peerId, err := peer.IDFromPublicKey(*libp2pPubKey)
	if err != nil {
		log.Fatal(err)
	}

	conMgr := connmgr.NewGenericConnectionManager()

	err = conMgr.ConnectWithLibp2p(ctx, "default", fmt.Sprintf("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/%s", peerId.String()), libp2p.Transport(libp2pquic.NewTransport))
	if err != nil {
		log.Fatal(err)
	}

	filter := &types.DownloadFilter{
		LeafRanges: &types.LeafLabelRange{
			From: from,
			To:   to,
		},
		IncludeContent: includeContent,
	}

	progressChan := make(chan types.DownloadProgress)

	go func() {
		for progress := range progressChan {
			if progress.Error != nil {
				fmt.Printf("Error downloading from %s: %v\n", progress.ConnectionID, progress.Error)
			} else {
				fmt.Printf("Progress for %s: %d leafs downloaded\n", progress.ConnectionID, progress.LeafsRetreived)
			}
		}
	}()

	log.Printf("Downloading leaves %d to %d (includeContent: %v)...", from, to, includeContent)
	_, dag, err := connmgr.DownloadDag(ctx, conMgr, "default", root, nil, filter, progressChan)
	if err != nil {
		log.Fatal(err)
	}

	close(progressChan)

	jsonData, _ := json.Marshal(dag.Dag.ToSerializable())
	filename := fmt.Sprintf("download_range_%d_%d.json", from, to)
	os.WriteFile(filename, jsonData, 0644)
	log.Printf("Downloaded partial DAG saved to %s", filename)

	conMgr.Disconnect("default")
}

func DownloadDagWithHashes(ctx context.Context, root string, hashesStr string, includeContentStr string) {
	hashes := strings.Split(hashesStr, ",")
	if len(hashes) == 0 {
		log.Fatal("No hashes provided")
	}

	includeContent := includeContentStr == "true" || includeContentStr == "1"

	// Connect to a hornet storage node
	publicKey, err := signing.DeserializePublicKey(npub)
	if err != nil {
		log.Fatal(err)
	}

	libp2pPubKey, err := signing.ConvertPubKeyToLibp2pPubKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	peerId, err := peer.IDFromPublicKey(*libp2pPubKey)
	if err != nil {
		log.Fatal(err)
	}

	conMgr := connmgr.NewGenericConnectionManager()

	err = conMgr.ConnectWithLibp2p(ctx, "default", fmt.Sprintf("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/%s", peerId.String()), libp2p.Transport(libp2pquic.NewTransport))
	if err != nil {
		log.Fatal(err)
	}

	filter := &types.DownloadFilter{
		LeafHashes:     hashes,
		IncludeContent: includeContent,
	}

	progressChan := make(chan types.DownloadProgress)

	go func() {
		for progress := range progressChan {
			if progress.Error != nil {
				fmt.Printf("Error downloading from %s: %v\n", progress.ConnectionID, progress.Error)
			} else {
				fmt.Printf("Progress for %s: %d leafs downloaded\n", progress.ConnectionID, progress.LeafsRetreived)
			}
		}
	}()

	log.Printf("Downloading %d specific leaves (includeContent: %v)...", len(hashes), includeContent)
	_, dag, err := connmgr.DownloadDag(ctx, conMgr, "default", root, nil, filter, progressChan)
	if err != nil {
		log.Fatal(err)
	}

	close(progressChan)

	jsonData, _ := json.Marshal(dag.Dag.ToSerializable())
	filename := fmt.Sprintf("download_hashes_%d_leaves.json", len(hashes))
	os.WriteFile(filename, jsonData, 0644)
	log.Printf("Downloaded partial DAG with %d leaves saved to %s", len(hashes), filename)

	conMgr.Disconnect("default")
}

func ReconstructDirectory(ctx context.Context, root string, outputPath string) {
	// Connect to a hornet storage node
	publicKey, err := signing.DeserializePublicKey(npub)
	if err != nil {
		log.Fatal(err)
	}

	libp2pPubKey, err := signing.ConvertPubKeyToLibp2pPubKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	peerId, err := peer.IDFromPublicKey(*libp2pPubKey)
	if err != nil {
		log.Fatal(err)
	}

	conMgr := connmgr.NewGenericConnectionManager()

	err = conMgr.ConnectWithLibp2p(ctx, "default", fmt.Sprintf("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/%s", peerId.String()), libp2p.Transport(libp2pquic.NewTransport))
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Downloading DAG with full content...")
	downloadStartTime := time.Now()

	progressChan := make(chan types.DownloadProgress)

	go func() {
		for progress := range progressChan {
			if progress.Error != nil {
				fmt.Printf("Error downloading from %s: %v\n", progress.ConnectionID, progress.Error)
			} else {
				fmt.Printf("Progress for %s: %d leafs downloaded\n", progress.ConnectionID, progress.LeafsRetreived)
			}
		}
	}()

	// Download with content included
	filter := &types.DownloadFilter{
		IncludeContent: true,
	}

	_, dag, err := connmgr.DownloadDag(ctx, conMgr, "default", root, nil, filter, progressChan)
	if err != nil {
		log.Fatal(err)
	}

	close(progressChan)
	downloadTime := time.Since(downloadStartTime)
	log.Printf("DAG downloaded in %v (%d leaves)", downloadTime, len(dag.Dag.Leafs))

	// Reconstruct directory structure
	log.Printf("Reconstructing directory structure to: %s", outputPath)
	reconstructStartTime := time.Now()

	err = dag.Dag.CreateDirectory(outputPath)
	if err != nil {
		log.Fatalf("Failed to reconstruct directory: %v", err)
	}

	reconstructTime := time.Since(reconstructStartTime)
	log.Printf("Directory reconstructed in %v", reconstructTime)

	conMgr.Disconnect("default")
}

func QueryDag() {
	ctx := context.Background()

	// Connect to a hornet storage node
	publicKey, err := signing.DeserializePublicKey(npub)
	if err != nil {
		log.Fatal(err)
	}

	libp2pPubKey, err := signing.ConvertPubKeyToLibp2pPubKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	peerId, err := peer.IDFromPublicKey(*libp2pPubKey)
	if err != nil {
		log.Fatal(err)
	}

	conMgr := connmgr.NewGenericConnectionManager()

	err = conMgr.ConnectWithLibp2p(ctx, "default", fmt.Sprintf("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/%s", peerId.String()), libp2p.Transport(libp2pquic.NewTransport))
	if err != nil {
		log.Fatal(err)
	}

	query := types.QueryFilter{
		Tags: map[string]string{
			"repo_id": "51c014af93d6c4c8a2fe0a710046194a00e1f0558db97bf3c7b80a5967b6a75f:nosis",
		},
	}

	// Upload the dag to the hornet storage node
	hashes, err := connmgr.QueryDag(ctx, conMgr, "default", query)
	if err != nil {
		log.Fatal(err)
	}

	data, err := json.Marshal(hashes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("RESULTS")

	for _, hash := range hashes {
		fmt.Println(hash)
	}

	fmt.Println(data)

	if len(hashes) > 0 {
		for _, hash := range hashes {
			_, dag, err := connmgr.DownloadDag(ctx, conMgr, "default", hash, nil, nil, nil)
			if err != nil {
				log.Fatal(err)
			}

			jsonData, _ := json.Marshal(dag.Dag.ToSerializable())
			os.WriteFile(fmt.Sprintf("%s.json", hash), jsonData, 0644)
		}
	}

	// Disconnect client as we no longer need it
	conMgr.Disconnect("default")
}

func UploadEvent(ctx context.Context) {
	// Construct content for metadata event
	metadataContent := map[string]string{
		"name":    "TestName",
		"about":   "TestAbout",
		"picture": "TestPicture",
	}

	// Serialize content to JSON
	contentBytes, err := json.Marshal(metadataContent)
	if err != nil {
		log.Fatal(err)
	}
	content := string(contentBytes)

	// Create event object
	event := &nostr.Event{
		PubKey:    npub,
		CreatedAt: nostr.Now(),
		Kind:      0,
		Tags: []nostr.Tag{
			{"e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://nostr.example.com"},
			{"p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca"},
		},
		Content: content,
	}

	event.Sign(signing.TrimPrivateKey(nsec))

	success, err := event.CheckSignature()
	if err != nil {
		log.Fatal(err)
	}

	if !success {
		log.Fatal(fmt.Errorf("failed to verify event signature"))
	}

	log.Println("Event sorted")

	// Connect to a hornet storage node
	publicKey, err := signing.DeserializePublicKey(npub)
	if err != nil {
		log.Fatal(err)
	}

	libp2pPubKey, err := signing.ConvertPubKeyToLibp2pPubKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	peerId, err := peer.IDFromPublicKey(*libp2pPubKey)
	if err != nil {
		log.Fatal(err)
	}

	conMgr := connmgr.NewGenericConnectionManager()

	err = conMgr.ConnectWithLibp2p(ctx, "default", fmt.Sprintf("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/%s", peerId.String()), libp2p.Transport(libp2pquic.NewTransport))
	if err != nil {
		log.Fatal(err)
	}

	results, err := connmgr.SendUniversalEvent(ctx, conMgr, event, nil)
	if err != nil {
		log.Fatal(err)
	}

	okEnv, ok := results["default"]
	if !ok {
		log.Fatal("Did not get a valid response")
	}

	fmt.Println(okEnv.EventID + " | " + okEnv.Reason)

	filter := nostr.Filter{
		IDs: []string{okEnv.EventID},
	}

	subId := "default"
	events, err := connmgr.QueryEvents(ctx, conMgr, "default", []nostr.Filter{filter}, &subId)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Logging events")

	for _, event := range events {
		fmt.Printf("Found Event %s of kind %d", event.ID, event.Kind)
	}
}

func TestKeys(ctx context.Context) {
	// Connect to a hornet storage node
	publicKey, err := signing.DeserializePublicKey(npub)
	if err != nil {
		log.Fatal(err)
	}

	libp2pPubKey, err := signing.ConvertPubKeyToLibp2pPubKey(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	peerId, err := peer.IDFromPublicKey(*libp2pPubKey)
	if err != nil {
		log.Fatal(err)
	}

	privKey, pubKey, err := signing.DeserializePrivateKey(nsec)
	if err != nil {
		log.Fatal(err)
	}

	spr, err := signing.SerializePrivateKey(privKey)
	if err != nil {
		log.Fatal(err)
	}

	sp, err := signing.SerializePublicKey(pubKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("private (hex): " + *spr)
	log.Println("public (hex): " + *sp)

	log.Printf("Keys deserialized properly and your libp2p peer id is: %s\n", peerId)
}

func TimeCheck(eventCreatedAt int64) (bool, string) {
	const timeCutoff = 5 * time.Minute // Define your own cutoff threshold
	eventTime := time.Unix(eventCreatedAt, 0)

	// Check if the event timestamp is too far in the past or future
	if time.Since(eventTime) > timeCutoff || time.Until(eventTime) > timeCutoff {
		errMsg := fmt.Sprintf("invalid: event creation date is too far off from the current time (%s)", eventTime)
		return false, errMsg
	}
	return true, ""
}
