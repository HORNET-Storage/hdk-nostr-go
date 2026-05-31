package signing

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

const PublicKeyPrefix = "npub"
const PrivateKeyPrefix = "nsec"

func DecodeKey(serializedKey string) ([]byte, error) {
	bytes, err := hex.DecodeString(TrimPrivateKey(TrimPublicKey(serializedKey)))
	if err != nil {
		_, bytesToBits, err := bech32.Decode(serializedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key from hex or bech32: %v", err)
		}

		bytes, err = bech32.ConvertBits(bytesToBits, 5, 8, false)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key from hex or bech32: %v", err)
		}
	}

	return bytes, nil
}

func DeserializePrivateKey(serializedKey string) (*secp256k1.PrivateKey, *secp256k1.PublicKey, error) {
	privateKeyBytes, err := DecodeKey(serializedKey)
	if err != nil {
		return nil, nil, err
	}

	privateKey, publicKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	return privateKey, publicKey, nil
}

func DeserializePublicKey(serializedKey string) (*secp256k1.PublicKey, error) {
	publicKeyBytes, err := DecodeKey(serializedKey)
	if err != nil {
		return nil, err
	}

	// Check if this is already a compressed key (33 bytes with compression flag)
	if len(publicKeyBytes) == 33 && (publicKeyBytes[0] == 0x02 || publicKeyBytes[0] == 0x03) {
		// This is already compressed, parse it directly to preserve compression flag
		publicKey, err := btcec.ParsePubKey(publicKeyBytes)
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	}

	// For 32-byte keys (Nostr format), try both compression flags
	if len(publicKeyBytes) == 32 {
		// Try with 0x03 flag first (odd y-coordinate)
		compressedBytes2 := append([]byte{0x03}, publicKeyBytes...)
		if publicKey, err := btcec.ParsePubKey(compressedBytes2); err == nil {
			return publicKey, nil
		}

		// Try with 0x02 flag (even y-coordinate)
		compressedBytes1 := append([]byte{0x02}, publicKeyBytes...)
		if publicKey, err := btcec.ParsePubKey(compressedBytes1); err == nil {
			return publicKey, nil
		}

		return nil, fmt.Errorf("unable to parse 32-byte public key with either compression flag")
	}

	// Fallback: use schnorr parsing for other formats
	publicKey, err := schnorr.ParsePubKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func TrimPrivateKey(privateKey string) string {
	return strings.TrimPrefix(privateKey, PrivateKeyPrefix+"1")
}

func TrimPublicKey(publicKey string) string {
	return strings.TrimPrefix(publicKey, PublicKeyPrefix+"1")
}

func SignData(data []byte, privateKey *btcec.PrivateKey) (*schnorr.Signature, error) {
	signature, err := schnorr.Sign(privateKey, data)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func SignCID(cid cid.Cid, privateKey *btcec.PrivateKey) (*schnorr.Signature, error) {
	hashed := sha256.Sum256(cid.Bytes())

	signature, err := SignData(hashed[:], privateKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func SignSerializedCid(serializedCid string, privateKey *btcec.PrivateKey) (*schnorr.Signature, error) {
	cid, err := cid.Parse(serializedCid)
	if err != nil {
		return nil, err
	}

	return SignCID(cid, privateKey)
}

func VerifySignature(signature *schnorr.Signature, data []byte, publicKey *secp256k1.PublicKey) error {
	result := signature.Verify(data, publicKey)
	if !result {
		return fmt.Errorf("data failed to verify")
	}

	return nil
}

func VerifyCIDSignature(signature *schnorr.Signature, cid cid.Cid, publicKey *secp256k1.PublicKey) error {
	hashed := sha256.Sum256(cid.Bytes())

	err := VerifySignature(signature, hashed[:], publicKey)
	if err != nil {
		return err
	}

	return nil
}

func VerifySerializedCIDSignature(signature *schnorr.Signature, serializedCid string, publicKey *secp256k1.PublicKey) error {
	cid, err := cid.Parse(serializedCid)
	if err != nil {
		return err
	}

	return VerifyCIDSignature(signature, cid, publicKey)
}

func GeneratePrivateKey() (*secp256k1.PrivateKey, error) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func SerializePrivateKeyBech32(privateKey *secp256k1.PrivateKey) (*string, error) {
	privateKeyBytes := privateKey.Serialize()

	bytes, err := bech32.ConvertBits(privateKeyBytes, 8, 5, true)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key from hex or bech32: %v", err)
	}

	encodedKey, err := bech32.Encode(PrivateKeyPrefix, bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key from hex or bech32: %v", err)
	}

	return &encodedKey, nil
}

func SerializePublicKeyBech32(publicKey *secp256k1.PublicKey) (*string, error) {
	publicKeyBytes := schnorr.SerializePubKey(publicKey)

	bytes, err := bech32.ConvertBits(publicKeyBytes, 8, 5, true)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key from hex or bech32: %v", err)
	}

	encodedKey, err := bech32.Encode(PublicKeyPrefix, bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key from hex or bech32: %v", err)
	}

	return &encodedKey, nil
}

func SerializePrivateKey(privateKey *secp256k1.PrivateKey) (*string, error) {
	privateKeyBytes := privateKey.Serialize()

	encodedKey := hex.EncodeToString(privateKeyBytes)

	return &encodedKey, nil
}

func SerializePublicKey(publicKey *secp256k1.PublicKey) (*string, error) {
	publicKeyBytes := schnorr.SerializePubKey(publicKey)

	encodedKey := hex.EncodeToString(publicKeyBytes)

	return &encodedKey, nil
}

// ConvertPubKeyToLibp2pPubKey converts a public key directly to a libp2p public key
func ConvertPubKeyToLibp2pPubKey(publicKey *secp256k1.PublicKey) (*crypto.PubKey, error) {
	compressedPubKey := publicKey.SerializeCompressed()

	libp2pPubKey, err := crypto.UnmarshalSecp256k1PublicKey(compressedPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal to libp2p key: %w", err)
	}

	return &libp2pPubKey, nil
}

// ConvertPubKeyToLibp2pPeerID converts a public key directly to a peer ID string
func ConvertPubKeyToLibp2pPeerID(publicKey *secp256k1.PublicKey) (string, error) {
	libp2pPubKey, err := ConvertPubKeyToLibp2pPubKey(publicKey)
	if err != nil {
		return "", err
	}

	peerId, err := peer.IDFromPublicKey(*libp2pPubKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate peer ID: %w", err)
	}

	return peerId.String(), nil
}
