package signing

import "testing"

func TestSerializePublicKeyBech32UsesNIP19Prefix(t *testing.T) {
	const hexPubkey = "51c014af93d6c4c8a2fe0a710046194a00e1f0558db97bf3c7b80a5967b6a75f"
	const expectedNpub = "npub128qpftun6mzv3gh7pfcsq3sefgqwruz43kuhhu78hq99jeak5a0sstnu23"

	publicKey, err := DeserializePublicKey(hexPubkey)
	if err != nil {
		t.Fatalf("DeserializePublicKey failed: %v", err)
	}

	npub, err := SerializePublicKeyBech32(publicKey)
	if err != nil {
		t.Fatalf("SerializePublicKeyBech32 failed: %v", err)
	}
	if *npub != expectedNpub {
		t.Fatalf("expected %q, got %q", expectedNpub, *npub)
	}

	decoded, err := DeserializePublicKey(expectedNpub)
	if err != nil {
		t.Fatalf("DeserializePublicKey npub failed: %v", err)
	}
	serialized, err := SerializePublicKey(decoded)
	if err != nil {
		t.Fatalf("SerializePublicKey failed: %v", err)
	}
	if *serialized != hexPubkey {
		t.Fatalf("expected decoded public key %q, got %q", hexPubkey, *serialized)
	}
}
