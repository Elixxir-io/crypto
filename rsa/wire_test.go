package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"golang.org/x/crypto/blake2b"
	"testing"
)

func TestMarshalUnMarshalWire(t *testing.T) {
	sLocal := GetScheme()
	serverPrivKey, err := sLocal.Generate(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	serverPubKey := serverPrivKey.Public()
	serverPubKeyBytes := serverPubKey.MarshalWire()
	serverPubKey2, err := sLocal.UnmarshalPublicKeyWire(serverPubKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	serverPubKey2Bytes := serverPubKey2.MarshalWire()
	if !bytes.Equal(serverPubKeyBytes, serverPubKey2Bytes) {
		t.Fatal("byte slices don't match")
	}

	message := []byte("fluffy bunny")
	hashed := blake2b.Sum256(message)
	signature, err := serverPrivKey.SignPSS(rand.Reader, crypto.BLAKE2b_256, hashed[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	err = serverPubKey2.VerifyPSS(crypto.BLAKE2b_256, hashed[:], signature, nil)
	if err != nil {
		t.Fatal(err)
	}
}

// Smoke test.
func TestPublic_GetMarshalWireLength(t *testing.T) {
	sLocal := GetScheme()
	val := 24

	// This is the equation used in GetMarshalWireLength as of writing
	expectedVal := val + ELength
	if sLocal.GetMarshalWireLength(val) != expectedVal {
		t.Fatalf("GetMarshalWireLength did not return expected value."+
			"\nExpected: %d"+
			"\nReceived: %v", expectedVal, sLocal.GetMarshalWireLength(val))
	}
}

// Error case: Tests that passing in bytes too short to be unmarshalled
// returns an error (ErrTooShortToUnmarshal).
func TestScheme_UnmarshalPublicKeyWire_Error(t *testing.T) {
	sLocal := GetScheme()
	dataTooShort := []byte{1}

	_, err := sLocal.UnmarshalPublicKeyWire(dataTooShort)
	if err == nil {
		t.Fatalf("Unmarshalled data too short for a public key")
	}
}

func TestWireLength(t *testing.T) {
	sLocal := GetScheme()
	serverPrivKey, err := sLocal.Generate(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	serverPubKey := serverPrivKey.Public()
	serverPubKeyBytes := serverPubKey.MarshalWire()
	wireLength := serverPubKey.GetMarshalWireLength()

	if len(serverPubKeyBytes)!=wireLength{
		t.Errorf("Wire length returned is not the same as the actual " +
			"wire length, %d vs %d", wireLength, len(serverPubKeyBytes))
	}

}