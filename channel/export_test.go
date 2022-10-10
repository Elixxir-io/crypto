////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"fmt"
	"gitlab.com/xx_network/crypto/csprng"
	"reflect"
	"testing"
)

func TestImportPrivateIdentity(t *testing.T) {
}

func TestPrivateIdentity_export(t *testing.T) {
}

func TestPrivateIdentity_encrypt(t *testing.T) {
	rng := &csprng.SystemRNG{}
	pi, err := GenerateIdentity(rng)
	if err != nil {
		t.Fatalf("Failed to gener identity: %+v", err)
	}

	password := "hunter2"
	params := testParams()
	encryptedData, salt, err := pi.encrypt(password, params, rng)
	if err != nil {
		t.Errorf("Failed to encrypt PrivateIdentity: %+v", err)
	}

	key := deriveKey(password, salt, params)
	decryptedData, err := decryptIdentity(encryptedData, key)
	if err != nil {
		t.Errorf("Failed to decrypt PrivateIdentity: %+v", err)
	}

	newPi, err := decodePrivateIdentity(decryptedData)
	if err != nil {
		t.Errorf("Failed to decode PrivateIdentity: %+v", err)
	}

	if !reflect.DeepEqual(pi, newPi) {
		t.Errorf("Decrypted PrivateIdentity does not match original."+
			"\nexpected: %+v\nreceived: %+v", pi, newPi)
	}
}

// Tests that a PrivateIdentity marshalled via PrivateIdentity.encode
// and unmarshalled via decodePrivateIdentity matches the original.
func TestPrivateIdentity_encode_decodePrivateIdentity(t *testing.T) {
	pi, err := GenerateIdentity(&csprng.SystemRNG{})
	if err != nil {
		t.Fatalf("Failed to gener identity: %+v", err)
	}

	data := pi.encode()

	newPi, err := decodePrivateIdentity(data)
	if err != nil {
		t.Errorf("Failed to unmarshal encrypted data: %+v", err)
	}

	if !reflect.DeepEqual(pi, newPi) {
		t.Errorf("Unmarshalled PrivateIdentity does not match original."+
			"\nexpected: %+v\nreceived: %+v", pi, newPi)
	}
}

// Error path: Tests that decodePrivateIdentity returns the expected error when the
// data passed in is of the wrong length.
func Test_decodePrivateIdentity_DataLengthError(t *testing.T) {
	pi, err := GenerateIdentity(&csprng.SystemRNG{})
	if err != nil {
		t.Fatalf("Failed to gener identity: %+v", err)
	}

	data := pi.encode()[5:]

	expectedErr := fmt.Sprintf(
		unmarshalDataLenErr, encodedLen, len(data))

	_, err = decodePrivateIdentity(data)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not receive expected error for data that is too short."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that decodePrivateIdentity returns the expected error when the
// data has an incorrect version.
func Test_decodePrivateIdentity_IncorrectVersionError(t *testing.T) {
	pi, err := GenerateIdentity(&csprng.SystemRNG{})
	if err != nil {
		t.Fatalf("Failed to gener identity: %+v", err)
	}

	data := pi.encode()
	data[0] = currentEncryptedVersion + 1

	expectedErr := fmt.Sprintf(
		versionMismatchErr, data[0], currentEncryptedVersion)

	_, err = decodePrivateIdentity(data)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not receive expected error with an incorrect version."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Happy path.
func Test_getTagContents(t *testing.T) {
	testData := map[string]string{
		"test1": "ABC123" + headTag + "test1" + footTag + "DEF456",
		"test2": "Hello, world!" + headTag + "test2" + footTag + "Lorem ipsum" + headTag + "test2" + footTag + "-/-*",
	}

	for expected, str := range testData {
		received, err := getTagContents([]byte(str), headTag, footTag)
		if err != nil {
			t.Errorf("Failed to get tag contents from string %s", str)
		}

		if expected != string(received) {
			t.Errorf("Failed to get the expected contents."+
				"\nexpected: %s\nreceived: %s", expected, received)
		}
	}
}

// Tests that getTagContents returns the expected error for a set of strings
// with invalid tag placement.
func Test_getTagContents_MissingTagsError(t *testing.T) {

	testData := map[string]string{
		"ABC123" + headTag + "test1" + "ABC123":                                noCloseTagErr,
		"ABC123" + footTag + "test2" + headTag + "ABC123":                      swappedTagErr,
		"ABC123" + footTag + "test3" + "ABC123" + footTag + "test3" + "ABC123": noOpenTagErr,
	}

	for str, expected := range testData {
		_, err := getTagContents([]byte(str), headTag, footTag)
		if err == nil || err.Error() != expected {
			t.Errorf("Did not get expected error for invalid tag placement."+
				"\nexpected: %s\nexpected: %+v", expected, str)
		}
	}
}
