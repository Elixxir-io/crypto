////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"gitlab.com/xx_network/crypto/csprng"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// Tests that a URL created via Channel.ShareURL can be decoded using
// DecodeShareURL and that it matches the original.
func TestChannel_ShareURL_DecodeShareURL(t *testing.T) {
	host := "https://internet.speakeasy.tech/"
	rng := csprng.NewSystemRNG()

	for _, level := range []PrivacyLevel{Public, Private, Secret} {
		c, _, err := NewChannel("My Channel",
			"Here is information about my channel.", level, 1000, rng)
		if err != nil {
			t.Fatalf("Failed to create new %s channel: %+v", level, err)
		}

		address, password, err := c.ShareURL(host, rng)
		if err != nil {
			t.Fatalf("Failed to create %s URL: %+v", level, err)
		}

		newChannel, err := DecodeShareURL(address, password)
		if err != nil {
			t.Errorf("Failed to decode %s URL: %+v", level, err)
		}

		if !reflect.DeepEqual(*c, *newChannel) {
			t.Errorf("Decoded %s channel does not match original."+
				"\nexpected: %+v\nreceived: %+v", level, *c, *newChannel)
		}
	}
}

// Tests that Channel.ShareURL returns an error for an invalid host.
func TestChannel_ShareURL_ParseError(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("A", "B", Public, 1000, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	host := "invalidHost\x7f"
	expectedErr := strings.Split(parseHostUrlErr, "%")[0]

	_, _, err = c.ShareURL(host, rng)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Did not receive expected error for URL %q."+
			"\nexpected: %s\nreceived: %+v", host, expectedErr, err)
	}
}

// Tests that DecodeShareURL returns an error for an invalid host.
func TestDecodeShareURL_ParseError(t *testing.T) {
	host := "invalidHost\x7f"
	expectedErr := strings.Split(parseShareUrlErr, "%")[0]

	_, err := DecodeShareURL(host, "")
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Did not receive expected error for URL %q."+
			"\nexpected: %s\nreceived: %+v", host, expectedErr, err)
	}
}

// Tests that DecodeShareURL returns an error when NewChannelID returns an error
// due to the salt size being incorrect.
func TestDecodeShareURL_NewChannelIDError(t *testing.T) {
	address := "https://internet.speakeasy.tech/" +
		"?0Name=My+Channel" +
		"&1Description=Here+is+information+about+my+channel." +
		"&2Level=Public" +
		"&e=z73XYenRG65WHmJh8r%2BanZ71r2rPOHjTgCSEh05TUlQ%3D" +
		"&k=9b1UtGnZ%2B%2FM3hnXTfNRN%2BZKXcsHyZE00vZ9We0oDP90%3D" +
		"&l=493" +
		"&p=1" +
		"&s=8tJb%2FC9j26MJEfb%2F2463YQ%3D%3D" +
		"&v=0"
	expectedErr := strings.Split(newReceptionIdErr, "%")[0]

	_, err := DecodeShareURL(address, "")
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Did not receive expected error for URL %q."+
			"\nexpected: %s\nreceived: %+v", address, expectedErr, err)
	}

}

// Tests that DecodeShareURL returns errors for a list of invalid URLs.
func TestDecodeShareURL_Error(t *testing.T) {
	type test struct {
		url, password, err string
	}

	tests := []test{
		{"test?", "", urlVersionErr},
		{"test?v=0", "", malformedUrlErr},
		{"test?v=q", "", parseVersionErr},
		{"test?v=2", "", versionErr},
		{"test?v=0&s=AA==", "", parseLevelErr},
		{"test?v=0&0Name=2", "", noPasswordErr},
		{"test?v=0&d=2", "", noPasswordErr},
		{"test?v=0&s=A&2Level=Public", "", parseSaltErr},
		{"test?v=0&s=AA==&2Level=Public&k=A", "", parseRsaPubKeyHashErr},
		{"test?v=0&s=AA==&2Level=Public&k=AA==&l=q", "", parseRsaPubKeyLengthErr},
		{"test?v=0&s=AA==&2Level=Public&k=AA==&l=5&p=t", "", parseRsaSubPayloadsErr},
		{"test?v=0&s=AA==&2Level=Public&k=AA==&l=5&p=1&e=A", "", parseSecretErr},
		{"test?v=0&0Name=2", "hello", decryptErr},
		{"test?v=0&d=2", "hello", decodeEncryptedErr},
	}

	for i, tt := range tests {
		expected := strings.Split(tt.err, "%")[0]

		_, err := DecodeShareURL(tt.url, tt.password)
		if err == nil || !strings.Contains(err.Error(), expected) {
			t.Errorf("Did not receive expected error for URL %q (%d)."+
				"\nexpected: %s\nreceived: %+v", tt.url, i, expected, err)
		}
	}
}

// Tests that a channel can be encoded to a URL using
// Channel.encodePublicShareURL and decoded to a new channel using
// Channel.decodePublicShareURL and that it matches the original.
func TestChannel_encodePublicShareURL_decodePublicShareURL(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test Channel", "Description", Public, 1000, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	urlValues := make(url.Values)
	urlValues = c.encodePublicShareURL(urlValues)

	var newChannel Channel
	err = newChannel.decodePublicShareURL(urlValues)
	if err != nil {
		t.Errorf("Error decoding URL values: %+v", err)
	}

	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID

	if !reflect.DeepEqual(*c, newChannel) {
		t.Errorf("Decoded channel does not match original."+
			"\nexpected: %+v\nreceived: %+v", *c, newChannel)
	}
}

// Tests that a channel can be encoded to a URL using
// Channel.encodePrivateShareURL and decoded to a new channel using
// Channel.decodePrivateShareURL and that it matches the original.
func TestChannel_encodePrivateShareURL_decodePrivateShareURL(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test Channel", "Description", Private, 1000, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	const password = "password"
	urlValues := make(url.Values)
	urlValues = c.encodePrivateShareURL(urlValues, password, rng)

	var newChannel Channel
	err = newChannel.decodePrivateShareURL(urlValues, password)
	if err != nil {
		t.Errorf("Error decoding URL values: %+v", err)
	}

	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID

	if !reflect.DeepEqual(*c, newChannel) {
		t.Errorf("Decoded channel does not match original."+
			"\nexpected: %+v\nreceived: %+v", *c, newChannel)
	}
}

// Tests that a channel can be encoded to a URL using
// Channel.encodeSecretShareURL and decoded to a new channel using
// Channel.decodeSecretShareURL and that it matches the original.
func TestChannel_encodeSecretShareURL_decodeSecretShareURL(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test Channel", "Description", Secret, 1000, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	const password = "password"
	urlValues := make(url.Values)
	urlValues = c.encodeSecretShareURL(urlValues, password, rng)

	var newChannel Channel
	err = newChannel.decodeSecretShareURL(urlValues, password)
	if err != nil {
		t.Errorf("Error decoding URL values: %+v", err)
	}

	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID

	if !reflect.DeepEqual(*c, newChannel) {
		t.Errorf("Decoded channel does not match original."+
			"\nexpected: %+v\nreceived: %+v", *c, newChannel)
	}
}

// Tests that a channel marshalled with Channel.marshalPrivateShareUrlSecrets
// and unmarshalled with Channel.unmarshalPrivateShareUrlSecrets matches the
// original, except for the Name, Description, and ReceptionID, which are added
// in the layer above.
func TestChannel_marshalPrivateShareUrlSecrets_unmarshalPrivateShareUrlSecrets(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test Channel", "Description", Private, 1000, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	data := c.marshalPrivateShareUrlSecrets()

	var newChannel Channel
	err = newChannel.unmarshalPrivateShareUrlSecrets(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal private channel data: %+v", err)
	}

	// Name, description, and reception ID are set at the layer above
	newChannel.Name = c.Name
	newChannel.Description = c.Description
	newChannel.ReceptionID = c.ReceptionID

	if !reflect.DeepEqual(*c, newChannel) {
		t.Errorf("Unmarshalled channel does not match original."+
			"\nexpected: %+v\nreceived: %+v", *c, newChannel)
	}
}

// Tests that channel.unmarshalPrivateShareUrlSecrets returns errors for a list
// of invalid URLs.
func TestChannel_unmarshalPrivateShareUrlSecrets_Errors(t *testing.T) {
	type test struct {
		data []byte
		err  string
	}

	rsaPubKeyHashLen := 10
	data := make([]byte, 1+saltSize+uint8Len)
	binary.LittleEndian.PutUint64(
		data[1+saltSize:1+saltSize+uint8Len],
		uint64(rsaPubKeyHashLen))

	tests := []test{
		{[]byte{}, readPrivacyLevelErr},
		{[]byte{1}, readSaltErr},
		{[]byte{1, 2},
			fmt.Sprintf(readSaltNumBytesErr, saltSize, 1)},
		{make([]byte, 1+saltSize), readRsaPubKeyHashLenErr},
		{make([]byte, 1+saltSize+2),
			fmt.Sprintf(readRsaPubKeyHashLenNumBytesErr, uint8Len, 2)},
		{data, readRsaPubKeyHashErr},
		{append(data, []byte{1}...),
			fmt.Sprintf(readRsaPubKeyHashNumBytesErr, rsaPubKeyHashLen, 1)},
		{append(data, make([]byte, rsaPubKeyHashLen)...), readRsaPubKeyLenErr},
		{append(data, make([]byte, rsaPubKeyHashLen+1)...),
			fmt.Sprintf(readRsaPubKeyLenNumBytesErr, uint8Len, 1)},
		{append(data, make([]byte, rsaPubKeyHashLen+uint8Len)...), readRSASubPayloadsErr},
		{append(data, make([]byte, rsaPubKeyHashLen+uint8Len+1)...),
			fmt.Sprintf(readRSASubPayloadsNumBytesErr, uint8Len, 1)},
		{append(data, make([]byte, rsaPubKeyHashLen+uint8Len+uint8Len)...), readSecretErr},
		{append(data, make([]byte, rsaPubKeyHashLen+uint8Len+secretSize+1)...),
			fmt.Sprintf(readSecretNumBytesErr, secretSize, 25)},
	}

	for i, tt := range tests {
		expected := strings.Split(tt.err, "%")[0]

		c := &Channel{}
		err := c.unmarshalPrivateShareUrlSecrets(tt.data)
		if err == nil || !strings.Contains(err.Error(), expected) {
			t.Errorf("Did not receive expected error test %d."+
				"\nexpected: %s\nreceived: %+v", i, expected, err)
		}
	}
}

// Tests that a channel marshalled with Channel.marshalSecretShareUrlSecrets and
// unmarshalled with Channel.unmarshalSecretShareUrlSecrets matches the
// original, except for the ReceptionID, which is added in the layer above.
func TestChannel_marshalSecretShareUrlSecrets_unmarshalSecretShareUrlSecrets(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test Channel", "Description", Secret, 1000, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	data := c.marshalSecretShareUrlSecrets()

	var newChannel Channel
	err = newChannel.unmarshalSecretShareUrlSecrets(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal secret channel data: %+v", err)
	}

	// Reception ID is set at the layer above
	newChannel.ReceptionID = c.ReceptionID

	if !reflect.DeepEqual(*c, newChannel) {
		t.Errorf("Unmarshalled channel does not match original."+
			"\nexpected: %+v\nreceived: %+v", *c, newChannel)
	}
}

// Tests that channel.unmarshalSecretShareUrlSecrets returns errors for a list
// of invalid URLs.
func TestChannel_unmarshalSecretShareUrlSecrets_Errors(t *testing.T) {
	type test struct {
		data []byte
		err  string
	}

	nameDescData := []byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1}
	rsaPubKeyHashLen := 10
	data := append(nameDescData, make([]byte, saltSize+uint8Len)...)
	binary.LittleEndian.PutUint64(
		data[len(nameDescData)+saltSize:len(nameDescData)+saltSize+uint8Len],
		uint64(rsaPubKeyHashLen))

	tests := []test{
		{[]byte{}, readPrivacyLevelErr},
		{[]byte{1}, readNameLenErr},
		{[]byte{1, 1},
			fmt.Sprintf(readNameLenNumBytesErr, uint8Len, 1)},
		{[]byte{1, 1, 0, 0, 0, 0, 0, 0, 0}, readNameErr},
		{[]byte{1, 2, 0, 0, 0, 0, 0, 0, 0, 1},
			fmt.Sprintf(readNameNumBytesErr, 2, 1)},
		{[]byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 1}, readDescLenErr},
		{[]byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 2},
			fmt.Sprintf(readDescLenNumBytesErr, uint8Len, 1)},
		{[]byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0},
			readDescErr},
		{[]byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 1},
			fmt.Sprintf(readDescNumBytesErr, 2, 1)},

		{nameDescData, readSaltErr},
		{append(nameDescData, []byte{1, 2}...),
			fmt.Sprintf(readSaltNumBytesErr, saltSize, 2)},
		{append(nameDescData, make([]byte, saltSize)...), readRsaPubKeyHashLenErr},
		{append(nameDescData, make([]byte, saltSize+2)...),
			fmt.Sprintf(readRsaPubKeyHashLenNumBytesErr, uint8Len, 2)},
		{data, readRsaPubKeyHashErr},
		{append(data, []byte{1}...),
			fmt.Sprintf(readRsaPubKeyHashNumBytesErr, rsaPubKeyHashLen, 1)},
		{append(data, make([]byte, rsaPubKeyHashLen)...), readRsaPubKeyLenErr},
		{append(data, make([]byte, rsaPubKeyHashLen+1)...),
			fmt.Sprintf(readRsaPubKeyLenNumBytesErr, uint8Len, 1)},
		{append(data, make([]byte, rsaPubKeyHashLen+uint8Len)...), readRSASubPayloadsErr},
		{append(data, make([]byte, rsaPubKeyHashLen+uint8Len+1)...),
			fmt.Sprintf(readRSASubPayloadsNumBytesErr, uint8Len, 1)},
		{append(data, make([]byte, rsaPubKeyHashLen+uint8Len+uint8Len)...), readSecretErr},
		{append(data, make([]byte, rsaPubKeyHashLen+uint8Len+secretSize+1)...),
			fmt.Sprintf(readSecretNumBytesErr, secretSize, 25)},
	}

	for i, tt := range tests {
		expected := strings.Split(tt.err, "%")[0]

		c := &Channel{}
		err := c.unmarshalSecretShareUrlSecrets(tt.data)
		if err == nil || !strings.Contains(err.Error(), expected) {
			t.Errorf("Did not receive expected error test %d."+
				"\nexpected: %s\nreceived: %+v", i, expected, err)
		}
	}
}

// Smoke test of encryptShareURL and decryptShareURL.
func Test_encryptShareURL_decryptShareURL(t *testing.T) {
	plaintext := []byte("Hello, World!")
	password := "test_password"
	ciphertext := encryptShareURL(plaintext, password, rand.Reader)
	decrypted, err := decryptShareURL(ciphertext, password)
	if err != nil {
		t.Errorf("%+v", err)
	}

	for i := range plaintext {
		if plaintext[i] != decrypted[i] {
			t.Errorf("%b != %b", plaintext[i], decrypted[i])
		}
	}
}

// Tests that decryptShareURL does not panic when given too little data.
func Test_decryptShareURL_ShortData(t *testing.T) {
	// Anything under 24 should cause an error.
	ciphertext := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	_, err := decryptShareURL(ciphertext, "dummyPassword")
	if err == nil {
		t.Errorf("Expected error on short decryption")
	}

	expectedErrMsg := "Read 24 bytes, too short to decrypt"
	if err.Error()[:len(expectedErrMsg)] != expectedErrMsg {
		t.Errorf("Unexpected error: %+v", err)
	}

	// Empty string shouldn't panic should cause an error.
	ciphertext = []byte{}
	_, err = decryptShareURL(ciphertext, "dummyPassword")
	if err == nil {
		t.Errorf("Expected error on short decryption")
	}

	expectedErrMsg = "Read 0 bytes, too short to decrypt"
	if err.Error()[:len(expectedErrMsg)] != expectedErrMsg {
		t.Errorf("Unexpected error: %+v", err)
	}
}
