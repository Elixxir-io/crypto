////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"crypto/rand"
	"gitlab.com/xx_network/crypto/csprng"
	"net/url"
	"reflect"
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
	address, _, err := c.ShareURL(host, rng)
	if err == nil {
		t.Errorf("Expected error for invalid host URL: %s", address)
	}
}

// Tests that DecodeShareURL returns errors for a list of invalid URLs.
func TestChannel_DecodeShareURL(t *testing.T) {
	invalidURLs := []string{
		"test?",
		"test?v=0",
		"test?v=0&d=2",
	}

	for _, u := range invalidURLs {
		_, err := DecodeShareURL(u, "")
		if err == nil {
			t.Errorf("Expected error for invalid URL: %s", u)
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
