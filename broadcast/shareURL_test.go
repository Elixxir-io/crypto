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
	"strings"
	"testing"
)

// Tests that a URL created via Channel.ShareURL can be decoded using
// DecodeShareURL and that it matches the original.
func TestChannel_ShareURL_DecodeShareURL(t *testing.T) {
	host := "https://internet.speakeasy.tech/"
	rng := csprng.NewSystemRNG()

	for i, level := range []PrivacyLevel{Public, Private, Secret} {
		c, _, err := NewChannel("My Channel",
			"Here is information about my channel.", level, 1000, rng)
		if err != nil {
			t.Fatalf("Failed to create new %s channel: %+v", level, err)
		}

		address, password, err := c.ShareURL(host, i, rng)
		if err != nil {
			t.Fatalf("Failed to create %s URL: %+v", level, err)
		}

		newChannel, maxUses, err := DecodeShareURL(address, password)
		if err != nil {
			t.Errorf("Failed to decode %s URL: %+v", level, err)
		}

		if i != maxUses {
			t.Errorf("Did not get expected max uses."+
				"\nexpected: %d\nreceived: %d", i, maxUses)
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

	_, _, err = c.ShareURL(host, 0, rng)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Did not receive expected error for URL %q."+
			"\nexpected: %s\nreceived: %+v", host, expectedErr, err)
	}
}

// Tests that DecodeShareURL returns an error for an invalid host.
func TestDecodeShareURL_ParseError(t *testing.T) {
	host := "invalidHost\x7f"
	expectedErr := strings.Split(parseShareUrlErr, "%")[0]

	_, _, err := DecodeShareURL(host, "")
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
		"&v=0" +
		"&m=0"
	expectedErr := strings.Split(newReceptionIdErr, "%")[0]

	_, _, err := DecodeShareURL(address, "")
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
		{"test?v=0&m=0", "", malformedUrlErr},
		{"test?v=q", "", parseVersionErr},
		{"test?v=2", "", versionErr},
		{"test?v=0&s=AA==&m=0", "", parseLevelErr},
		{"test?v=0&0Name=2&m=0", "", noPasswordErr},
		{"test?v=0&d=2&m=0", "", noPasswordErr},
		{"test?v=0&s=A&2Level=Public&m=0", "", parseSaltErr},
		{"test?v=0&s=AA==&2Level=Public&k=A&m=0", "", parseRsaPubKeyHashErr},
		{"test?v=0&s=AA==&2Level=Public&k=AA==&l=q&m=0", "", parseRsaPubKeyLengthErr},
		{"test?v=0&s=AA==&2Level=Public&k=AA==&l=5&p=t&m=0", "", parseRsaSubPayloadsErr},
		{"test?v=0&s=AA==&2Level=Public&k=AA==&l=5&p=1&e=A&m=0", "", parseSecretErr},
		{"test?v=0&0Name=2&m=0", "hello", decryptErr},
		{"test?v=0&d=2&m=0", "hello", decodeEncryptedErr},
	}

	for i, tt := range tests {
		expected := strings.Split(tt.err, "%")[0]

		_, _, err := DecodeShareURL(tt.url, tt.password)
		if err == nil || !strings.Contains(err.Error(), expected) {
			t.Errorf("Did not receive expected error for URL %q (%d)."+
				"\nexpected: %s\nreceived: %+v", tt.url, i, expected, err)
		}
	}
}

// Tests that GetShareUrlType returns the expected PrivacyLevel for every time
// of URL.
func TestGetShareUrlType(t *testing.T) {
	tests := map[string]PrivacyLevel{
		"https://internet.speakeasy.tech/?0Name=My+Channel&1Description=Here+is+information+about+my+channel.&2Level=Public&e=z73XYenRG65WHmJh8r%2BanZ71r2rPOHjTgCSEh05TUlQ%3D&k=9b1UtGnZ%2B%2FM3hnXTfNRN%2BZKXcsHyZE00vZ9We0oDP90%3D&l=493&p=1&s=FyaykitzwwhRVvW%2FkqdKKbEvSiVcj9hwhFbvgb2UCDM%3D&v=0":                                                                             Public,
		"https://internet.speakeasy.tech/?0Name=My+Channel&1Description=Here+is+information+about+my+channel.&d=rmU6scJhBFDKqRsXzPJUIx6WTaKvqCLv8Cuq0XaWe11d%2Bt3s3F5vj%2BgDfAUIEn1cMxjD997QBKoDUmjWppN63DWw1LDzYjfVWW7LvvOvPIo6thLb78NtN%2BhcG2gX54UM0Ieu3Uerpp2BEkUuEUmRqCR35oqSApC1P97a4FJJv2VGQwULO6ZaZcowoG3Z%2FNyJRXNphsu6APz6%2FhN%2BhcfiejM%3D&v=0":                         Private,
		"https://internet.speakeasy.tech/?d=2VNLAz%2FqXGlZ6b7gRBmR8Q41S25Y0Q63MDpTJ58DZKaYCBDYEcOBBe7vZYQ6tLFL8%2BG7mvBaierirBbNlaI8iyd%2B2vIkMiPbRm3PFLX2xTW5eVCDMnbEmMaYfhmSYJuzi7oHaZykmtyQ4SQftgdRK7R0kko3wwmk4gzUO3FJ7HZhAacgh2dpcTwySjfLjhB5K1QK2HPxQiLvCEm4Qg4Lv5ttk03TiOe%2BGV2ThW0y4lgS%2BhczwZrEicQSjFotYub0Qzn%2Bi%2B4PNW2jkvWpdy%2B338hMar%2BafFfQQ99Hf0y%2FA8E%3D&v=0": Secret,
	}

	for u, expected := range tests {
		pl, err := GetShareUrlType(u)
		if err != nil {
			t.Errorf("Failed to get type of URL %q: %+v", u, err)
		}

		if expected != pl {
			t.Errorf("Did not receive expected privacy level."+
				"\nexpected: %s\nreceived: %s", expected, pl)
		}
	}
}

// Tests that GetShareUrlType returns an error for an invalid host.
func TestGetShareUrlType_ParseError(t *testing.T) {
	host := "invalidHost\x7f"
	c, err := GetShareUrlType(host)
	if err == nil {
		t.Errorf("Expected error for invalid host URL: %+v", c)
	}
}

// Tests that GetShareUrlType returns errors for a list of invalid URLs.
func TestGetShareUrlType_Error(t *testing.T) {
	type test struct {
		url, password, err string
	}

	tests := []test{
		{"test?", "", urlVersionErr},
		{"test?v=0", "", malformedUrlErr},
		{"test?v=q", "", parseVersionErr},
		{"test?v=2", "", versionErr},
	}

	for i, tt := range tests {
		_, err := GetShareUrlType(tt.url)
		expected := strings.Split(tt.err, "%")[0]
		if err == nil || !strings.Contains(err.Error(), expected) {
			t.Errorf("Did not receive expected error for URL %q (%d)."+
				"\nexpected: %s\nreceived: %+v", tt.url, i, tt.err, err)
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
	maxUses := 12
	urlValues := make(url.Values)
	urlValues = c.encodePrivateShareURL(urlValues, password, maxUses, rng)

	var newChannel Channel
	loadedMaxUses, err := newChannel.decodePrivateShareURL(urlValues, password)
	if err != nil {
		t.Errorf("Error decoding URL values: %+v", err)
	}

	if maxUses != loadedMaxUses {
		t.Errorf("Did not get expected max uses.\nexpected: %d\nreceived: %d",
			maxUses, loadedMaxUses)
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
	maxUses := 2
	urlValues := make(url.Values)
	urlValues = c.encodeSecretShareURL(urlValues, password, maxUses, rng)

	var newChannel Channel
	loadedMaxUses, err := newChannel.decodeSecretShareURL(urlValues, password)
	if err != nil {
		t.Errorf("Error decoding URL values: %+v", err)
	}

	if maxUses != loadedMaxUses {
		t.Errorf("Did not get expected max uses.\nexpected: %d\nreceived: %d",
			maxUses, loadedMaxUses)
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

	maxUses := 5
	data := c.marshalPrivateShareUrlSecrets(maxUses)

	var newChannel Channel
	unmarshalledMaxUses, err := newChannel.unmarshalPrivateShareUrlSecrets(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal private channel data: %+v", err)
	}

	if maxUses != unmarshalledMaxUses {
		t.Errorf("Unmarshalled max uses does not match expected."+
			"\nexpected: %d\nreceived: %d", maxUses, unmarshalledMaxUses)
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

// Tests that a channel marshalled with Channel.marshalSecretShareUrlSecrets and
// unmarshalled with Channel.unmarshalSecretShareUrlSecrets matches the
// original, except for the ReceptionID, which is added in the layer above.
func TestChannel_marshalSecretShareUrlSecrets_unmarshalSecretShareUrlSecrets(t *testing.T) {
	rng := csprng.NewSystemRNG()
	c, _, err := NewChannel("Test Channel", "Description", Secret, 1000, rng)
	if err != nil {
		t.Fatalf("Failed to create new channel: %+v", err)
	}

	maxUses := 5
	data := c.marshalSecretShareUrlSecrets(maxUses)

	var newChannel Channel
	unmarshalledMaxUses, err := newChannel.unmarshalSecretShareUrlSecrets(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal secret channel data: %+v", err)
	}

	if maxUses != unmarshalledMaxUses {
		t.Errorf("Unmarshalled max uses does not match expected."+
			"\nexpected: %d\nreceived: %d", maxUses, unmarshalledMaxUses)
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
