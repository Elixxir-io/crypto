////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package fileTransfer

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/xx_network/crypto/csprng"
	"io"
	"math/rand"
	"strconv"
	"testing"
)

// Consistency test for EncryptPart.
func TestEncryptPart_Consistency(t *testing.T) {
	prng := NewPrng(42)
	// The expected values for encrypted messages and MACs
	expectedValues := []struct{ encrPart, mac string }{
		{"/pJCVL8FzUpxaWI=", "T02QGQlg36ko8FH26IgxCyKsuLrS7KqkU/3DJlNOfAs="},
		{"AFyk+pU2+maQNkA=", "O3V8fAsI3Tmrau81b3rn7/vUD2HMrWFlCljZNUtokro="},
		{"z9aOLbSwqkn/XDI=", "NijSEkNo/Czzw7zeNR+3lfyBZtOQRBVQcrEIEmjD3ls="},
		{"fY/a+Jc8lzjNioM=", "PzRQ9X5BpvTWvUTNBtiuLqOhB2MjR7Wqh5aU4eGX2bg="},
		{"4sXWEZ5D+AXXZB8=", "KPdq2Hx8dyySNzZ5rhQUEquJjVP2KKF1WaN0orTunD0="},
		{"sHBfFDPrs2Q9CGg=", "ZEPZRdZWyxP0VMHeXA9o/tjd4R2QPEG1j1jA/Uk1DWU="},
		{"NrVAkRa5fwcczXs=", "GlIoH7jZ/pAJ2LfzpWNQKbM9nJaDxouvpWX6CgueSjk="},
		{"ffyeHJpZwYBpsWg=", "B9oDoFSeF1j4Bs414nFUixcfawZ+kTIwFNhXXNT3vMc="},
		{"4WdM4SAE43ybQIU=", "CtRmKeXVfs6jNnDvQOreM9H4G+iCEO/PE7eTATIkhRE="},
		{"fvbi3mt2Ui1POVA=", "RoXczfWjqZpnOGqRdZoZNVL4g/uZcH/HeMvQNIE0Vsk="},
	}

	kwy, err := NewTransferKey(prng)
	if err != nil {
		t.Fatalf("Failed to generate transfer key: %+v", err)
	}

	nonceMap := make(map[string]bool, len(expectedValues))

	for i, expected := range expectedValues {
		payload := []byte("payloadMsg" + strconv.Itoa(i))
		ecr, mac, nonce, err := EncryptPart(kwy, payload, uint16(i), prng)
		if err != nil {
			t.Errorf("EncryptPart returned an error (%d): %+v", i, err)
		}

		// Verify the encrypted part
		ecr64 := base64.StdEncoding.EncodeToString(ecr)
		if expected.encrPart != ecr64 {
			t.Errorf("Encrypted part does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected.encrPart, ecr64)
		}

		// Verify the MAC
		mac64 := base64.StdEncoding.EncodeToString(mac)
		if expected.mac != mac64 {
			t.Errorf("MAC does not match expected (%d)"+
				"\nexpected: %s\nreceived: %s", i, expected.mac, mac64)
		}

		// Verify the nonce is unique
		nonce64 := base64.StdEncoding.EncodeToString(nonce)
		if nonceMap[nonce64] {
			t.Errorf("Padding not unique (%d): %s", i, nonce64)
		} else {
			nonceMap[nonce64] = true
		}
	}
}

// Tests that a file part encrypted with EncryptPart can be decrypted with
// DecryptPart. This ensures that they are the inverse of each other.
func TestEncryptPart_DecryptPart(t *testing.T) {
	prng := NewPrng(42)
	key, err := NewTransferKey(prng)
	if err != nil {
		t.Fatalf("Failed to generate transfer key: %+v", err)
	}

	for i := uint16(0); i < 25; i++ {
		message := make([]byte, 32)
		_, _ = prng.Read(message)
		ecr, mac, nonce, err := EncryptPart(key, message, i, prng)
		if err != nil {
			t.Errorf("Failed to encrypt part %d: %+v", i, err)
		}

		dec, err := DecryptPart(key, ecr, nonce, mac, i)
		if err != nil {
			t.Errorf("Failed to decrypt part: %+v", err)
		}

		if !bytes.Equal(dec, message) {
			t.Errorf("Decrypted message does not match original message (%d)."+
				"\nexpected: %+v\nreceived: %+v", i, message, dec)
		}
	}
}

// Error path: tests DecryptPart returns the expected error if the provided MAC
// is incorrect.
func TestEncryptPart_DecryptPart_InvalidMacError(t *testing.T) {
	prng := NewPrng(42)
	key, err := NewTransferKey(prng)
	if err != nil {
		t.Fatalf("Failed to generate transfer key: %+v", err)
	}

	for i := uint16(0); i < 25; i++ {
		message := make([]byte, 32)
		_, _ = prng.Read(message)
		ecr, mac, nonce, err := EncryptPart(key, message, i, prng)
		if err != nil {
			t.Errorf("Failed to encrypt part %d: %+v", i, err)
		}

		// Generate invalid MAC
		_, _ = prng.Read(mac)

		_, err = DecryptPart(key, ecr, nonce, mac, i)
		if err == nil || err.Error() != macMismatchErr {
			t.Errorf("DecryptPart did not return the expected error when the "+
				"MAC is invalid.\nexpected: %s\nreceived: %+v",
				macMismatchErr, err)
		}
	}
}

// Prng is a PRNG that satisfies the csprng.Source interface.
type Prng struct{ prng io.Reader }

func NewPrng(seed int64) csprng.Source     { return &Prng{rand.New(rand.NewSource(seed))} }
func (s *Prng) Read(b []byte) (int, error) { return s.prng.Read(b) }
func (s *Prng) SetSeed([]byte) error       { return nil }