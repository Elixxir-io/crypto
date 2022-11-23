////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"bytes"
	"testing"

	"gitlab.com/elixxir/crypto/nike/ecdh"
)

func TestScheme_EncryptSelf(t *testing.T) {
	message1 := []byte("i am a message")

	_, alicePubKey := ecdh.ECDHNIKE.NewKeypair()
	bobPrivKey, _ := ecdh.ECDHNIKE.NewKeypair()

	ciphertext, err := Cipher.EncryptSelf(message1, bobPrivKey,
		alicePubKey, 1024)
	if err != nil {
		t.Fatalf("Failed to encrypt: %+v", err)
	}

	pubKey, plaintext, err := Cipher.DecryptSelf(ciphertext, bobPrivKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %+v", err)
	}

	if !bytes.Equal(message1, plaintext) {
		t.Fatalf("Decrypted plaintext does not match originally encrypted message!")
	}

	if !bytes.Equal(pubKey.Bytes(), alicePubKey.Bytes()) {
		t.Fatalf("bad public keys: %s != %s", pubKey, alicePubKey)
	}

}
