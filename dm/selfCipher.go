////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"crypto/hmac"
	"encoding/binary"

	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/xx_network/crypto/csprng"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// IsSelfEncrypted will return whether the ciphertext provided has been
// encrypted by the owner of the passed in private key. Returns true
// if the ciphertext has been encrypted by the user.
func (s *dmCipher) IsSelfEncrypted(data []byte,
	myPrivateKey nike.PrivateKey) bool {

	// Pull nonce from ciphertext
	offset := lengthOfOverhead + nonceSize
	nonce := data[lengthOfOverhead:offset]

	// Pull public key from ciphertext
	receivedPubKey := data[offset : offset+pubKeySize]

	// Construct expected public key using nonce in ciphertext and
	// the user's private key
	expectedPubKey := constructSelfCryptPublicKey(myPrivateKey.Bytes(), nonce)

	// Check that generated public key matches public key within ciphertext
	if hmac.Equal(receivedPubKey, expectedPubKey[:]) {
		return true
	}

	return false
}

// EncryptSelf will encrypt the passed plaintext. This will simulate the
// encryption protocol in Encrypt, using just the user's public key.
func (s *dmCipher) EncryptSelf(plaintext []byte, myPrivateKey nike.PrivateKey,
	maxPayloadSize int) ([]byte, error) {

	// Construct nonce
	nonce := make([]byte, nonceSize)
	count, err := csprng.NewSystemRNG().Read(nonce)
	if err != nil {
		return nil, err
	}
	panicOnRngFailure(count, nonceSize)

	// Construct public key
	pubKey := constructSelfCryptPublicKey(myPrivateKey.Bytes(), nonce)

	// Construct key for ChaCha cipher
	chaKey := constructSelfChaKey(myPrivateKey.Bytes(), pubKey[:], nonce)

	// Construct cipher
	chaCipher, err := chacha20poly1305.NewX(chaKey[:])
	panicOnChaChaFailure(err)

	// Encrypt plaintext
	encrypted := chaCipher.Seal(nil, nonce, plaintext, nil)
	res := make([]byte, maxPayloadSize)

	// Place the size of the payload (byte-serialized) at the beginning of the
	// ciphertext
	payloadSize := len(encrypted) + nonceSize + len(pubKey)
	binary.PutUvarint(res, uint64(payloadSize))

	// Place the nonce into the ciphertext
	copy(res[lengthOfOverhead:], nonce)

	// Place the public key into the ciphertext
	offset := lengthOfOverhead + nonceSize
	copy(res[offset:], pubKey[:])

	// Place the encrypted data into the ciphertext
	offset = offset + len(pubKey)
	copy(res[offset:], encrypted)

	// Fill the rest of the ciphertext with padding. This simulates the Noise
	// protocol.
	count, err = csprng.NewSystemRNG().Read(res[payloadSize+lengthOfOverhead:])
	panicOnError(err)
	panicOnRngFailure(count, maxPayloadSize-(payloadSize+lengthOfOverhead))

	return res, nil
}

// DecryptSelf will decrypt the passed ciphertext. This will check if the
// ciphertext is expected using IsSelfEncrypted.
func (s *dmCipher) DecryptSelf(ciphertext []byte,
	myPrivateKey nike.PrivateKey) ([]byte, error) {
	if !s.IsSelfEncrypted(ciphertext, myPrivateKey) {
		return nil, errors.New("Could not confirm that data is self-encrypted")
	}

	// Pull nonce from ciphertext
	offset := lengthOfOverhead + nonceSize
	nonce := ciphertext[lengthOfOverhead:offset]

	// Pull public key from ciphertext
	receivedPubKey := ciphertext[offset : offset+pubKeySize]

	// Find size of payload
	encryptedSizeBytes := ciphertext[:lengthOfOverhead]
	encryptedSize, _ := binary.Uvarint(encryptedSizeBytes)

	// Pull encrypted payload from ciphertext
	offset = offset + pubKeySize
	encrypted := ciphertext[offset : encryptedSize+lengthOfOverhead]

	// Construct key for decryption
	chaKey := constructSelfChaKey(myPrivateKey.Bytes(), receivedPubKey, nonce)

	// Construct cipher
	chaCipher, err := chacha20poly1305.NewX(chaKey[:])
	panicOnChaChaFailure(err)

	// Decrypt ciphertext
	plaintext, err := chaCipher.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// constructSelfChaKey is a helper function which generates the key
// used for self encryption and decryption.
func constructSelfChaKey(myPrivateKey, pubKey, nonce []byte) [pubKeySize]byte {
	chaKey := make([]byte, 0)
	chaKey = append(chaKey, pubKey[:]...)
	chaKey = append(chaKey, nonce...)
	chaKey = append(chaKey, myPrivateKey...)
	return blake2b.Sum256(chaKey)
}

// constructSelfCryptPublicKey is a helper function which will construct the
// facsimile "public key" will be used to generate the key for self
// encryption.
func constructSelfCryptPublicKey(myPrivateKey, nonce []byte) [pubKeySize]byte {
	// Construct "public key"
	toHash := append(myPrivateKey, nonce...)
	return blake2b.Sum256(toHash)

}
