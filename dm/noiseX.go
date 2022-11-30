////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"encoding/binary"
	"io"

	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/yawning/nyquist.git"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	prologueSize       = 2
	ciphertextOverhead = 96

	// lengthOfOverhead is the reserved bytes used to indicate the
	// serialized length of the payload within a ciphertext.
	lengthOfOverhead = 2

	// pubKeySize is the size of the facsimile public key used for self
	// encryption/decryption.
	pubKeySize = blake2b.Size256

	// nonceSize is the size of the nonce used for the encryption
	// algorithm used for self encryption/decryption.
	nonceSize = chacha20poly1305.NonceSizeX
)

var (
	NoiseX   NoiseCipher = &noiseX{}
	protocol *nyquist.Protocol
	version  = []byte{0x0, 0x0}
)

// NoiseCipher is a minimal abstraction useful for building a noise
// protocol layer.
type NoiseCipher interface {
	// CiphertextOverhead returns the ciphertext overhead in bytes.
	CiphertextOverhead() int

	// Encrypt encrypts the given plaintext as a Noise X message.
	// - plaintext: The message to Encrypt
	// - partnerStaticPubKey: The public key of the target of the message
	// - rng: a cryptographically secure pseudo random number generator
	// - maxPayloadSize: the size of the ciphertext to be returned
	Encrypt(plaintext []byte,
		partnerStaticPubKey nike.PublicKey,
		rng io.Reader,
		maxPayloadSize int) []byte

	// Decrypt decrypts the given ciphertext as a Noise X message.
	Decrypt(ciphertext []byte,
		myStatic nike.PrivateKey) ([]byte, error)
}

// noiseX is an implementation of NoiseScheme interface.
type noiseX struct{}

func (s *noiseX) CiphertextOverhead() int {
	return ciphertextOverhead
}

// Encrypt encrypts the given plaintext as a Noise X message.
func (s *noiseX) Encrypt(plaintext []byte,
	partnerStaticPubKey nike.PublicKey, rng io.Reader,
	maxPayloadSize int) []byte {
	ecdhPrivate, ecdhPublic := ecdh.ECDHNIKE.NewKeypair(rng)

	privKey := privateToNyquist(ecdhPrivate)
	theirPubKey := publicToNyquist(partnerStaticPubKey)

	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		Prologue:     version,
		LocalStatic:  privKey,
		RemoteStatic: theirPubKey,
		IsInitiator:  true,
	}
	hs, err := nyquist.NewHandshake(cfg)
	panicOnError(err)
	defer hs.Reset()
	ciphertext, err := hs.WriteMessage(nil, plaintext)
	handleErrorOnNoise(hs, err)
	return ciphertextToNoise(ciphertext, ecdhPublic, maxPayloadSize)
}

// Decrypt decrypts the given ciphertext as a Noise X message.
func (s *noiseX) Decrypt(ciphertext []byte, myStatic nike.PrivateKey) (
	[]byte, error) {

	encrypted, partnerStaticPubKey, err := parseCiphertext(ciphertext)
	if err != nil {
		return nil, err
	}

	privKey := privateToNyquist(myStatic)
	theirPubKey := publicToNyquist(partnerStaticPubKey)

	cfg := &nyquist.HandshakeConfig{
		Protocol:     protocol,
		Prologue:     version,
		LocalStatic:  privKey,
		RemoteStatic: theirPubKey,
		IsInitiator:  false,
	}

	hs, err := nyquist.NewHandshake(cfg)
	if err != nil {
		return nil, err
	}
	defer hs.Reset()

	plaintext, err := hs.ReadMessage(nil, encrypted)
	handleErrorOnNoise(hs, err)

	return plaintext, nil
}

// parseCiphertext is a helper function which parses the ciphertext. This should
// be the inverse of ciphertextToNoise, returning to the user
// the encrypted data and the public key.
func parseCiphertext(ciphertext []byte) ([]byte, nike.PublicKey, error) {
	// Extract the payload from the ciphertext
	lengthOfPayloadBytes := ciphertext[:lengthOfOverhead]
	payloadSize, _ := binary.Uvarint(lengthOfPayloadBytes)
	payload := ciphertext[lengthOfOverhead:payloadSize]

	// Extract the public key from the payload
	publicKeySize := ecdh.ECDHNIKE.PublicKeySize()
	publicKeyBytes := payload[:publicKeySize]
	publicKey, err := ecdh.ECDHNIKE.
		UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	// Extract encrypted data from payload
	encrypted := payload[publicKeySize:]

	return encrypted, publicKey, nil
}

// ciphertextToNoise is a helper function which will take the ciphertext
// and format it to fit Noise's specifications. The returned byte data should
// be formatted as such:
// Length of Payload | Public Key | Ciphertext | Random Data
func ciphertextToNoise(ciphertext []byte,
	ecdhPublic nike.PublicKey, maxPayloadSize int) []byte {
	res := make([]byte, maxPayloadSize)

	lengthOfPublicKey := len(ecdhPublic.Bytes())
	actualPayloadSize := lengthOfPublicKey + len(ciphertext) + lengthOfOverhead

	// Put at the start the length of the payload (ciphertext)
	binary.PutUvarint(res, uint64(actualPayloadSize))

	// Put in the public key per the Noise spec
	copy(res[lengthOfOverhead:], ecdhPublic.Bytes())

	// Put in the cipher text
	copy(res[lengthOfOverhead+lengthOfPublicKey:], ciphertext)

	// Fill the rest of the context with random data
	rng := csprng.NewSystemRNG()
	count, err := rng.Read(res[actualPayloadSize:])
	panicOnError(err)
	panicOnRngFailure(count, maxPayloadSize-actualPayloadSize)

	return res
}

func init() {
	var err error
	protocol, err = nyquist.NewProtocol("Noise_X_25519_ChaChaPoly_BLAKE2s")
	panicOnError(err)
}