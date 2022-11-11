package rsa

import (
	"crypto"
	gorsa "crypto/rsa"
	"gitlab.com/xx_network/crypto/large"
	oldrsa "gitlab.com/xx_network/crypto/signature/rsa"
	"hash"
	"io"
)

// Scheme is an interface encapsulating the entry point for RSA
type Scheme interface {

	// Generate generates an RSA keypair of the given bit size using the
	// random source random (for example, crypto/rand.Reader).
	Generate(rng io.Reader, bits int) (PrivateKey, error)

	// GenerateDefault generates an RSA keypair of the library default bit
	// size using the random source random (for example, crypto/rand.Reader).
	GenerateDefault(rng io.Reader) (PrivateKey, error)

	// UnmarshalPrivateKeyPEM unmarshals the private key from a PEM file.
	// Will refuse to unmarshal a key smaller than 64 bits, this is not an
	// endorsement of that key size
	// Will print an error to the log if they key size is less than 3072 bits
	UnmarshalPrivateKeyPEM(pem []byte) (PrivateKey, error)

	// UnmarshalPublicKeyPEM unmarshals the public key from a PEM file.
	// Will refuse to unmarshal a key smaller than 64 bits, this is not an
	// endorsement of that key size
	// Will print an error to the log if they key size is less than 3072 bits
	UnmarshalPublicKeyPEM(pem []byte) (PublicKey, error)

	// UnmarshalPublicKeyWire unmarshals the public key from a compact wire
	// format.
	// Will return an error if the passed in byte slice is too small. It is
	// expecting a minimum of 64 bit public key with a 32 bit public exponent,
	// or a minimum length of 12 byes.
	// This acceptance criteria is not an endorsement of keys of those sizes being
	// secure
	UnmarshalPublicKeyWire(b []byte) (PublicKey, error)

	// GetDefaultKeySize returns the deafult key size in bits the
	// scheme will generate
	GetDefaultKeySize() int

	// GetSoftMinKeySize returns the minimum key size in bits the scheme will
	// allow to be generated without printing an error to the log
	GetSoftMinKeySize() int

	// GetMarshalWireLength returns the length of a Marshal Wire for a given key
	// size
	GetMarshalWireLength(size int) int

	// Convert accepts a gorsa.PrivateKey and returns a PrivateKey interface
	Convert(key *gorsa.PrivateKey) PrivateKey
}

// PrivateKey is an interface for an RSA private key which implements the
// standard operation available on go RSA by calling the go rsa code as well as
// a custom multicast OEAP encryption
type PrivateKey interface {

	/* Operations */

	// SignPSS calculates the signature of digest using PSS.
	//
	// digest must be the result of hashing the input message using the given hash
	// function. The opts argument may be nil, in which case sensible defaults are
	// used. If opts.Hash is set, it overrides hash.
	SignPSS(rand io.Reader, hash crypto.Hash, hashed []byte,
		opts *PSSOptions) ([]byte, error)

	// SignPKCS1v15 calculates the signature of hashed using
	// RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5.  Note that hashed must
	// be the result of hashing the input message using the given hash
	// function. If hash is zero, hashed is signed directly. This isn't
	// advisable except for interoperability.
	//
	// If random is not nil then RSA blinding will be used to avoid timing
	// side-channel attacks.
	//
	// This function is deterministic. Thus, if the set of possible
	// messages is small, an attacker may be able to build a map from
	// messages to signatures and identify the signed messages. As ever,
	// signatures provide authenticity, not confidentiality.
	SignPKCS1v15(random io.Reader, hash crypto.Hash,
		hashed []byte) ([]byte, error)

	// DecryptOAEP decrypts ciphertext using RSA-OAEP.
	//
	// OAEP is parameterised by a hash function that is used as a random oracle.
	// Encryption and decryption of a given message must use the same hash function
	// and sha256.New() is a reasonable choice.
	//
	// The random parameter, if not nil, is used to blind the private-key operation
	// and avoid timing side-channel attacks. Blinding is purely internal to this
	// function – the random data need not match that used when encrypting.
	//
	// The label parameter must match the value given when encrypting. See
	// EncryptOAEP for details.
	DecryptOAEP(hash hash.Hash, random io.Reader, ciphertext []byte,
		label []byte) ([]byte, error)

	// EncryptOAEPMulticast encrypts the given message with RSA-OAEP using a Private Key
	// for multicast RSA.
	//
	// OAEP is parameterised by a hash function that is used as a random oracle.
	// Encryption and decryption of a given message must use the same hash function
	// and sha256.New() is a reasonable choice.
	//
	// The random parameter is used as a source of entropy to ensure that
	// encrypting the same message twice doesn't result in the same ciphertext.
	//
	// The label parameter may contain arbitrary data that will not be encrypted,
	// but which gives important context to the message. For example, if a given
	// public key is used to encrypt two types of messages then distinct label
	// values could be used to ensure that a ciphertext for one purpose cannot be
	// used for another by an attacker. If not required it can be empty.
	//
	// The message must be no longer than the length of the public modulus minus
	// twice the hash length, minus a further 2.
	EncryptOAEPMulticast(hash hash.Hash, random io.Reader, msg []byte,
		label []byte) ([]byte, error)

	// DecryptPKCS1v15 decrypts a plaintext using RSA and the padding scheme from PKCS #1 v1.5.
	// If random != nil, it uses RSA blinding to avoid timing side-channel attacks.
	//
	// Note that whether this function returns an error or not discloses secret
	// information. If an attacker can cause this function to run repeatedly and
	// learn whether each instance returned an error then they can decrypt and
	// forge signatures as if they had the private key. See
	// DecryptPKCS1v15SessionKey for a way of solving this problem.
	DecryptPKCS1v15(random io.Reader, ciphertext []byte) ([]byte, error)

	// DecryptPKCS1v15SessionKey decrypts a session key using RSA and the padding scheme from PKCS #1 v1.5.
	// If random != nil, it uses RSA blinding to avoid timing side-channel attacks.
	// It returns an error if the ciphertext is the wrong length or if the
	// ciphertext is greater than the public modulus. Otherwise, no error is
	// returned. If the padding is valid, the resulting plaintext message is copied
	// into key. Otherwise, key is unchanged. These alternatives occur in constant
	// time. It is intended that the user of this function generate a random
	// session key beforehand and continue the protocol with the resulting value.
	// This will remove any possibility that an attacker can learn any information
	// about the plaintext.
	// See “Chosen Ciphertext Attacks Against Protocols Based on the RSA
	// Encryption Standard PKCS #1”, Daniel Bleichenbacher, Advances in Cryptology
	// (Crypto '98).
	//
	// Note that if the session key is too small then it may be possible for an
	// attacker to brute-force it. If they can do that then they can learn whether
	// a random value was used (because it'll be different for the same ciphertext)
	// and thus whether the padding was correct. This defeats the point of this
	// function. Using at least a 16-byte key will protect against this attack.
	DecryptPKCS1v15SessionKey(random io.Reader, ciphertext []byte,
		key []byte) error

	/* Getters */

	// Public returns the public key in *rsa.PublicKey format.
	Public() PublicKey

	// GetGoRSA returns the private key in the standard go rsa format.
	GetGoRSA() *gorsa.PrivateKey

	// GetOldRSA returns the private key in the old wrapper format for RSA
	// within the xx project. Deprecated, only for compatibility during the
	// change
	GetOldRSA() *oldrsa.PrivateKey

	// Size returns the key size in bits of the private key
	Size() int

	// GetD returns the private exponent of the RSA Private Key as
	// a large.Int
	GetD() *large.Int

	// GetPrimes returns the prime factors of N, which has >= 2 elements
	GetPrimes() []*large.Int

	// GetDp returns D mod (P - 1), or nil if unavailable
	GetDp() *large.Int

	// GetDq returns D mod (Q - 1), or nil if unavailable
	GetDq() *large.Int

	// GetMaxOEAPPayloadSize returns the maximum size of a multicastRSA
	// broadcast message
	// The message must be no longer than the length of the public modulus minus
	// twice the hash length, minus a further 2.
	// This is done per the OEAP spec, example of how a similar thing is done in the
	// standard RSA: https://github.com/golang/go/blob/master/src/crypto/rsa/rsa.go#L452
	GetMaxOEAPPayloadSize(hash hash.Hash) int

	/* Marshallers */

	// MarshalPem returns a PEM file of the private key
	MarshalPem() []byte
}

// PublicKey is an interface for an RSA public key which implements the
// standard operation available on go RSA by calling the go rsa code as well as
// a custom multicast OEAP decryption and a compact wire protocol
type PublicKey interface {
	/* Operations */

	// EncryptOAEP encrypts the given message with RSA-OAEP.
	//
	// OAEP is parameterised by a hash function that is used as a random oracle.
	// Encryption and decryption of a given message must use the same hash function
	// and sha256.New() is a reasonable choice.
	//
	// The random parameter is used as a source of entropy to ensure that
	// encrypting the same message twice doesn't result in the same ciphertext.
	//
	// The label parameter may contain arbitrary data that will not be encrypted,
	// but which gives important context to the message. For example, if a given
	// public key is used to encrypt two types of messages then distinct label
	// values could be used to ensure that a ciphertext for one purpose cannot be
	// used for another by an attacker. If not required it can be empty.
	//
	// The message must be no longer than the length of the public modulus minus
	// twice the hash length, minus a further 2.
	EncryptOAEP(hash hash.Hash, random io.Reader, msg []byte,
		label []byte) ([]byte, error)

	// DecryptOAEPMulticast decrypts ciphertext using RSA-OAEP using an RSA
	// Public Key for multicast RSA.
	//
	// OAEP is parameterised by a hash function that is used as a random oracle.
	// Encryption and decryption of a given message must use the same hash function
	// and sha256.New() is a reasonable choice.
	//
	// The label parameter must match the value given when encrypting. See
	// PrivateKey.EncryptOAEPMulticast for details.
	DecryptOAEPMulticast(hash hash.Hash, ciphertext []byte,
		label []byte) ([]byte, error)

	// EncryptPKCS1v15 encrypts the given message with RSA and the padding
	// scheme from PKCS #1 v1.5.  The message must be no longer than the
	// length of the public modulus minus 11 bytes.
	//
	// The random parameter is used as a source of entropy to ensure that
	// encrypting the same message twice doesn't result in the same
	// ciphertext.
	//
	// WARNING: use of this function to encrypt plaintexts other than
	// session keys is dangerous. Use RSA OAEP in new protocols.
	EncryptPKCS1v15(random io.Reader, msg []byte) ([]byte, error)

	// VerifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature.
	// hashed is the result of hashing the input message using the given hash
	// function and sig is the signature. A valid signature is indicated by
	// returning a nil error. If hash is zero then hashed is used directly. This
	// isn't advisable except for interoperability.
	VerifyPKCS1v15(hash crypto.Hash, hashed []byte, sig []byte) error

	// VerifyPSS verifies a PSS signature.
	//
	// A valid signature is indicated by returning a nil error. digest must be the
	// result of hashing the input message using the given hash function. The opts
	// argument may be nil, in which case sensible defaults are used. opts.Hash is
	// ignored.
	VerifyPSS(hash crypto.Hash, digest []byte, sig []byte, opts *PSSOptions) error

	/* Getters */

	// GetGoRSA returns the private key in the standard go rsa format.
	GetGoRSA() *gorsa.PublicKey

	// GetOldRSA returns the private key in the old wrapper format for RSA
	// within the xx project. Deprecated, only for compatibility during the
	// change
	GetOldRSA() *oldrsa.PublicKey

	// Size returns the key size in bits of the public key
	Size() int

	// GetN returns the RSA Public Key modulus
	GetN() *large.Int

	// GetE returns the RSA Public Key exponent
	GetE() int

	// GetMaxOEAPPayloadSize returns the maximum size of a multicastRSA
	// broadcast message
	// The message must be no longer than the length of the public modulus minus
	// twice the hash length, minus a further 2.
	// This is done per the OEAP spec, example of how a similar thing is done in the
	// standard RSA: https://github.com/golang/go/blob/master/src/crypto/rsa/rsa.go#L452
	GetMaxOEAPPayloadSize(hash hash.Hash) int

	// MarshalPem returns a PEM file of the private key
	MarshalPem() []byte

	// MarshalWire returns a marshaled version of the private key which contains
	// everything needed to reconstruct it, specifically both the private exponent
	// as well as the modulus.
	// Notice: the size of the return will be 4 bytes longer than the
	MarshalWire() []byte

	// GetMarshalWireLength returns the length of a Marshal Wire
	GetMarshalWireLength() int
}
