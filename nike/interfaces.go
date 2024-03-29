////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package nike

import "io"

// Key is an interface for types encapsulating key material.
type Key interface {

	// Reset resets the key material to all zeros.
	Reset()

	// Bytes serializes key material into a byte slice.
	Bytes() []byte

	// FromBytes copys key material from the given byte slice and
	// initializes the Key
	FromBytes(data []byte) error

	Scheme() Nike
}

// PrivateKey is an interface for types encapsulating
// private key material.
type PrivateKey interface {
	Key

	DeriveSecret(PublicKey) []byte
}

// PublicKey is an interface for types encapsulating
// public key material.
type PublicKey interface {
	Key
}

// Nike is an interface encapsulating a
// non-interactive key exchange.
type Nike interface {

	// PublicKeySize returns the size in bytes of the public key.
	PublicKeySize() int

	// PrivateKeySize returns the size in bytes of the private key.
	PrivateKeySize() int

	// NewKeypair returns a newly generated key pair.
	NewKeypair(rng io.Reader) (PrivateKey, PublicKey)

	// UnmarshalBinaryPublicKey unmarshals the public key bytes.
	UnmarshalBinaryPublicKey(b []byte) (PublicKey, error)

	// UnmarshalBinaryPrivateKey unmarshals the public key bytes.
	UnmarshalBinaryPrivateKey(b []byte) (PrivateKey, error)

	// NewEmptyPrivateKey is helper method used to help
	// implement UnmarshalBinaryPrivateKey.
	NewEmptyPrivateKey() PrivateKey

	// NewEmptyPublicKey is a helper method used to help
	// implement UnmarshalBinaryPublicKey.
	NewEmptyPublicKey() PublicKey

	// DerivePublicKey derives a public key given a private key.
	DerivePublicKey(PrivateKey) PublicKey
}
