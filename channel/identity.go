////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"crypto/ed25519"
	"errors"
	"golang.org/x/crypto/blake2b"
	"io"
	"strings"
)

type Language uint8

const (
	English Language = iota
)

type PrivateIdentity struct {
	Privkey *ed25519.PrivateKey
	Identity
}

// Marshal creates a write version of the private identity
func (i PrivateIdentity) Marshal() []byte {
	return append([]byte{i.CodesetVersion}, append(*i.Privkey, i.PubKey...)...)
}

// UnmarshalPrivateIdentity created a private identity from a marshaled version
func UnmarshalPrivateIdentity(data []byte) (PrivateIdentity, error) {
	if len(data) != ed25519.PrivateKeySize+ed25519.PublicKeySize+1 {
		return PrivateIdentity{}, errors.New("data to unmarshal as a " +
			"private identity is the wrong length")
	}

	version := uint8(data[0])
	privkey := ed25519.PrivateKey(data[1 : 1+ed25519.PrivateKeySize])
	pubKey := ed25519.PublicKey(data[1+ed25519.PrivateKeySize:])

	pi := PrivateIdentity{
		Privkey:  &privkey,
		Identity: constructIdentity(pubKey, version),
	}

	return pi, nil
}

// Identity is the public object describing all aspects of a channel definition
type Identity struct {
	PubKey ed25519.PublicKey

	Honorific CodeNamePart
	Adjective CodeNamePart
	Noun      CodeNamePart

	Codename  string
	Color     string
	Extension string

	CodesetVersion uint8
}

// GenerateIdentity create a new channels identity from scratch and assigns
// it a codename
func GenerateIdentity(rng io.Reader) (PrivateIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		return PrivateIdentity{}, err
	}

	pi := PrivateIdentity{
		Privkey:  &priv,
		Identity: ConstructIdentity(pub),
	}

	return pi, nil
}

// ConstructIdentity creates a codename from an extant identity
func ConstructIdentity(pub ed25519.PublicKey) Identity {
	h, _ := blake2b.New256(nil)

	honorific := generateCodeNamePart(h, pub, honorificSalt, honorifics)
	adjective := generateCodeNamePart(h, pub, adjectiveSalt, adjectives)
	noun := generateCodeNamePart(h, pub, nounSalt, nouns)

	if honorific.Generated != "" {
		adjective.Generated = strings.Title(adjective.Generated)
	}

	if honorific.Generated != "" || adjective.Generated != "" {
		noun.Generated = strings.Title(noun.Generated)
	}

	i := Identity{
		PubKey:         pub,
		Honorific:      honorific,
		Adjective:      adjective,
		Noun:           noun,
		Codename:       honorific.Generated + adjective.Generated + noun.Generated,
		Color:          generateColor(h, pub),
		Extension:      generateExtension(h, pub),
		CodesetVersion: codesetv0,
	}
	return i
}

// constructIdentity creates a codename from an extant identity for a given
// version
// currently, because there is only version 0, it only deals with version 0
func constructIdentity(pub ed25519.PublicKey, codesetVersion uint8) Identity {
	h, _ := blake2b.New256(nil)

	honorific := generateCodeNamePart(h, pub, honorificSalt, honorifics)
	adjective := generateCodeNamePart(h, pub, adjectiveSalt, adjectives)
	noun := generateCodeNamePart(h, pub, nounSalt, nouns)

	if honorific.Generated != "" {
		adjective.Generated = strings.Title(adjective.Generated)
	}

	if honorific.Generated != "" || adjective.Generated != "" {
		noun.Generated = strings.Title(noun.Generated)
	}

	i := Identity{
		PubKey:         pub,
		Honorific:      honorific,
		Adjective:      adjective,
		Noun:           noun,
		Codename:       honorific.Generated + adjective.Generated + noun.Generated,
		Color:          generateColor(h, pub),
		Extension:      generateExtension(h, pub),
		CodesetVersion: codesetVersion,
	}
	return i
}

// Marshal creates a write version of the identity
func (i Identity) Marshal() []byte {
	return append([]byte{i.CodesetVersion}, i.PubKey...)
}

// UnmarshalIdentity created an identity from a marshaled version
func UnmarshalIdentity(data []byte) (Identity, error) {
	if len(data) != ed25519.PublicKeySize+1 {
		return Identity{}, errors.New("data to unmarshal as an identity is " +
			"the wrong length")
	}

	version := uint8(data[0])
	pubkey := ed25519.PublicKey(data[1:])

	return constructIdentity(pubkey, version), nil
}
