//go:build ctidh
// +build ctidh

////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package ctidh

import (
	"encoding/pem"

	ctidh "git.xx.network/elixxir/ctidh_cgo"

	"gitlab.com/elixxir/crypto/nike"
)

// ctidhNIKE implements the Nike interface using our ctidh module.
type ctidhNIKE struct{}

// CTIDHNIKE is essentially a factory type which
// has no state. It's used to build NIKE types.
var CTIDHNIKE = new(ctidhNIKE)

var _ nike.PrivateKey = (*PrivateKey)(nil)
var _ nike.PublicKey = (*publicKey)(nil)
var _ nike.Nike = (*ctidhNIKE)(nil)

func (e *ctidhNIKE) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	return &publicKey{
		publicKey: ctidh.DerivePublicKey(privKey.(*PrivateKey).privateKey),
	}
}

// PublicKeySize returns the size in bytes of the public key.
func (e *ctidhNIKE) PublicKeySize() int {
	return ctidh.PublicKeySize
}

// PrivateKeySize returns the size in bytes of the private key.
func (e *ctidhNIKE) PrivateKeySize() int {
	return ctidh.PrivateKeySize
}

// NewKeypair returns a newly generated key pair.
func (e *ctidhNIKE) NewKeypair() (nike.PrivateKey, nike.PublicKey) {
	privKey, pubKey := ctidh.GenerateKeyPair()
	return &PrivateKey{
			privateKey: privKey,
		}, &publicKey{
			publicKey: pubKey,
		}
}

func (e *ctidhNIKE) NewEmptyPublicKey() nike.PublicKey {
	return &publicKey{
		publicKey: ctidh.NewEmptyPublicKey(),
	}
}

func (e *ctidhNIKE) NewEmptyPrivateKey() nike.PrivateKey {
	return &PrivateKey{
		privateKey: ctidh.NewEmptyPrivateKey(),
	}
}

// UnmarshalBinaryPublicKey unmarshals the public key bytes.
func (e *ctidhNIKE) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	pubKey := e.NewEmptyPublicKey()
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// UnmarshalBinaryPrivateKey unmarshals the public key bytes.
func (e *ctidhNIKE) UnmarshalBinaryPrivateKey(b []byte) (nike.PrivateKey, error) {
	privKey := e.NewEmptyPrivateKey()
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

type PrivateKey struct {
	privateKey *ctidh.PrivateKey
}

func (p *PrivateKey) Scheme() nike.Nike {
	return CTIDHNIKE
}

func (p *PrivateKey) Reset() {
	p.privateKey.Reset()
}

func (p *PrivateKey) ToPEMFile(f string) error {
	return p.privateKey.ToPEMFile(f)
}

func (p *PrivateKey) ToPEM() (*pem.Block, error) {
	return p.privateKey.ToPEM()
}

func (p *PrivateKey) Bytes() []byte {
	return p.privateKey.Bytes()
}

func (p *PrivateKey) FromBytes(data []byte) error {
	return p.privateKey.FromBytes(data)
}

func (p *PrivateKey) DeriveSecret(pubKey nike.PublicKey) []byte {
	return p.privateKey.DeriveSecret(pubKey.(*publicKey).publicKey)
}

type publicKey struct {
	publicKey *ctidh.PublicKey
}

func (p *publicKey) Scheme() nike.Nike {
	return CTIDHNIKE
}

func (p *publicKey) ToPEMFile(f string) error {
	return p.publicKey.ToPEMFile(f)
}

func (p *publicKey) ToPEM() (*pem.Block, error) {
	return p.publicKey.ToPEM()
}

func (p *publicKey) Reset() {
	p.publicKey.Reset()
}

func (p *publicKey) Bytes() []byte {
	return p.publicKey.Bytes()
}

func (p *publicKey) FromBytes(data []byte) error {
	return p.publicKey.FromBytes(data)
}
