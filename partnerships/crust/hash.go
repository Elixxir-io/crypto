////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package crust will contain cryptographic functions needed for communication between
// the xx messenger and Crust.
package crust

import (
	"crypto/sha256"
	multiHash "github.com/multiformats/go-multihash/core"
)

const (
	usernameHashSalt = "CrustXXBackupUsernameSalt"
	multiHashSize    = 32
	multiHashSha     = multiHash.SHA2_256
)

// HashUsername hashes the passed in username using the sha256 hashing algorithm.
func HashUsername(username string) []byte {
	h := sha256.New()
	h.Write([]byte(username))
	h.Write([]byte(usernameHashSalt))

	return h.Sum(nil)
}

// HashFile hashes the file using the go-multihash library.
func HashFile(file []byte) ([]byte, error) {
	h, err := multiHash.GetVariableHasher(multiHashSha, multiHashSize)
	if err != nil {
		return nil, err
	}

	h.Write(file)
	return h.Sum(nil), nil
}
