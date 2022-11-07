////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package authorize contains logic for signing and verifying a given timestamp.
// This package is designed for usage with the authorizer to prevent DDoS attacks
package authorize

import (
	"encoding/binary"
	"github.com/pkg/errors"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/crypto/xx"
	"gitlab.com/xx_network/primitives/id"
	"hash"
	"io"
	"time"
)

// Sign takes in a node's current timestamp and signs that with its own private key
func Sign(rand io.Reader, now time.Time, privKey *rsa.PrivateKey) ([]byte, error) {
	// Construct the hash
	options := rsa.NewDefaultOptions()
	hashedData := digest(options.Hash.New(), now)

	// Sign the data
	return rsa.Sign(rand, privKey, options.Hash, hashedData, options)
}

// Verify confirms the node's signed timestamp. It performs a
// series of checks prior to doing so:
// First it will determine that signedTS is within +/- delta of now.
// Second it will check that the public key and salt make the passed in node ID
// Finally it will verify the signature on the signedTS using the public key
func Verify(now time.Time, signedTS time.Time,
	pubkey *rsa.PublicKey, nid *id.ID, salt []byte,
	delta time.Duration, signature []byte) error {

	// Check that the signed timestamp is within the delta passed in
	lowerBound := now.Add(-delta)
	upperBound := now.Add(delta)

	if signedTS.After(upperBound) || signedTS.Before(lowerBound) {
		return errors.Errorf("Signed timestamp (%s) is not within "+
			"bounds given by delta (%s) and given current time (%s)", signedTS.String(), delta.String(), now.String())
	}

	// Check that node ID passed in matches the
	// passed in public key and salt
	generatedId, err := xx.NewID(pubkey, salt, id.Node)
	if err != nil {
		return errors.Errorf("Issue generating ID for authorization check: %v", err)
	}

	if !nid.Cmp(generatedId) {
		return errors.Errorf("Node ID %s does not match ID generated by given salt "+
			"and public key", nid)
	}

	// Construct the hash
	options := rsa.NewDefaultOptions()
	hashedData := digest(options.Hash.New(), signedTS)

	// Verify the signature passed in
	return rsa.Verify(pubkey, options.Hash, hashedData, signature, options)

}

// digest serializes and hashes the given timestamp
func digest(h hash.Hash, timestamp time.Time) []byte {
	// Serialize the timestamp
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(timestamp.UnixNano()))

	// Hash the timestamp
	h.Write(tsBytes)
	return h.Sum(nil)
}
