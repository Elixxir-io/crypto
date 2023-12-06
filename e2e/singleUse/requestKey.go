////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
)

const requestKeySalt = "singleUseTransmitKeySalt"

// NewRequestKey generates the key used for the request message.
func NewRequestKey(dhKey *cyclic.Int) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("[SU] Failed to create new hash for single-use "+
			"request key: %+v", err)
	}

	// Hash the DH key and salt
	h.Write(dhKey.Bytes())
	h.Write([]byte(requestKeySalt))

	// Get hash bytes
	return h.Sum(nil)
}
