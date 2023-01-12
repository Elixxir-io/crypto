package broadcast

import (
	"gitlab.com/elixxir/crypto/rsa"
)

const (
	minKeySize = 1024 / 8
)

// calculateKeySize finds the optimal key size and number of sub-packets smaller
// than the key size and larger than the minKeySize. Both payloadSize and
// maxKeySizeGoal should be in bytes.
func calculateKeySize(payloadSize int) (selectedKeySize int, selectedN int) {

	// Some payload is taken up by data for the sized broadcast included in the
	// outer symmetric encryption layer; account for that.
	sizedPayloadSize := MaxSizedBroadcastPayloadSize(payloadSize)

	// Calculate the maximum key size that can be used for a given payload
	computedKeySize := (sizedPayloadSize - rsa.ELength) / 2

	// ensure the calculated key size is dividable by 128 to account
	// for issues in javascript
	// this code takes advantage of the fact that 128 = 2^7, meaning
	// a number can be set to be divisable by 128 by ensuring the
	// bottom 7 bits are zero in 0s complement (unsigned) space
	selectedKeySize = int(uint(computedKeySize) & 0xffffffffffffff80)

	// there are 2 sub payloads, but 1 will be used for the public key,
	// so the number of usable sub payloads is 1
	selectedN = 1
	return
}

func calculateRsaToPublicPacketSize(keySize, numSubPayloads int) int {
	return keySize*numSubPayloads + rsa.GetScheme().GetMarshalWireLength(keySize)
}

func calculateRsaToPrivatePacketSize(keySize, numSubPayloads int) int {
	return keySize * numSubPayloads
}
