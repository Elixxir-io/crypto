package e2e

import (
	"crypto/rand"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
	"io"
)

// Calls encrypt() with crypto.rand.Reader.
func Encrypt(g cyclic.Group, key, msg *cyclic.Int) (*cyclic.Int, error) {
	return encrypt(g, key, msg, rand.Reader)
}

// Modular multiplies the key and padded message under the passed group.
func encrypt(g cyclic.Group, key, msg *cyclic.Int, rand io.Reader) (*cyclic.Int, error) {
	// Get the padded message
	encMsg, err := pad(msg.Bytes(), format.TOTAL_LEN, rand)

	// Return if an error occurred
	if err != nil {
		return nil, err
	}

	// Modular multiply the key with the padded message
	product := g.Mul(key, cyclic.NewIntFromBytes(encMsg), cyclic.NewInt(0))

	// Return the result
	return product, nil
}

// Modular inverts the key under the passed group and modular multiplies it with
// the encrypted message under the passed group.
func Decrypt(g cyclic.Group, key, encMsg *cyclic.Int) (*cyclic.Int, error) {
	// Modular invert the key under the group
	keyInv := g.Inverse(key, cyclic.NewInt(0))

	// Modular multiply the inverted key with the message
	product := g.Mul(keyInv, encMsg, cyclic.NewInt(0))

	// Remove the padding from the message
	unPadMsg, err := Unpad(product.LeftpadBytes(uint64(format.TOTAL_LEN)))

	// Return if an error occurred
	if err != nil {
		return nil, err
	}

	// Convert the byte slice into a cyclic int and return
	return cyclic.NewIntFromBytes(unPadMsg), nil
}
