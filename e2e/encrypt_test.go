package e2e

import (
	"errors"
	"gitlab.com/elixxir/crypto/cyclic"
	"math/rand"
	"reflect"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	// Create group
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

	p := cyclic.NewIntFromString(primeString, 16)
	min := cyclic.NewInt(2)
	max := cyclic.NewInt(0)
	max.Mul(p, cyclic.NewInt(1000))
	seed := cyclic.NewInt(42)
	rng := cyclic.NewRandom(min, max)
	g := cyclic.NewInt(2)
	grp := cyclic.NewGroup(p, seed, g, rng)

	// Create key and message
	key := cyclic.NewInt(3)
	msg := cyclic.NewInt(4)

	// Encrypt key
	encMsg, err := Encrypt(grp, key, msg)

	if err != nil {
		t.Errorf("Encrypt() produced an unexpected error\n\treceived: %v\n\texpected: %v", err, nil)
	}

	// Decrypt key
	dncMsg, err := Decrypt(grp, key, encMsg)

	if dncMsg == msg {
		t.Errorf("Encrypt() did not encrypt the message correctly\n\treceived: %v\n\texpected: %v", dncMsg, msg)
	}
}

func TestEncrypt_Consistency(t *testing.T) {
	// Create group
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	p := cyclic.NewIntFromString(primeString, 16)
	min := cyclic.NewInt(2)
	max := cyclic.NewInt(0)
	max.Mul(p, cyclic.NewInt(1000))
	seed := cyclic.NewInt(42)
	rng := cyclic.NewRandom(min, max)
	g := cyclic.NewInt(2)
	grp := cyclic.NewGroup(p, seed, g, rng)

	// Set up expected values
	expectedMsgs := [][]byte{
		{0x8e, 0x8a, 0x11, 0xd0, 0x6c, 0xde, 0x5a, 0xa2, 0x21, 0x98, 0x0, 0xc3, 0x6a, 0x1a, 0xf0, 0xb8, 0x17, 0x76, 0xf4, 0x22, 0xea, 0x2f, 0x68, 0x60, 0x99, 0xc5, 0x6f, 0x92, 0x63, 0x14, 0x80, 0xda, 0x52, 0xb9, 0x1c, 0xba, 0x8c, 0xac, 0x1, 0xb6, 0xbc, 0x9b, 0x8f, 0xb5, 0x20, 0xcf, 0xad, 0x83, 0x75, 0x13, 0x1c, 0x29, 0xa4, 0xb, 0x6b, 0x6d, 0x6e, 0xf9, 0x59, 0xeb, 0x47, 0x86, 0xbe, 0xe0, 0xce, 0x34, 0xb8, 0xfa, 0xcf, 0xc2, 0x6c, 0xaf, 0x73, 0xb3, 0x78, 0x48, 0x34, 0x91, 0x76, 0xe6, 0x86, 0x48, 0x17, 0x36, 0x62, 0x97, 0x44, 0x15, 0x26, 0xc0, 0xb4, 0x9b, 0xfd, 0x6e, 0x97, 0x8c, 0x46, 0xe3, 0x78, 0xaf, 0x1f, 0xdf, 0xc9, 0x6c, 0x2e, 0x3f, 0x36, 0x8f, 0xaf, 0xd6, 0xf9, 0x14, 0x5, 0x79, 0x77, 0xaa, 0x31, 0xe5, 0xf0, 0x2d, 0x88, 0x5d, 0x1a, 0x92, 0x78, 0x19, 0x35, 0xe1, 0xb6, 0xe8, 0xf2, 0x42, 0x87, 0x92, 0xcd, 0xa1, 0x9e, 0x3b, 0x36, 0x7f, 0xf4, 0xac, 0xc1, 0xd3, 0xf7, 0x43, 0x5b, 0x6, 0xc, 0xd4, 0xe7, 0x89, 0x5, 0x5, 0xa9, 0xb, 0x91, 0x2f, 0xa6, 0x8c, 0xa5, 0xe5, 0x4b, 0xeb, 0xe4, 0x87, 0xd7, 0xa4, 0x82, 0xe, 0x6e, 0x63, 0x4b, 0x62, 0x22, 0xf7, 0x42, 0x6, 0x40, 0xb, 0xe8, 0x6f, 0x17, 0x8d, 0x4e, 0xbc, 0xe7, 0x6d, 0x7b, 0xb8, 0xb, 0x6c, 0x1d, 0xa6, 0x6b, 0x5b, 0x14, 0xab, 0xb2, 0x41, 0xa, 0xcc, 0x86, 0x7c, 0x49, 0x8a, 0xe4, 0x3, 0x57, 0xb9, 0xb6, 0xf6, 0x38, 0x3b, 0xa2, 0x68, 0xc1, 0x50, 0xda, 0x86, 0x60, 0xba, 0xae, 0xb8, 0x7e, 0x6c, 0x44, 0x46, 0x50, 0x5e, 0x82, 0xd6, 0xe5, 0x2c, 0xc0, 0xee, 0x40, 0xf2, 0x21, 0x89, 0x4d, 0xbd, 0x75, 0x9c, 0x22, 0x2b, 0xeb, 0xfc, 0x9b, 0xb3, 0x94, 0x84, 0x1c, 0xcb, 0x5, 0xe6},
		{0x29, 0x73, 0x67, 0x43, 0x22, 0x50, 0x87, 0x59, 0xfe, 0xd1, 0x59, 0x64, 0x70, 0x87, 0x9c, 0xd0, 0x89, 0xff, 0x4c, 0x43, 0xd6, 0xd5, 0x92, 0x37, 0xef, 0x10, 0x37, 0xe6, 0x1e, 0xea, 0xc1, 0xc8, 0xf4, 0x90, 0x94, 0x3c, 0xfc, 0xf6, 0x66, 0x22, 0x29, 0x3, 0xc0, 0x87, 0xa4, 0xb3, 0x66, 0x6e, 0x1f, 0x1f, 0x99, 0x88, 0x73, 0x5f, 0x3, 0xbe, 0x47, 0xf8, 0xab, 0x50, 0xdf, 0xdd, 0x9a, 0xff, 0xd0, 0xfd, 0x90, 0x45, 0x76, 0x8b, 0x5d, 0x29, 0xda, 0x0, 0x63, 0x78, 0x88, 0x57, 0xdf, 0x12, 0xa0, 0x63, 0xc7, 0xa6, 0xc7, 0x9c, 0xa0, 0x24, 0xb6, 0x80, 0x7e, 0x32, 0x71, 0xf5, 0xde, 0xd5, 0x74, 0x86, 0xf6, 0x60, 0xd9, 0xf, 0xaa, 0x1c, 0x48, 0x9a, 0x38, 0xda, 0x40, 0x5b, 0x2d, 0x1c, 0x53, 0x95, 0xf7, 0x3a, 0x6d, 0xb3, 0x1, 0xe6, 0x3c, 0x77, 0x1c, 0xe6, 0xa6, 0xb1, 0xf2, 0x82, 0xfc, 0x29, 0x5b, 0xb7, 0xb2, 0x1c, 0x7f, 0xee, 0x12, 0x45, 0x65, 0x96, 0x52, 0x25, 0x16, 0x72, 0x29, 0x62, 0x9d, 0xaa, 0x50, 0xa6, 0xf0, 0xe6, 0x2f, 0x4, 0x77, 0xb6, 0xb1, 0x66, 0xa1, 0x68, 0x56, 0x9c, 0x7b, 0xeb, 0xe9, 0xa3, 0x85, 0x8c, 0xdf, 0xbb, 0xc3, 0x8e, 0x25, 0xfb, 0x78, 0x1a, 0x62, 0xbc, 0x1e, 0x6a, 0xb8, 0xe6, 0x5e, 0x77, 0xd, 0x80, 0x92, 0x38, 0xce, 0xca, 0x9d, 0xba, 0x94, 0xac, 0x8d, 0x8d, 0x55, 0xd1, 0x47, 0x4, 0x16, 0xaa, 0x22, 0xf4, 0xb9, 0xcd, 0x8b, 0xc0, 0x4e, 0xde, 0x9c, 0x5d, 0x39, 0x1f, 0xa5, 0x89, 0xd5, 0xc, 0x98, 0x16, 0x84, 0xe2, 0xa7, 0xac, 0xe, 0xfb, 0x96, 0xb4, 0xb0, 0x64, 0x1d, 0x43, 0xc5, 0x46, 0x1a, 0x32, 0x89, 0x89, 0x70, 0xc6, 0xea, 0x58, 0x52, 0xc1, 0xa7, 0x27, 0xd3, 0x71, 0x5c, 0xf3, 0x62, 0x69, 0x51, 0x5f, 0xd1, 0x99},
		{0x4d, 0xf7, 0xc0, 0xbe, 0xc4, 0xed, 0x62, 0x3b, 0x23, 0x61, 0x52, 0x48, 0x4a, 0x5b, 0x6d, 0x40, 0x14, 0xab, 0x99, 0x9b, 0x16, 0xc, 0x44, 0xdc, 0x84, 0x98, 0x83, 0xc2, 0x54, 0xe3, 0x24, 0xde, 0x1b, 0x4, 0xf3, 0x13, 0xb, 0x8a, 0x75, 0x59, 0x43, 0x3c, 0xbb, 0xe8, 0x2c, 0x40, 0x88, 0xb2, 0x6c, 0xbd, 0xb2, 0xb3, 0x56, 0x65, 0x2e, 0x3b, 0xe5, 0xa9, 0x52, 0xb0, 0x65, 0x9f, 0x57, 0x5d, 0x2a, 0x56, 0xaf, 0x8d, 0x3d, 0x1, 0xeb, 0x1e, 0x55, 0x40, 0x69, 0x56, 0xa6, 0x53, 0x53, 0x87, 0x2d, 0x4b, 0x71, 0xd2, 0x27, 0x4f, 0xbb, 0x5f, 0x98, 0xba, 0x55, 0xde, 0x9, 0xc5, 0x56, 0x20, 0x36, 0x90, 0x98, 0x85, 0x68, 0x3f, 0x96, 0x48, 0x8b, 0x56, 0x23, 0xe5, 0x46, 0xae, 0xe7, 0x56, 0x62, 0x20, 0xc, 0xb3, 0xfb, 0x73, 0x3e, 0x7b, 0x47, 0x7c, 0x7e, 0x15, 0xa9, 0x9a, 0x61, 0x7, 0xfb, 0xcd, 0xa1, 0x89, 0xea, 0xb2, 0x2, 0x1, 0xf3, 0x19, 0x17, 0x79, 0x62, 0x13, 0xf8, 0x22, 0xe5, 0x1f, 0xb4, 0xb, 0x9d, 0x31, 0x14, 0x17, 0xa2, 0x2e, 0xde, 0xb2, 0xce, 0xce, 0x48, 0x76, 0x6, 0x69, 0x9c, 0x80, 0x19, 0xa3, 0xf6, 0xa9, 0x5e, 0x27, 0x9b, 0xca, 0xf0, 0x1b, 0xd6, 0x67, 0x97, 0xbd, 0xb, 0x7e, 0xaa, 0x58, 0x7e, 0x47, 0x57, 0x4b, 0xa4, 0x0, 0x7b, 0x50, 0xda, 0xd8, 0x74, 0xe, 0xd3, 0x41, 0xb0, 0xf7, 0x32, 0xf9, 0xdc, 0x8d, 0xe6, 0xf5, 0x44, 0x13, 0x48, 0x4b, 0xde, 0x89, 0x2a, 0x5b, 0xd8, 0x76, 0xb5, 0xcc, 0xe5, 0xcd, 0xf8, 0x84, 0x22, 0x61, 0x1a, 0xd3, 0x1f, 0x8b, 0x5d, 0xe2, 0xb8, 0xa0, 0x4d, 0x85, 0xd7, 0x98, 0xc, 0x4f, 0x5, 0x45, 0x2a, 0xc0, 0xce, 0x25, 0xd2, 0xe0, 0xcb, 0x10, 0xe0, 0x10, 0x27, 0x55, 0x5c, 0x32, 0x79, 0x5e, 0xd, 0xb4},
		{0x37, 0x0, 0xb0, 0x70, 0xf3, 0x56, 0xd7, 0xba, 0x3b, 0x86, 0xb2, 0x56, 0x15, 0xf, 0x81, 0x71, 0x70, 0x61, 0x5a, 0x11, 0x77, 0xb2, 0x5f, 0xe6, 0xdd, 0x53, 0x58, 0x81, 0xaf, 0x6d, 0xe2, 0x9e, 0x77, 0xa1, 0xdf, 0x2e, 0x62, 0x97, 0x65, 0x4e, 0x6c, 0x79, 0x72, 0x72, 0x61, 0x88, 0x52, 0x40, 0x59, 0x14, 0xb6, 0xae, 0x40, 0x78, 0xa6, 0xa, 0x70, 0x8d, 0xf7, 0x5b, 0x69, 0xe9, 0x77, 0xd2, 0xb0, 0x82, 0x7f, 0x80, 0x1e, 0xd6, 0xe4, 0x72, 0x13, 0x3e, 0xb9, 0xdc, 0x28, 0xaa, 0x11, 0xde, 0x4f, 0x8, 0xa8, 0x3c, 0xfc, 0x8c, 0xf8, 0xa0, 0xfc, 0xce, 0x3c, 0xbe, 0x41, 0x39, 0x64, 0x21, 0x36, 0xa5, 0x2b, 0xbe, 0xc7, 0xe5, 0xa8, 0x9e, 0x1a, 0x6b, 0x71, 0x13, 0xa4, 0xa1, 0x79, 0x29, 0xc1, 0x44, 0xea, 0xbd, 0x5a, 0xc1, 0xc0, 0x73, 0x1a, 0xf2, 0xc2, 0xf1, 0x4, 0xae, 0x5b, 0xc9, 0x36, 0x34, 0xed, 0x14, 0x8c, 0x93, 0x4d, 0x1, 0x5e, 0xd1, 0xaa, 0xdb, 0xbc, 0xc, 0x89, 0xc8, 0x6, 0x71, 0xe5, 0xfd, 0xec, 0x25, 0xc8, 0x2b, 0x9, 0xf4, 0x3f, 0xdd, 0x73, 0x53, 0x1d, 0x1a, 0xd9, 0xed, 0x18, 0xba, 0xd5, 0xb6, 0x10, 0x3e, 0x6e, 0x59, 0x42, 0x71, 0x3a, 0x20, 0x8e, 0x24, 0x26, 0x8c, 0x9, 0xc1, 0x4a, 0xe2, 0x8f, 0xb8, 0x47, 0xb5, 0x61, 0x97, 0x39, 0x4d, 0x21, 0x8c, 0x1, 0x9f, 0x3f, 0x52, 0x49, 0xb4, 0x53, 0x43, 0x9a, 0x4a, 0x3f, 0x8a, 0x1f, 0x67, 0x50, 0xf, 0xa3, 0x50, 0x19, 0x43, 0xba, 0xc7, 0xe7, 0x27, 0x88, 0xe9, 0x4c, 0xf0, 0x41, 0x61, 0x7b, 0xad, 0x23, 0x48, 0xb, 0x81, 0x16, 0xf7, 0x3a, 0x65, 0xe7, 0x5a, 0x81, 0x4b, 0xec, 0x3f, 0xd9, 0x33, 0xac, 0xe7, 0x80, 0xc, 0x68, 0xdc, 0x96, 0xcb, 0x84, 0x6e, 0x39, 0xfc, 0x95, 0x91, 0x5a, 0x77},
		{0x91, 0x81, 0xe2, 0xb, 0x8c, 0xc0, 0x2c, 0x67, 0xdb, 0x82, 0xac, 0x4f, 0x5f, 0x17, 0x6c, 0x5b, 0xcb, 0xf7, 0xf4, 0xdf, 0x13, 0xd7, 0x37, 0x9a, 0xa3, 0xbe, 0x9d, 0x12, 0x6e, 0x5e, 0xef, 0x4a, 0xca, 0xc2, 0x63, 0x69, 0x7e, 0x16, 0xdc, 0xd9, 0xa9, 0x18, 0x17, 0x44, 0x64, 0x29, 0x28, 0x81, 0x16, 0xd3, 0xf0, 0xf8, 0x11, 0x4f, 0xe5, 0xd8, 0x69, 0xd8, 0xc1, 0x36, 0x3, 0x89, 0x8, 0x58, 0x48, 0x5f, 0x20, 0x92, 0xf8, 0x27, 0x46, 0x4f, 0xca, 0x47, 0x42, 0xb0, 0x3e, 0xa4, 0x65, 0xf, 0x15, 0x81, 0x1e, 0xd5, 0xe6, 0xce, 0x70, 0xc8, 0xa, 0xe, 0x48, 0xac, 0x15, 0xf7, 0x2b, 0x31, 0xf9, 0x68, 0x2b, 0xe5, 0x58, 0xaa, 0x85, 0xd0, 0xa3, 0x12, 0x13, 0x0, 0x8a, 0x91, 0x17, 0x4f, 0xd4, 0xd1, 0x4a, 0x16, 0x3, 0xfb, 0xd6, 0x29, 0x65, 0xf9, 0x6c, 0x22, 0xa9, 0x75, 0x8d, 0x9a, 0xa8, 0x8b, 0x35, 0xa2, 0xe1, 0x42, 0xe8, 0x76, 0xbb, 0x59, 0x8d, 0xc7, 0xed, 0xcd, 0xeb, 0xe7, 0xc7, 0xb1, 0x53, 0xeb, 0x5c, 0x7d, 0x93, 0x6, 0x99, 0x97, 0x50, 0x4, 0xe6, 0x42, 0x4, 0x14, 0x9a, 0x85, 0x26, 0xda, 0xcb, 0xd1, 0xea, 0x13, 0xbb, 0x56, 0xf0, 0x1, 0x1e, 0xb0, 0xf, 0xc8, 0x7c, 0x7, 0x87, 0xb0, 0x12, 0x87, 0x47, 0xd3, 0xa8, 0xc3, 0xc, 0xa8, 0x8, 0x9b, 0x20, 0x90, 0xca, 0x6b, 0x6c, 0xdc, 0x15, 0xc2, 0xbd, 0x3b, 0xf6, 0x13, 0x88, 0x63, 0xd9, 0x54, 0xdf, 0x32, 0x66, 0x30, 0xa7, 0xf4, 0xa9, 0x53, 0x18, 0x7, 0xdd, 0x25, 0x24, 0x76, 0x79, 0x6b, 0x8d, 0x9e, 0x29, 0x62, 0x12, 0x15, 0xa8, 0xde, 0x57, 0x5a, 0x61, 0xdb, 0x62, 0xad, 0x9a, 0xbd, 0x6d, 0xc2, 0xe4, 0xd3, 0x49, 0x1c, 0x6f, 0x11, 0x35, 0x45, 0xf6, 0x48, 0x4c, 0xa, 0xad, 0x83, 0x8c, 0x8b},
		{0x14, 0xcc, 0xd9, 0x1a, 0x7d, 0xf5, 0xb9, 0x19, 0x19, 0xd6, 0xc4, 0x72, 0xfc, 0xc5, 0x86, 0x7, 0x5, 0xbc, 0x3b, 0x58, 0xa7, 0x94, 0x8d, 0xaf, 0xce, 0x8f, 0xdf, 0x79, 0x4c, 0xc4, 0xde, 0x18, 0xc9, 0xc7, 0x12, 0xdf, 0xb5, 0x95, 0x13, 0xe4, 0xb8, 0x93, 0xa, 0xfb, 0x4a, 0x3d, 0x4b, 0x1b, 0x7f, 0xce, 0xf8, 0x21, 0x9a, 0xf0, 0x43, 0xd6, 0x4e, 0xa9, 0x75, 0xd2, 0xd1, 0xb4, 0x87, 0xc9, 0xd7, 0x9e, 0x16, 0x2e, 0x2c, 0x63, 0x6, 0xa3, 0xd2, 0xe6, 0x60, 0xe5, 0x80, 0x51, 0x6c, 0x60, 0xe, 0xd4, 0x40, 0xd6, 0x38, 0x30, 0x45, 0x51, 0x41, 0x66, 0xb2, 0xd6, 0xbe, 0x32, 0x51, 0x78, 0x7e, 0x50, 0xe4, 0xae, 0x44, 0x43, 0xcc, 0xe9, 0x2b, 0xb4, 0x4a, 0x3f, 0x3f, 0x4b, 0x49, 0x10, 0x75, 0x22, 0x8d, 0xe2, 0x44, 0xa7, 0x6, 0x49, 0xab, 0x7, 0xdf, 0x7b, 0xdb, 0x56, 0x54, 0xb1, 0xc5, 0xab, 0x62, 0x8c, 0x73, 0xa2, 0x68, 0xe3, 0x44, 0x6c, 0x2d, 0x1c, 0x9c, 0x22, 0xed, 0x3a, 0x1c, 0x4b, 0x96, 0x3a, 0xa2, 0x84, 0x5e, 0x51, 0x7f, 0xa3, 0xec, 0xfe, 0x12, 0x45, 0x9a, 0xd4, 0x91, 0x73, 0x87, 0x66, 0x90, 0x69, 0x66, 0x5e, 0xdc, 0xc9, 0x2c, 0x9, 0x70, 0xfe, 0xfe, 0xee, 0x42, 0x8f, 0xab, 0x8b, 0x5b, 0x76, 0x7d, 0x5, 0xee, 0xb7, 0x6a, 0x59, 0x76, 0x9e, 0x64, 0x3e, 0x0, 0x34, 0x3b, 0xbd, 0x4d, 0x62, 0xd, 0xad, 0x95, 0x81, 0x3d, 0x78, 0x4b, 0xc5, 0xc8, 0xbc, 0x6, 0x49, 0x33, 0x61, 0x89, 0x40, 0x7e, 0xd1, 0x18, 0xe9, 0xdc, 0x2, 0x77, 0x9b, 0xb3, 0x45, 0x51, 0xcf, 0x5c, 0xda, 0x0, 0xcd, 0x6a, 0xe3, 0xdd, 0x52, 0x27, 0xa0, 0x31, 0xab, 0xf6, 0x91, 0xf0, 0x80, 0xf7, 0x3d, 0xec, 0xdd, 0x3f, 0x6, 0x72, 0x8d, 0xb0, 0x85, 0xf0, 0x17, 0xdd, 0x3a},
		{0x7d, 0x1c, 0xa1, 0x9, 0xd3, 0xaf, 0xf5, 0xc6, 0x26, 0x17, 0x98, 0x42, 0x96, 0xcc, 0xd, 0x4a, 0x10, 0xf4, 0x2d, 0x7e, 0x88, 0x85, 0x86, 0xf0, 0xc2, 0x68, 0x95, 0x59, 0x5c, 0x1e, 0x1c, 0xec, 0x5d, 0x1, 0x18, 0xe4, 0x30, 0x3a, 0xe2, 0x85, 0xae, 0x7f, 0xf4, 0x19, 0xc9, 0x68, 0x22, 0x3, 0xcf, 0x6b, 0x13, 0xa3, 0xe2, 0x20, 0x30, 0x38, 0x30, 0x72, 0x3, 0x16, 0x93, 0xb8, 0x30, 0x3a, 0x53, 0xa, 0xc6, 0xd9, 0x7, 0xa6, 0xd0, 0x18, 0x61, 0xd0, 0x43, 0x3e, 0x24, 0x32, 0xfe, 0x69, 0x9e, 0x25, 0x69, 0xfa, 0xa4, 0xac, 0x6d, 0xd, 0xb, 0xdf, 0x6a, 0x66, 0x6a, 0x5c, 0xd, 0x0, 0xaa, 0xa1, 0xf0, 0x8b, 0xa9, 0x8d, 0xa7, 0x68, 0x8c, 0x4a, 0x61, 0x40, 0x4, 0xd1, 0x1c, 0x9b, 0xd4, 0x2, 0x6e, 0xb1, 0xa3, 0xe9, 0x23, 0x43, 0x7c, 0xbd, 0x3b, 0xd2, 0x9f, 0x90, 0x85, 0x3c, 0xb7, 0xc5, 0x85, 0xab, 0xb5, 0x6e, 0x0, 0xca, 0xeb, 0x2, 0x88, 0x93, 0x46, 0x56, 0xd1, 0x25, 0x74, 0x3, 0xff, 0xbf, 0xc7, 0xba, 0x1c, 0x52, 0xe7, 0x57, 0x6b, 0x2a, 0x2a, 0x9d, 0xa1, 0x19, 0x65, 0x76, 0x89, 0xab, 0x21, 0x4c, 0x9a, 0x85, 0xe, 0x3e, 0xa1, 0xc5, 0xb1, 0x3e, 0x97, 0x3, 0xbb, 0x9b, 0x86, 0xa6, 0x8f, 0x31, 0xf5, 0x28, 0x2e, 0xad, 0x41, 0x30, 0xa7, 0x6b, 0x11, 0xe3, 0x59, 0xd4, 0x69, 0x3, 0xad, 0x6b, 0x1b, 0xc4, 0xcb, 0x27, 0x5f, 0x85, 0x74, 0xf6, 0xe7, 0xda, 0xec, 0xa8, 0x47, 0x45, 0xbc, 0x85, 0x53, 0xa2, 0xd0, 0x98, 0xce, 0xc8, 0xcb, 0x4c, 0x73, 0x90, 0xcc, 0xfe, 0x38, 0x12, 0xac, 0x73, 0x83, 0x7e, 0x43, 0x2c, 0x71, 0x9, 0xb2, 0x58, 0xaf, 0x80, 0x7, 0xf8, 0xef, 0x5f, 0xa8, 0xb4, 0x79, 0xeb, 0xc0, 0xa5, 0x66, 0x3f, 0x8f, 0xd1, 0x2, 0x7b},
		{0x14, 0xea, 0x3e, 0xf2, 0xa2, 0x33, 0x10, 0x9, 0x37, 0xa4, 0xf8, 0x1d, 0x84, 0xa0, 0xea, 0x77, 0xd, 0xbf, 0x25, 0x2a, 0x47, 0x4f, 0xbc, 0x62, 0xeb, 0xbd, 0xb, 0xa, 0xc8, 0xe0, 0xd6, 0x34, 0x20, 0x66, 0x9f, 0x4e, 0xfb, 0x99, 0x93, 0x10, 0x99, 0x33, 0x24, 0x4c, 0x2, 0xf7, 0x90, 0x8, 0x86, 0xc5, 0xbf, 0x3a, 0x7e, 0x9a, 0xa4, 0x59, 0x14, 0x9c, 0xb8, 0x89, 0x49, 0xc3, 0x21, 0x63, 0x7f, 0x25, 0x14, 0x45, 0xb3, 0x80, 0x4a, 0xcf, 0x62, 0x6e, 0xfc, 0xb9, 0xc0, 0xf4, 0xcb, 0x49, 0x1b, 0xef, 0xae, 0x3b, 0xcc, 0xb0, 0xc4, 0x3e, 0x87, 0x2f, 0x1e, 0x55, 0x7d, 0xa7, 0x0, 0x5e, 0xcd, 0xa7, 0xa1, 0xdc, 0xb8, 0x45, 0x25, 0xb5, 0x75, 0x14, 0x57, 0x50, 0xc, 0x97, 0x79, 0x2d, 0x37, 0xd1, 0xa3, 0xe8, 0xca, 0x23, 0x93, 0x4, 0x73, 0xda, 0x6d, 0x2c, 0x2e, 0xbb, 0xeb, 0x81, 0x83, 0x53, 0x61, 0x53, 0xca, 0xcd, 0x48, 0xf8, 0x86, 0xa, 0xa1, 0x27, 0x24, 0x80, 0x8, 0x4a, 0x16, 0x63, 0x93, 0x25, 0xb6, 0x16, 0xc1, 0x7b, 0xe7, 0x3f, 0xff, 0x4f, 0xcc, 0x8d, 0xed, 0xc1, 0x6b, 0xc7, 0xe7, 0x6d, 0x56, 0xd1, 0xe2, 0xef, 0x2f, 0x60, 0x8f, 0xef, 0xa0, 0x2e, 0x1d, 0xc3, 0x87, 0xc6, 0xf1, 0xec, 0x2a, 0x11, 0x16, 0x28, 0xd1, 0xfc, 0x54, 0xef, 0xfc, 0xfd, 0xa, 0xc8, 0x35, 0xeb, 0xd, 0xc, 0x94, 0xa1, 0x52, 0xe9, 0x83, 0x2d, 0xcb, 0xaa, 0x65, 0xa5, 0x6b, 0xbd, 0x6, 0xb8, 0x65, 0x6c, 0x5e, 0xfd, 0x84, 0xdf, 0xb5, 0x3b, 0x9d, 0x2, 0xf7, 0x37, 0xa, 0x14, 0xf, 0x9d, 0x18, 0xfd, 0xf2, 0x54, 0x87, 0x81, 0x31, 0x21, 0xf1, 0x24, 0x56, 0xef, 0x29, 0x4b, 0x7e, 0x7b, 0x84, 0x3f, 0x1d, 0x13, 0x53, 0x70, 0x36, 0x58, 0xf, 0xef, 0x50, 0x40, 0x4d, 0xce},
		{0xdb, 0x7e, 0xd7, 0xaa, 0xce, 0xa4, 0x7c, 0xac, 0x44, 0x6d, 0xa5, 0x89, 0x30, 0xe8, 0x1c, 0x5d, 0xd, 0x92, 0x30, 0x28, 0x7c, 0x38, 0xcf, 0x31, 0x1e, 0x71, 0xd6, 0x3c, 0xd6, 0xf, 0xfc, 0xc, 0x40, 0x82, 0x5, 0x7f, 0xd4, 0xdd, 0x36, 0x36, 0xcc, 0x56, 0xec, 0x25, 0x77, 0xb8, 0x6b, 0xb, 0xa0, 0x67, 0x17, 0x45, 0x35, 0xa8, 0xb9, 0x3c, 0xe9, 0xdd, 0x87, 0xb, 0xc8, 0x7c, 0xa7, 0x81, 0x74, 0x5, 0x8d, 0x97, 0xd6, 0xae, 0xa9, 0xd7, 0x89, 0x2b, 0xa3, 0xbd, 0x73, 0x42, 0xc5, 0x3c, 0x5, 0x77, 0x58, 0xdb, 0xad, 0xed, 0xe5, 0x18, 0xff, 0xfb, 0xd6, 0x8a, 0xed, 0xe6, 0xbb, 0xeb, 0x46, 0x86, 0xdf, 0x3f, 0x82, 0x95, 0x28, 0x84, 0x17, 0x96, 0xf2, 0x6b, 0x45, 0xcd, 0xc1, 0x17, 0xd9, 0x7c, 0x98, 0x3c, 0xb3, 0xe6, 0xc4, 0x46, 0xda, 0xfa, 0xa6, 0x5d, 0x6a, 0x2c, 0xf3, 0x7a, 0x92, 0x92, 0xf6, 0x5b, 0x15, 0x54, 0xb9, 0xfe, 0x16, 0x9d, 0xf4, 0xa8, 0xb0, 0x52, 0xf5, 0x8e, 0x29, 0xa9, 0xaa, 0xc0, 0xa6, 0x8d, 0xb0, 0x76, 0x81, 0x41, 0xd7, 0xe8, 0x4c, 0x11, 0x91, 0x69, 0xee, 0x3d, 0xf6, 0x33, 0x7, 0xf, 0xae, 0xb7, 0xcc, 0xdb, 0x2c, 0xf5, 0xb8, 0xdc, 0xdd, 0x5c, 0x2b, 0xd9, 0x4c, 0x5c, 0xfa, 0xfe, 0x6e, 0xeb, 0x2d, 0x7c, 0xd8, 0xc6, 0x10, 0xcc, 0x56, 0xbc, 0x2, 0x87, 0x7c, 0x77, 0xef, 0x15, 0xfe, 0xb6, 0x14, 0x23, 0x1d, 0x31, 0x4e, 0xfd, 0x59, 0xbf, 0xb0, 0x1, 0xd, 0x54, 0x74, 0x8c, 0x4f, 0x60, 0x6d, 0x6d, 0xd0, 0x57, 0xdb, 0x9f, 0xb9, 0xf3, 0xdd, 0x83, 0x73, 0xaf, 0x4f, 0xf0, 0xc1, 0x9b, 0xf5, 0xd3, 0xee, 0x44, 0x4, 0x39, 0x3c, 0x76, 0x4c, 0xa1, 0xa9, 0x95, 0xff, 0xa1, 0x75, 0xd3, 0xf1, 0xb3, 0xad, 0x2c, 0xa7, 0xbe, 0x27, 0x58},
		{0xc3, 0x99, 0x48, 0x9d, 0xc1, 0x29, 0xde, 0x16, 0xb8, 0x69, 0x3, 0xea, 0x12, 0xe3, 0x5, 0x76, 0x8, 0xfc, 0x71, 0x8b, 0xb5, 0x7b, 0xd6, 0xdb, 0x9d, 0x7d, 0x33, 0x32, 0x83, 0x6a, 0xf8, 0x10, 0xa4, 0x1d, 0x30, 0xc9, 0xd9, 0xa8, 0xae, 0xa1, 0x28, 0x74, 0x0, 0x5c, 0x8b, 0x3c, 0x86, 0x43, 0x23, 0x9, 0x29, 0xfe, 0x17, 0xc2, 0x74, 0x39, 0xc7, 0x8a, 0x7b, 0x12, 0x7b, 0x95, 0xf7, 0xe, 0xda, 0x29, 0x36, 0x8d, 0x85, 0xdc, 0xe4, 0x3b, 0xc4, 0x13, 0x29, 0x5e, 0x52, 0xb0, 0xed, 0xf4, 0xf0, 0x87, 0x5a, 0xb9, 0xab, 0x26, 0xf4, 0x71, 0x81, 0x2f, 0x4f, 0xc9, 0x3c, 0x60, 0xc2, 0xe, 0x5, 0xfa, 0x1e, 0xc3, 0xea, 0xf0, 0x7b, 0xca, 0x4b, 0xce, 0x36, 0xa2, 0xe, 0xa4, 0xab, 0xd1, 0x30, 0xf7, 0xfd, 0x3a, 0xd9, 0x52, 0x10, 0x58, 0xb1, 0x6a, 0x74, 0x17, 0x95, 0x24, 0x2c, 0x6b, 0x7f, 0x24, 0x92, 0x36, 0xfb, 0x78, 0xd8, 0x74, 0x27, 0x12, 0x54, 0xc4, 0xa3, 0x6e, 0x5d, 0x9e, 0x27, 0xc0, 0xca, 0xcf, 0x8e, 0xa2, 0xf0, 0xc2, 0x2, 0x1a, 0x15, 0xcb, 0x36, 0xa3, 0x89, 0xda, 0x63, 0xfe, 0x19, 0x41, 0xff, 0x38, 0x91, 0x3f, 0x4, 0xc1, 0xa0, 0x2a, 0xc, 0xd5, 0xfc, 0x64, 0x4e, 0x5a, 0x49, 0xc8, 0xe6, 0x6, 0xf0, 0xb4, 0x8, 0xae, 0xc9, 0x42, 0xb0, 0x85, 0x9, 0x72, 0x88, 0x6b, 0x3a, 0xd5, 0xe8, 0xa4, 0xfe, 0x2b, 0xb2, 0xff, 0x5, 0x4a, 0x42, 0xba, 0x66, 0xe5, 0xdf, 0xb3, 0x77, 0x3f, 0x84, 0x1c, 0xf9, 0x20, 0x5b, 0x63, 0xd7, 0xfe, 0x13, 0xa9, 0x39, 0xbb, 0x9e, 0xc6, 0x87, 0x77, 0xc7, 0x64, 0x3a, 0x8, 0x6d, 0x98, 0x2d, 0x9f, 0x82, 0x29, 0xde, 0xff, 0xb5, 0x83, 0x9d, 0x5d, 0x58, 0x5a, 0x9, 0xd5, 0x73, 0xce, 0xef, 0xce, 0xff, 0xce, 0x8c, 0xc3},
		{0x2f, 0x3e, 0x20, 0xdb, 0x26, 0x3d, 0x74, 0x62, 0xa4, 0x63, 0xfb, 0x18, 0x36, 0x36, 0x33, 0x3c, 0x41, 0xc4, 0x6e, 0x7c, 0x82, 0x20, 0x48, 0x7c, 0x33, 0xeb, 0x9d, 0x76, 0xa7, 0x73, 0xf8, 0xf7, 0x5c, 0x68, 0xb6, 0xa9, 0x91, 0x75, 0xb9, 0x90, 0xa1, 0x9e, 0x5f, 0xce, 0x9, 0x29, 0xce, 0xb9, 0x49, 0x23, 0x5f, 0xe6, 0x2, 0x2, 0x8f, 0xbd, 0x3d, 0x7c, 0xf3, 0x1c, 0x59, 0x3d, 0x22, 0x77, 0xcb, 0x93, 0x93, 0x94, 0xa, 0xbd, 0xc6, 0x2e, 0x39, 0x40, 0x9c, 0xf6, 0x79, 0x82, 0x1e, 0x25, 0xab, 0x6a, 0x17, 0x59, 0xe1, 0x98, 0x2d, 0x6c, 0x51, 0xd, 0x65, 0x96, 0x7, 0xcc, 0x54, 0x41, 0x78, 0x6e, 0xdb, 0x59, 0xe6, 0x5b, 0x4c, 0x63, 0xab, 0xe5, 0x92, 0xcd, 0x1c, 0xe4, 0x4d, 0x9c, 0x8b, 0x12, 0x6, 0x86, 0x71, 0x60, 0xd1, 0xec, 0x9, 0xb4, 0x0, 0x8, 0x17, 0x2c, 0x94, 0x17, 0xfd, 0xf3, 0x3b, 0x7b, 0x80, 0x82, 0x25, 0x8c, 0x80, 0x45, 0xe3, 0xff, 0x7b, 0x6d, 0x37, 0xe4, 0x84, 0x1a, 0x7d, 0xd, 0xd7, 0xb0, 0xb, 0x5a, 0xa6, 0x11, 0x67, 0xf0, 0x40, 0x2d, 0xc4, 0xfe, 0x13, 0x86, 0x20, 0x75, 0xde, 0xdf, 0x6d, 0x7d, 0x6e, 0x34, 0xeb, 0x89, 0x64, 0x4, 0xe, 0x8e, 0x21, 0x8c, 0x4e, 0x5f, 0x20, 0xe8, 0xd7, 0x9e, 0x85, 0xef, 0xd0, 0xaf, 0xbe, 0x1d, 0x93, 0xa7, 0x4b, 0xd6, 0xa9, 0xe2, 0xdf, 0x28, 0x7c, 0x6f, 0x1a, 0x5d, 0x5e, 0xd5, 0xe7, 0xaf, 0xfe, 0x30, 0xf4, 0xae, 0x6c, 0xc, 0xd4, 0x64, 0x85, 0x82, 0x86, 0x9, 0x43, 0xf5, 0x6e, 0x5f, 0x86, 0xc1, 0x14, 0x8f, 0xec, 0xe2, 0x9a, 0xfb, 0x8c, 0xea, 0xba, 0x6, 0xe2, 0x54, 0x21, 0xfb, 0x17, 0x46, 0xf, 0xb3, 0x60, 0x6e, 0x27, 0x55, 0x8, 0x48, 0x27, 0x22, 0x54, 0x95, 0xe9, 0xa2, 0xec, 0x2e},
		{0x91, 0x56, 0xf9, 0x16, 0x69, 0x4, 0x4b, 0xa0, 0x76, 0x1, 0xd8, 0x27, 0x43, 0x9e, 0xc8, 0xfb, 0xe7, 0x58, 0x62, 0x7a, 0x39, 0x7b, 0x54, 0xdb, 0x36, 0xd3, 0x9d, 0x2c, 0xec, 0x47, 0xb2, 0x44, 0x8c, 0x29, 0xcd, 0x99, 0xdb, 0x5b, 0x5f, 0xdd, 0x6f, 0xbe, 0x37, 0x88, 0x7, 0x7f, 0xc3, 0x24, 0xa1, 0x29, 0x38, 0xed, 0x8d, 0xc9, 0x83, 0xcf, 0x87, 0x4e, 0x3a, 0x83, 0x95, 0x73, 0x6b, 0x8c, 0xd2, 0x58, 0x68, 0x42, 0x4a, 0x76, 0x92, 0x90, 0x48, 0xa6, 0x8c, 0xa, 0x74, 0x5, 0x5, 0xc7, 0xc6, 0xf2, 0x37, 0x83, 0xf3, 0x69, 0xcc, 0x13, 0x1f, 0x77, 0x3c, 0xe4, 0x25, 0xb4, 0x64, 0xe9, 0x6e, 0x8, 0xa7, 0x7b, 0x1, 0x37, 0xfc, 0x11, 0x93, 0x4e, 0xe6, 0x80, 0x91, 0x88, 0x42, 0x1d, 0xde, 0x9c, 0x51, 0x3f, 0x83, 0x85, 0x88, 0x90, 0xac, 0x42, 0xf4, 0x3d, 0x79, 0xec, 0xcb, 0xd6, 0x37, 0x37, 0xbe, 0xe8, 0xcc, 0xd, 0x9b, 0x14, 0xb9, 0xfb, 0x6f, 0x7f, 0x8a, 0x4d, 0x7f, 0x63, 0x2e, 0x8d, 0x76, 0x9, 0x9c, 0x7, 0x5c, 0x6c, 0x4f, 0x3d, 0x4b, 0x46, 0xcb, 0x90, 0xa8, 0xb0, 0xa9, 0xc4, 0xc1, 0x38, 0xd1, 0x13, 0xd7, 0x4c, 0x4c, 0x41, 0xf7, 0xdc, 0x53, 0x2, 0xbe, 0xbd, 0xa4, 0x52, 0x50, 0x75, 0x10, 0xab, 0xdf, 0xd1, 0xd2, 0x6d, 0xd7, 0x62, 0x85, 0x33, 0x51, 0x10, 0x5e, 0xbd, 0x22, 0x8a, 0xe7, 0xac, 0xef, 0x16, 0x9d, 0x58, 0x58, 0x78, 0x87, 0x96, 0x4a, 0xe0, 0x88, 0xc9, 0x58, 0x8b, 0x2, 0xcd, 0xf2, 0x19, 0x9f, 0x16, 0x41, 0x9b, 0xa3, 0x7e, 0xca, 0x7e, 0x1a, 0x29, 0x24, 0xa4, 0x2a, 0xc1, 0x68, 0xf6, 0x5a, 0x2c, 0xc2, 0x91, 0x21, 0x5b, 0x7a, 0xf5, 0x67, 0x48, 0x70, 0x6a, 0x7d, 0xac, 0xf5, 0x1c, 0xa0, 0xb4, 0x71, 0x53, 0xc, 0x3c, 0x78, 0xa4},
		{0x53, 0x52, 0x95, 0x64, 0x7f, 0xce, 0xb6, 0xbb, 0xb7, 0xe9, 0xea, 0x78, 0xca, 0x37, 0x44, 0x3f, 0xdd, 0x72, 0x17, 0xc6, 0xfd, 0x3b, 0x88, 0x76, 0x6b, 0xe0, 0x7a, 0x79, 0x31, 0xc1, 0x3e, 0x46, 0x30, 0xb6, 0x6, 0xb4, 0x2a, 0xc7, 0x99, 0xba, 0xc3, 0xe8, 0xa7, 0xa3, 0x46, 0xd3, 0x7a, 0x5a, 0xdc, 0x50, 0x17, 0x95, 0xba, 0xd2, 0xaf, 0xaf, 0x8a, 0x40, 0x1, 0x26, 0x42, 0x38, 0x0, 0x5f, 0x0, 0x8b, 0x0, 0xcb, 0x2d, 0x8f, 0x8, 0x6e, 0xa0, 0xb1, 0x5d, 0x64, 0xb4, 0xd6, 0x2e, 0x26, 0x1b, 0x4f, 0xca, 0x95, 0xfe, 0xed, 0xd5, 0x12, 0x21, 0x93, 0x44, 0x53, 0xa1, 0x79, 0x1f, 0xa, 0x23, 0x9a, 0x15, 0xee, 0x43, 0xdb, 0xd, 0x15, 0x5b, 0xa0, 0xcb, 0x1a, 0xf5, 0xdb, 0x62, 0xe0, 0x9a, 0x81, 0xbc, 0xd2, 0xa3, 0x8e, 0x9a, 0xd0, 0x16, 0xb8, 0x88, 0x27, 0xb2, 0x96, 0x9, 0xdb, 0xb0, 0x4f, 0x3e, 0x67, 0xe2, 0x8e, 0x25, 0xb1, 0x3d, 0x50, 0x1e, 0xd4, 0x43, 0xc, 0xd9, 0x5a, 0xd2, 0x85, 0xaf, 0xe0, 0x81, 0x36, 0x41, 0x42, 0xcd, 0xa1, 0xf3, 0xa0, 0xa7, 0x87, 0xd9, 0xd, 0x42, 0x39, 0xe9, 0x5, 0xa5, 0x6e, 0x41, 0x3f, 0xe0, 0x39, 0x1f, 0x68, 0xba, 0xc3, 0xe6, 0x38, 0xbd, 0x39, 0xc0, 0x5f, 0xa0, 0xba, 0x5a, 0x67, 0xd, 0x7e, 0xf9, 0x12, 0x56, 0xb4, 0x15, 0x4c, 0xea, 0x97, 0xe4, 0xd0, 0x76, 0x7d, 0x26, 0x96, 0xd, 0x15, 0x6b, 0x34, 0x2b, 0x3f, 0x25, 0xdf, 0xc1, 0x1, 0x12, 0xd4, 0xea, 0xfa, 0x74, 0x22, 0xd5, 0x2c, 0x71, 0xaf, 0x73, 0x1f, 0x9a, 0x6c, 0x6e, 0x87, 0x34, 0x40, 0xc5, 0xd1, 0x29, 0xc9, 0xaf, 0xe9, 0x6c, 0xa, 0x4c, 0xae, 0x74, 0xa7, 0x8e, 0x81, 0xce, 0x11, 0x90, 0xd, 0x3c, 0x8c, 0x6e, 0x88, 0x37, 0x5b, 0xb6, 0x41, 0x1e, 0xff},
		{0x4c, 0x60, 0x53, 0x72, 0xe8, 0xcf, 0x87, 0x6b, 0x87, 0xcb, 0xa1, 0xcd, 0xbc, 0x5f, 0x2e, 0xea, 0x4e, 0xd, 0x90, 0xec, 0x7, 0xef, 0xf, 0x8c, 0x6b, 0xff, 0x15, 0x78, 0x43, 0x46, 0xf4, 0x74, 0x9e, 0x2b, 0xbc, 0x3f, 0x5e, 0x12, 0x38, 0x50, 0x12, 0x22, 0x0, 0xe8, 0x72, 0xab, 0x6, 0xe4, 0xb2, 0x17, 0x66, 0xc2, 0xc4, 0x3d, 0x25, 0x46, 0xf3, 0xf4, 0x8b, 0x80, 0xa2, 0x1c, 0x1d, 0x8c, 0xb9, 0x1b, 0xfa, 0xe9, 0xe5, 0xac, 0xda, 0xf5, 0x28, 0xcf, 0x92, 0xb0, 0x44, 0xe, 0xc8, 0xd6, 0x73, 0x9a, 0xd6, 0x45, 0x6f, 0xb3, 0x65, 0xa4, 0x79, 0x16, 0x7, 0x9d, 0xa2, 0x8d, 0xfe, 0xfc, 0xb1, 0x68, 0x4f, 0xe4, 0xe7, 0xa4, 0x61, 0xd0, 0xe2, 0x0, 0x3a, 0xaf, 0xd2, 0xdd, 0x88, 0xa, 0xb5, 0xfb, 0xa6, 0xec, 0x79, 0x92, 0x34, 0x90, 0xd5, 0x3a, 0xa7, 0x6d, 0x8d, 0xd0, 0x6b, 0x96, 0x25, 0x4e, 0x39, 0x42, 0x12, 0x85, 0x0, 0x12, 0x50, 0xb3, 0x2, 0x7c, 0x43, 0xd5, 0x24, 0x50, 0xec, 0x3f, 0x4b, 0x84, 0xe5, 0x6c, 0xf4, 0xde, 0x38, 0x58, 0x4a, 0x21, 0x6c, 0xeb, 0x20, 0xbc, 0x7d, 0x40, 0xfe, 0xb8, 0x72, 0x67, 0xa, 0xa1, 0x98, 0xdb, 0xa4, 0xcd, 0x78, 0x10, 0xa5, 0x15, 0xeb, 0xd0, 0x16, 0x10, 0x8a, 0xfe, 0x81, 0x42, 0x30, 0x19, 0x71, 0xe5, 0x6d, 0x38, 0xc3, 0x5c, 0x2c, 0x3f, 0x5, 0xec, 0xdc, 0x1c, 0xf3, 0x8b, 0xf5, 0x78, 0x21, 0xe5, 0x2d, 0x27, 0x6b, 0x60, 0x4f, 0xd9, 0xce, 0xfb, 0xba, 0xec, 0xa8, 0x4c, 0x5c, 0x6b, 0x45, 0x18, 0x98, 0x72, 0xf7, 0x8f, 0xfb, 0x9, 0xd6, 0x91, 0x67, 0x13, 0x32, 0x72, 0xdd, 0x38, 0x2d, 0x16, 0xb5, 0x5e, 0x92, 0x2a, 0x3b, 0xb2, 0x99, 0xa4, 0xba, 0xc9, 0xbd, 0xf6, 0x0, 0x5a, 0xf8, 0xe5, 0x97, 0x35, 0xb8, 0x2b},
		{0x40, 0xde, 0xed, 0x5d, 0xec, 0xe5, 0xf9, 0x5a, 0x45, 0x6d, 0xf4, 0x32, 0x6b, 0xb7, 0xde, 0xd4, 0xe, 0x29, 0xca, 0x8a, 0xfc, 0x6b, 0x5e, 0xa, 0x78, 0x60, 0xae, 0x78, 0xa0, 0x6b, 0x44, 0x74, 0x29, 0x26, 0xd8, 0x7, 0x71, 0xa5, 0xa0, 0x81, 0x9e, 0x2b, 0x1d, 0xe0, 0x8a, 0x49, 0xc5, 0x4c, 0x99, 0xe3, 0x9e, 0x83, 0xcb, 0x36, 0xf3, 0x29, 0x46, 0x42, 0x6f, 0x9, 0x9c, 0xf1, 0x5d, 0xb5, 0x62, 0x6d, 0xaa, 0x1e, 0xc9, 0x6e, 0xf1, 0x2b, 0x46, 0x73, 0xae, 0x3f, 0xa6, 0xe, 0xc6, 0x3b, 0x51, 0x94, 0x19, 0x46, 0xb2, 0x46, 0x7a, 0xe6, 0x39, 0xbd, 0xdc, 0xca, 0xac, 0x13, 0xea, 0x5f, 0x2f, 0x90, 0x30, 0x69, 0x9e, 0xec, 0x36, 0xcb, 0xab, 0xcc, 0xba, 0x18, 0xb0, 0xce, 0x3a, 0xf7, 0xed, 0x4a, 0x1a, 0xad, 0x41, 0xb9, 0x4c, 0x38, 0xf, 0xac, 0x38, 0x8e, 0x26, 0xec, 0x39, 0x55, 0x85, 0x7f, 0xe6, 0xd7, 0x6f, 0x76, 0xcc, 0x91, 0x95, 0x93, 0x22, 0xed, 0x75, 0x1c, 0x44, 0xc8, 0xb3, 0x7e, 0x78, 0x47, 0xb5, 0x69, 0x19, 0xc8, 0xec, 0x34, 0x75, 0x5b, 0xae, 0xf2, 0x9f, 0x17, 0xb1, 0xa8, 0x1b, 0x5, 0x63, 0x46, 0x73, 0xc, 0x77, 0xac, 0x44, 0x88, 0xec, 0x1f, 0x0, 0xcc, 0xcc, 0x90, 0xad, 0xa9, 0xdd, 0x94, 0x6e, 0xac, 0x77, 0x2c, 0x83, 0xd8, 0x5e, 0x4d, 0xb6, 0x13, 0xf9, 0xc2, 0x27, 0x9b, 0x57, 0x8f, 0x1b, 0xa, 0x7f, 0x3b, 0x16, 0xaa, 0x2c, 0x9a, 0x77, 0xad, 0x1, 0x7f, 0x42, 0xdf, 0x8f, 0x52, 0x18, 0x5a, 0x9b, 0x7f, 0x18, 0x56, 0x30, 0x64, 0x91, 0xe, 0x86, 0xa0, 0xc2, 0xf1, 0x4a, 0x5a, 0xed, 0x44, 0x78, 0x3e, 0xb8, 0xff, 0x2b, 0xed, 0x1c, 0x7a, 0xb, 0xeb, 0x5, 0x55, 0x62, 0x57, 0xce, 0xb6, 0xc7, 0x57, 0xab, 0xe0, 0x8, 0x27, 0x6d, 0x8e},
		{0xde, 0xd6, 0x85, 0x47, 0x86, 0x65, 0xc6, 0xc9, 0x35, 0xd0, 0x7b, 0x7a, 0x9b, 0x6c, 0x89, 0xf7, 0x89, 0x35, 0x5f, 0x1e, 0x92, 0xbc, 0xa, 0x3e, 0xe9, 0xe6, 0xff, 0x3f, 0x26, 0xde, 0x77, 0xa5, 0xc6, 0x5a, 0xbf, 0xdf, 0x6b, 0x7b, 0x81, 0x22, 0xe4, 0xe3, 0x90, 0xab, 0xae, 0x44, 0xe1, 0xaf, 0x60, 0xc9, 0x79, 0x7d, 0xcd, 0xfd, 0x7a, 0xf4, 0xfc, 0x7b, 0x7b, 0x1c, 0xbf, 0x32, 0x86, 0xb5, 0x20, 0x22, 0xb2, 0x35, 0xbf, 0xe3, 0xd5, 0xa, 0x8d, 0xb2, 0x65, 0x7d, 0xa0, 0xc1, 0x86, 0xd3, 0x46, 0x66, 0x7a, 0xfe, 0xa0, 0x7e, 0xc6, 0x97, 0x56, 0x29, 0xf5, 0xdd, 0x9e, 0x81, 0xdb, 0xbc, 0xc1, 0x11, 0x92, 0xd4, 0x36, 0xe0, 0x66, 0x48, 0xe7, 0x19, 0x3, 0x16, 0xd6, 0x4b, 0x88, 0xe4, 0x6f, 0x18, 0xff, 0xfe, 0x59, 0x94, 0xac, 0xaf, 0x1d, 0x69, 0x0, 0x29, 0x37, 0x19, 0xff, 0x82, 0x3d, 0x8f, 0x14, 0xa9, 0xe3, 0xe8, 0xd7, 0x2b, 0x78, 0xf9, 0x96, 0xc4, 0x9a, 0x4e, 0xf5, 0xa8, 0xbd, 0xe5, 0xec, 0xa, 0x1e, 0x7b, 0x3a, 0xad, 0xf0, 0x2a, 0xd5, 0xd8, 0xa3, 0x8e, 0xbf, 0xbb, 0xa4, 0x4b, 0xaf, 0x1a, 0x63, 0xe6, 0x41, 0x65, 0x42, 0xcc, 0xcf, 0xcb, 0x36, 0x3, 0x58, 0x19, 0xf, 0xb7, 0xaf, 0x34, 0x85, 0xf, 0xce, 0x5d, 0xe7, 0x36, 0xf3, 0x37, 0xf3, 0x1d, 0x78, 0xff, 0x58, 0x8a, 0x93, 0x32, 0xfe, 0x41, 0xad, 0x1, 0x2e, 0xab, 0x2, 0xc9, 0xdd, 0xd1, 0xb8, 0x91, 0xf4, 0x19, 0xc6, 0x7e, 0x58, 0x86, 0x29, 0xae, 0xcf, 0xcb, 0x30, 0xaf, 0xcd, 0xae, 0x9e, 0xc7, 0x85, 0x75, 0x2d, 0x1a, 0x2f, 0xe9, 0xa2, 0x8a, 0x1d, 0x49, 0x8f, 0x4e, 0x39, 0xbd, 0x0, 0x9, 0x16, 0x79, 0xab, 0x3a, 0x4c, 0xc, 0x9c, 0x74, 0xea, 0x8e, 0x42, 0xa4, 0x22, 0x9d, 0x15, 0xad},
	}

	// Generate keys and messages
	var keys, msgs []*cyclic.Int
	keyPrng := rand.New(rand.NewSource(3271645196))
	msgPrng := rand.New(rand.NewSource(3102644637))
	for i := 0; i < 16; i++ {
		keys = append(keys, cyclic.NewInt(keyPrng.Int63()))
		msgs = append(msgs, cyclic.NewInt(msgPrng.Int63()))
	}

	prng := rand.New(rand.NewSource(42))

	for i := 0; i < len(msgs); i++ {
		encMsg, err := encrypt(grp, keys[i], msgs[i], prng)

		if err != nil {
			t.Errorf("encrypt() produced an unexpected error\n\treceived: %#v\n\texpected: %#v", err, nil)
		}

		if !reflect.DeepEqual(expectedMsgs[i], encMsg.Bytes()) {
			t.Errorf("encrypt() did not produce the correct message\n\treceived: %#v\n\texpected: %#v", expectedMsgs[i], encMsg.Bytes())
		}
	}
}

func TestEncrypt_ErrorOnLongMessage(t *testing.T) {
	// Create group
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	p := cyclic.NewIntFromString(primeString, 16)
	min := cyclic.NewInt(2)
	max := cyclic.NewInt(0)
	max.Mul(p, cyclic.NewInt(1000))
	seed := cyclic.NewInt(42)
	rng := cyclic.NewRandom(min, max)
	g := cyclic.NewInt(2)
	grp := cyclic.NewGroup(p, seed, g, rng)

	// Create key and message
	rand.Seed(42)
	msgBytes := make([]byte, 4000)
	rand.Read(msgBytes)
	msg := cyclic.NewIntFromBytes(msgBytes)
	key := cyclic.NewInt(65)

	// Encrypt key
	encMsg, err := Encrypt(grp, key, msg)

	if err == nil {
		t.Errorf("Encrypt() did not produce the expected error\n\treceived: %#v\n\texpected: %#v", err, errors.New("message too long"))
	}

	if encMsg != nil {
		t.Errorf("Encrypt() unexpectedly produced a non-nil message on error\n\treceived: %v\n\texpected: %v", encMsg, nil)
	}
}

func TestDecrypt_ErrorOnPaddingPrefix(t *testing.T) {
	// Create group
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	p := cyclic.NewIntFromString(primeString, 16)
	min := cyclic.NewInt(2)
	max := cyclic.NewInt(0)
	max.Mul(p, cyclic.NewInt(1000))
	seed := cyclic.NewInt(42)
	rng := cyclic.NewRandom(min, max)
	g := cyclic.NewInt(2)
	grp := cyclic.NewGroup(p, seed, g, rng)

	// Create key and message
	rand.Seed(42)
	msgBytes := make([]byte, 40)
	rand.Read(msgBytes)
	msg := cyclic.NewIntFromBytes(msgBytes)
	key := cyclic.NewInt(65)

	// Decrypt key
	dncMsg, err := Decrypt(grp, key, msg)

	if err == nil {
		t.Errorf("Decrypt() did not produce the expected error\n\treceived: %#v\n\texpected: %#v", err, errors.New("padding prefix invalid"))
	}

	if dncMsg != nil {
		t.Errorf("Decrypt() unexpectedly produced a non-nil message on error\n\treceived: %v\n\texpected: %v", dncMsg, nil)
	}
}
