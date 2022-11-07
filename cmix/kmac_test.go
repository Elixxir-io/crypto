////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package cmix

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"reflect"
	"testing"
)

//Tests that the kmac function outputs wha
func TestGenerateKMAC_Consistency(t *testing.T) {

	grp := grpTest()

	rng := rand.New(rand.NewSource(42))

	roundID := id.Round(42)

	h, err := hash.NewCMixHash()

	if err != nil {
		t.Errorf("Could not get cmixHash: %+v", h)
	}

	for i := 0; i < 100; i++ {

		baseKeyBytes, err := csprng.GenerateInGroup(grp.GetPBytes(), grp.GetP().ByteLen(), rng)
		if err != nil {
			t.Errorf("could not generate base base keys")
		}
		baseKey := grp.NewIntFromBytes(baseKeyBytes)

		salt := make([]byte, 32)
		_, err = rng.Read(salt)
		if err != nil {
			t.Errorf("could not generate salt")
		}

		kmac := GenerateKMAC(salt, baseKey, roundID, h)

		if !reflect.DeepEqual(kmac, precannedKMAC[i]) {
			t.Errorf("KMAC %v did not match expected:"+
				"\n  Received: %v\n  Expected: %v", i, kmac, precannedKMAC[i])
		}
	}
}

//Tests that the kmac function outputs wha
func TestGenerateKMACs_Consistency(t *testing.T) {

	grp := grpTest()

	rng := rand.New(rand.NewSource(42))

	h, err := hash.NewCMixHash()

	if err != nil {
		t.Errorf("Could not get cmixHash: %+v", h)
	}

	roundID := id.Round(42)

	numbaseKeys := 3

	for i := 0; i < 10; i++ {

		var baseKeys []*cyclic.Int

		for i := 0; i < numbaseKeys; i++ {
			baseKeyBytes, err := csprng.GenerateInGroup(grp.GetPBytes(), grp.GetP().ByteLen(), rng)
			if err != nil {
				t.Errorf("could not generate base base keys")
			}
			baseKey := grp.NewIntFromBytes(baseKeyBytes)
			baseKeys = append(baseKeys, baseKey)
		}

		salt := make([]byte, 32)
		_, err = rng.Read(salt)
		if err != nil {
			t.Errorf("could not generate salt")
		}

		kmacs := GenerateKMACs(salt, baseKeys, roundID, h)

		if !reflect.DeepEqual(kmacs, precannedKMACs[i]) {
			t.Errorf("KMAC %v did not match expected:"+
				"\n  Received: %v\n  Expected: %v", i, kmacs, precannedKMACs[i])
		}
	}
}

//Happy path
func TestVerifyKMAC(t *testing.T) {
	grp := grpTest()

	rng := rand.New(rand.NewSource(42))

	h, err := hash.NewCMixHash()

	if err != nil {
		t.Errorf("Could not get cmixHash: %+v", h)
	}

	roundID := id.Round(42)

	for i := 0; i < 100; i++ {

		baseKeyBytes, err := csprng.GenerateInGroup(grp.GetPBytes(), grp.GetP().ByteLen(), rng)
		if err != nil {
			t.Errorf("could not generate base base keys")
		}
		baseKey := grp.NewIntFromBytes(baseKeyBytes)

		salt := make([]byte, 32)
		_, err = rng.Read(salt)
		if err != nil {
			t.Errorf("could not generate salt")
		}

		kmac := GenerateKMAC(salt, baseKey, roundID, h)

		if !VerifyKMAC(kmac, salt, baseKey, roundID, h) {
			t.Errorf("KMAC %v could not be verified", i)
		}
	}
}

//Error path
func TestVerifyKMAC_WrongExpectedKmac(t *testing.T) {

	grp := grpTest()

	rng := rand.New(rand.NewSource(42))

	h, err := hash.NewCMixHash()

	roundID := id.Round(42)

	if err != nil {
		t.Errorf("Could not get cmixHash: %+v", h)
	}

	baseKeyBytes, err := csprng.GenerateInGroup(grp.GetPBytes(), grp.GetP().ByteLen(), rng)
	if err != nil {
		t.Errorf("could not generate base base keys")
	}
	baseKey := grp.NewIntFromBytes(baseKeyBytes)

	salt := make([]byte, 32)
	_, err = rng.Read(salt)
	if err != nil {
		t.Errorf("could not generate salt")
	}

	//Pass in a 'bad' kmac (ie one that would not be generated by the salt/basekey/hash)
	if !VerifyKMAC(make([]byte, 2), salt, baseKey, roundID, h) {
		return
	}
	t.Errorf("KMAC should not have been verified")

}

//Error path
func TestVerifyKACY_Mismatch(t *testing.T) {
	grp := grpTest()

	rng := rand.New(rand.NewSource(42))

	h, err := hash.NewCMixHash()

	if err != nil {
		t.Errorf("Could not get cmixHash: %+v", h)
	}

	roundID := id.Round(42)

	for i := 0; i < 100; i++ {

		baseKeyBytes, err := csprng.GenerateInGroup(grp.GetPBytes(), grp.GetP().ByteLen(), rng)
		if err != nil {
			t.Errorf("could not generate base base keys")
		}
		baseKey := grp.NewIntFromBytes(baseKeyBytes)

		salt := make([]byte, 32)
		_, err = rng.Read(salt)
		if err != nil {
			t.Errorf("could not generate salt")
		}

		kmac := make([]byte, 32)
		rng.Read(kmac)

		if VerifyKMAC(kmac, salt, baseKey, roundID, h) {
			t.Errorf("KMAC %v verified when it shouldnt", i)
		}
	}
}

var precannedKMAC = [][]byte{
	{181, 13, 154, 82, 75, 190, 115, 166, 125, 118, 36, 134, 188, 45, 235, 21, 166, 197, 237, 26, 76, 24, 62, 56, 205, 250, 215, 94, 222, 172, 143, 59},
	{214, 240, 76, 229, 171, 249, 151, 69, 14, 172, 141, 255, 220, 246, 142, 108, 197, 56, 160, 247, 97, 127, 114, 189, 184, 188, 63, 199, 239, 253, 179, 10},
	{196, 47, 45, 170, 179, 119, 113, 27, 192, 0, 77, 199, 70, 175, 204, 39, 217, 213, 212, 83, 145, 32, 32, 65, 166, 203, 134, 248, 250, 11, 188, 179},
	{125, 97, 249, 157, 122, 147, 38, 238, 152, 20, 103, 133, 108, 164, 0, 27, 178, 0, 156, 7, 209, 75, 10, 25, 207, 190, 14, 13, 46, 218, 62, 40},
	{186, 208, 33, 153, 211, 24, 48, 89, 103, 66, 180, 126, 84, 94, 86, 35, 46, 188, 160, 94, 16, 246, 227, 254, 220, 173, 109, 56, 12, 252, 210, 85},
	{241, 126, 195, 101, 74, 134, 231, 77, 117, 156, 59, 16, 250, 88, 53, 39, 6, 13, 198, 144, 91, 37, 156, 233, 154, 61, 158, 254, 135, 94, 29, 212},
	{51, 227, 158, 103, 184, 101, 110, 41, 157, 31, 63, 57, 218, 248, 94, 77, 127, 239, 108, 228, 239, 179, 107, 120, 137, 255, 143, 93, 21, 105, 43, 57},
	{154, 16, 181, 172, 32, 124, 175, 196, 174, 242, 159, 38, 247, 166, 47, 174, 52, 48, 111, 204, 174, 11, 57, 92, 87, 140, 43, 104, 133, 86, 131, 193},
	{132, 170, 90, 241, 45, 208, 132, 67, 69, 216, 172, 35, 36, 54, 143, 216, 237, 248, 136, 33, 39, 75, 216, 177, 186, 10, 253, 123, 230, 167, 253, 240},
	{146, 87, 216, 205, 142, 147, 62, 19, 134, 217, 90, 97, 209, 150, 235, 190, 198, 166, 168, 67, 59, 97, 58, 43, 31, 150, 17, 51, 159, 126, 135, 78},
	{220, 90, 164, 68, 185, 94, 254, 87, 139, 33, 125, 134, 208, 11, 48, 237, 198, 225, 180, 139, 37, 88, 63, 60, 232, 184, 149, 5, 122, 78, 146, 190},
	{93, 119, 249, 132, 142, 12, 44, 238, 213, 162, 245, 2, 178, 190, 146, 208, 18, 4, 86, 83, 26, 220, 153, 216, 170, 235, 204, 122, 151, 42, 16, 102},
	{249, 80, 161, 135, 183, 15, 65, 221, 227, 0, 141, 143, 124, 90, 76, 160, 239, 43, 219, 187, 204, 62, 219, 73, 139, 128, 228, 53, 202, 161, 15, 176},
	{93, 145, 13, 226, 75, 118, 179, 207, 108, 106, 169, 190, 190, 22, 94, 182, 234, 115, 220, 23, 241, 2, 224, 209, 85, 68, 98, 125, 2, 6, 220, 140},
	{233, 111, 159, 18, 73, 251, 178, 30, 191, 158, 156, 40, 25, 235, 0, 99, 36, 106, 96, 233, 214, 200, 192, 100, 231, 1, 223, 79, 49, 188, 144, 68},
	{243, 199, 5, 178, 8, 68, 7, 75, 9, 134, 223, 120, 241, 129, 155, 128, 10, 6, 5, 206, 193, 19, 249, 41, 48, 226, 111, 45, 15, 0, 177, 133},
	{38, 150, 238, 92, 118, 219, 181, 93, 238, 8, 189, 199, 33, 153, 78, 105, 201, 146, 81, 198, 170, 105, 143, 190, 109, 64, 246, 246, 82, 146, 101, 96},
	{189, 127, 253, 219, 12, 201, 233, 16, 177, 97, 198, 105, 23, 121, 44, 209, 46, 95, 128, 150, 177, 241, 71, 242, 48, 229, 193, 60, 222, 162, 164, 191},
	{232, 5, 113, 7, 201, 67, 132, 86, 109, 155, 166, 41, 64, 237, 3, 62, 123, 167, 254, 122, 39, 40, 111, 70, 31, 213, 177, 75, 167, 15, 129, 2},
	{136, 13, 65, 85, 153, 16, 227, 4, 166, 138, 61, 91, 233, 8, 169, 20, 245, 3, 204, 184, 110, 159, 112, 160, 26, 56, 153, 218, 74, 67, 235, 37},
	{243, 229, 60, 164, 206, 242, 113, 8, 113, 37, 202, 225, 8, 234, 157, 140, 102, 62, 55, 237, 51, 159, 204, 186, 22, 155, 1, 187, 233, 79, 181, 201},
	{138, 92, 140, 229, 148, 51, 160, 117, 38, 226, 64, 6, 187, 208, 132, 216, 45, 75, 103, 193, 3, 240, 130, 160, 12, 125, 130, 15, 220, 131, 230, 196},
	{94, 92, 48, 190, 38, 148, 159, 151, 176, 64, 38, 217, 36, 56, 22, 118, 230, 191, 206, 53, 3, 57, 36, 59, 238, 83, 0, 93, 124, 114, 217, 193},
	{45, 134, 2, 47, 117, 242, 21, 235, 2, 123, 251, 74, 220, 50, 137, 249, 233, 204, 31, 150, 223, 241, 28, 47, 212, 53, 58, 32, 155, 147, 198, 211},
	{164, 4, 164, 160, 178, 108, 186, 79, 122, 235, 120, 202, 15, 113, 124, 13, 24, 63, 225, 165, 94, 117, 241, 83, 78, 29, 77, 249, 201, 205, 228, 240},
	{49, 44, 71, 229, 31, 136, 18, 153, 246, 145, 63, 239, 249, 95, 246, 109, 222, 98, 92, 16, 131, 130, 63, 211, 153, 27, 72, 143, 45, 214, 209, 102},
	{4, 34, 103, 143, 210, 82, 179, 129, 27, 48, 177, 130, 241, 168, 197, 64, 127, 144, 35, 141, 24, 131, 74, 187, 3, 193, 205, 116, 250, 85, 14, 95},
	{10, 239, 179, 147, 31, 45, 69, 131, 1, 243, 1, 140, 7, 246, 228, 79, 139, 41, 13, 145, 69, 81, 124, 247, 224, 159, 6, 129, 42, 250, 130, 138},
	{242, 230, 223, 195, 42, 73, 47, 142, 139, 31, 241, 71, 55, 226, 25, 92, 90, 120, 162, 223, 110, 161, 52, 46, 59, 244, 149, 199, 139, 219, 217, 26},
	{165, 35, 171, 63, 211, 231, 56, 242, 238, 107, 137, 33, 55, 146, 234, 80, 49, 88, 143, 248, 40, 45, 204, 29, 172, 88, 195, 27, 250, 191, 251, 98},
	{169, 229, 72, 85, 115, 190, 114, 121, 239, 205, 3, 158, 174, 239, 238, 233, 14, 158, 220, 127, 62, 135, 107, 59, 185, 10, 135, 184, 107, 174, 199, 41},
	{148, 247, 209, 78, 228, 25, 2, 47, 109, 186, 55, 58, 252, 14, 89, 18, 127, 198, 138, 64, 21, 99, 235, 225, 222, 223, 245, 134, 134, 63, 114, 74},
	{105, 66, 195, 1, 196, 68, 172, 79, 175, 104, 27, 199, 156, 246, 101, 104, 250, 247, 234, 198, 214, 217, 195, 192, 124, 96, 122, 30, 8, 19, 89, 187},
	{181, 58, 252, 159, 53, 160, 176, 67, 148, 98, 103, 36, 64, 114, 229, 50, 199, 24, 211, 20, 116, 29, 216, 240, 63, 183, 35, 36, 26, 9, 132, 138},
	{51, 132, 254, 146, 111, 138, 56, 1, 175, 172, 79, 123, 194, 214, 53, 5, 112, 210, 62, 146, 140, 131, 241, 40, 184, 161, 99, 34, 84, 232, 35, 167},
	{53, 45, 5, 149, 81, 157, 119, 255, 122, 149, 159, 90, 38, 58, 62, 198, 184, 21, 66, 16, 80, 100, 27, 139, 253, 81, 44, 124, 221, 143, 223, 235},
	{167, 114, 104, 248, 72, 164, 255, 81, 181, 242, 103, 148, 30, 90, 105, 201, 112, 90, 164, 146, 228, 155, 147, 192, 59, 212, 36, 46, 19, 242, 132, 30},
	{205, 80, 209, 131, 251, 240, 39, 149, 23, 10, 187, 81, 4, 29, 176, 42, 6, 242, 238, 185, 242, 225, 87, 244, 217, 128, 213, 53, 29, 112, 91, 208},
	{245, 218, 74, 103, 254, 254, 142, 186, 44, 71, 251, 137, 135, 57, 169, 202, 235, 210, 45, 165, 222, 7, 124, 129, 44, 18, 149, 194, 188, 124, 46, 53},
	{110, 142, 162, 157, 188, 63, 253, 170, 247, 142, 184, 46, 238, 80, 63, 213, 215, 80, 103, 125, 234, 146, 33, 177, 227, 50, 152, 199, 180, 36, 31, 2},
	{230, 102, 41, 222, 223, 30, 197, 109, 241, 150, 101, 176, 71, 58, 27, 239, 95, 112, 193, 71, 254, 254, 89, 155, 214, 10, 221, 154, 173, 162, 154, 39},
	{27, 129, 101, 35, 201, 164, 248, 173, 107, 233, 123, 17, 241, 24, 111, 135, 88, 255, 56, 103, 183, 4, 136, 100, 123, 48, 230, 121, 176, 20, 178, 1},
	{131, 6, 171, 62, 202, 24, 130, 213, 149, 255, 129, 10, 115, 24, 82, 168, 170, 202, 179, 241, 33, 190, 238, 62, 42, 124, 155, 170, 100, 157, 66, 115},
	{147, 162, 72, 236, 126, 11, 121, 253, 95, 22, 107, 64, 238, 224, 76, 56, 41, 113, 127, 170, 66, 48, 67, 113, 134, 13, 157, 27, 106, 127, 110, 10},
	{30, 247, 76, 117, 162, 208, 253, 251, 208, 48, 14, 154, 119, 11, 228, 201, 67, 67, 95, 146, 227, 49, 205, 1, 212, 233, 109, 226, 96, 131, 199, 200},
	{116, 104, 89, 49, 251, 14, 149, 230, 122, 184, 211, 157, 1, 240, 155, 178, 102, 35, 31, 189, 18, 242, 1, 240, 140, 93, 5, 151, 36, 36, 148, 68},
	{153, 80, 80, 211, 173, 151, 151, 69, 129, 253, 27, 5, 97, 212, 27, 2, 255, 23, 136, 219, 220, 50, 169, 47, 14, 221, 196, 6, 116, 254, 239, 43},
	{44, 173, 234, 59, 124, 85, 151, 176, 242, 59, 176, 68, 57, 248, 80, 73, 61, 217, 31, 122, 100, 2, 30, 43, 70, 243, 174, 126, 139, 110, 29, 3},
	{65, 25, 2, 106, 76, 157, 103, 20, 208, 157, 125, 224, 225, 159, 21, 94, 211, 117, 181, 109, 134, 8, 222, 182, 226, 45, 4, 24, 216, 81, 28, 22},
	{222, 219, 247, 26, 252, 121, 93, 204, 50, 113, 34, 38, 45, 33, 79, 85, 182, 104, 34, 124, 62, 235, 84, 121, 25, 190, 240, 9, 33, 238, 252, 61},
	{138, 241, 190, 231, 246, 253, 130, 216, 230, 195, 49, 231, 44, 255, 135, 91, 74, 104, 37, 119, 181, 240, 206, 22, 216, 116, 22, 67, 7, 59, 174, 114},
	{39, 121, 196, 81, 48, 80, 60, 89, 166, 6, 95, 12, 95, 93, 50, 248, 192, 18, 71, 117, 97, 78, 175, 173, 143, 239, 122, 235, 52, 229, 197, 76},
	{11, 199, 111, 47, 29, 184, 133, 155, 79, 231, 89, 151, 1, 30, 221, 132, 158, 160, 76, 65, 54, 15, 209, 95, 202, 127, 151, 98, 72, 235, 136, 231},
	{211, 154, 40, 78, 167, 218, 132, 245, 173, 240, 97, 94, 78, 68, 126, 123, 70, 28, 114, 114, 223, 235, 235, 77, 244, 171, 168, 148, 215, 152, 143, 250},
	{118, 73, 34, 75, 244, 174, 99, 11, 246, 67, 22, 42, 188, 193, 140, 32, 53, 245, 248, 148, 22, 21, 218, 195, 33, 155, 115, 59, 85, 207, 96, 219},
	{225, 17, 162, 78, 174, 202, 76, 237, 98, 187, 244, 147, 45, 167, 166, 38, 230, 93, 144, 157, 44, 142, 51, 220, 150, 222, 91, 93, 74, 220, 67, 145},
	{151, 68, 146, 128, 29, 148, 87, 5, 73, 245, 92, 176, 98, 234, 113, 214, 138, 83, 200, 239, 180, 115, 16, 221, 138, 20, 94, 124, 29, 206, 88, 243},
	{198, 187, 41, 243, 230, 249, 221, 223, 29, 76, 23, 229, 5, 16, 76, 255, 139, 173, 173, 115, 112, 218, 113, 180, 49, 38, 22, 14, 30, 2, 200, 8},
	{87, 127, 242, 127, 158, 131, 171, 47, 67, 248, 230, 231, 28, 23, 28, 212, 159, 78, 2, 45, 34, 241, 92, 38, 237, 101, 67, 16, 143, 37, 233, 71},
	{175, 110, 157, 151, 168, 15, 169, 52, 133, 200, 133, 212, 88, 27, 32, 161, 249, 182, 153, 216, 232, 124, 230, 251, 224, 106, 55, 243, 183, 159, 84, 247},
	{22, 126, 248, 58, 98, 51, 2, 45, 129, 193, 174, 179, 12, 165, 99, 17, 18, 100, 53, 229, 246, 32, 157, 108, 145, 212, 106, 110, 199, 238, 94, 171},
	{109, 60, 90, 205, 230, 191, 197, 217, 135, 114, 32, 59, 168, 96, 214, 151, 250, 137, 148, 52, 29, 117, 36, 229, 40, 96, 160, 26, 128, 10, 252, 12},
	{58, 90, 255, 254, 136, 90, 191, 19, 104, 243, 240, 251, 71, 162, 128, 252, 122, 78, 84, 74, 211, 56, 220, 233, 251, 21, 209, 150, 167, 161, 95, 50},
	{82, 126, 217, 31, 39, 152, 203, 43, 161, 249, 245, 254, 39, 22, 129, 73, 164, 16, 101, 65, 65, 102, 167, 181, 61, 126, 167, 244, 149, 95, 117, 69},
	{118, 130, 221, 208, 207, 221, 51, 120, 76, 60, 115, 205, 128, 196, 78, 149, 100, 5, 124, 75, 187, 207, 20, 135, 178, 74, 44, 140, 102, 26, 123, 222},
	{233, 144, 17, 46, 131, 74, 5, 108, 43, 213, 32, 124, 250, 223, 207, 252, 74, 127, 244, 122, 166, 110, 31, 1, 163, 86, 201, 113, 196, 220, 63, 121},
	{195, 63, 52, 111, 116, 30, 198, 131, 123, 162, 89, 17, 63, 255, 154, 248, 211, 38, 121, 35, 2, 61, 140, 112, 10, 20, 251, 114, 29, 82, 162, 77},
	{201, 13, 71, 61, 68, 137, 96, 172, 40, 142, 79, 111, 40, 222, 117, 121, 18, 88, 248, 84, 86, 133, 103, 253, 193, 53, 139, 33, 148, 98, 5, 197},
	{168, 3, 53, 139, 183, 121, 112, 50, 20, 103, 57, 106, 195, 168, 27, 45, 164, 43, 20, 107, 173, 194, 156, 149, 141, 69, 222, 228, 93, 222, 198, 15},
	{230, 118, 128, 222, 216, 105, 105, 233, 90, 103, 212, 247, 118, 103, 208, 93, 254, 102, 204, 76, 23, 1, 104, 139, 184, 76, 208, 6, 139, 183, 162, 36},
	{157, 245, 103, 33, 134, 155, 254, 184, 163, 53, 45, 136, 223, 211, 246, 116, 138, 120, 7, 63, 91, 101, 22, 155, 70, 235, 160, 84, 123, 195, 230, 107},
	{190, 148, 23, 15, 230, 1, 141, 37, 68, 103, 47, 173, 139, 114, 73, 44, 165, 244, 198, 202, 137, 219, 238, 51, 43, 249, 47, 171, 236, 221, 60, 49},
	{157, 18, 48, 59, 17, 200, 78, 157, 91, 199, 46, 239, 129, 2, 217, 216, 183, 116, 158, 25, 51, 161, 55, 254, 73, 137, 235, 251, 46, 107, 183, 198},
	{163, 41, 185, 179, 88, 121, 130, 209, 124, 207, 42, 33, 244, 158, 180, 117, 89, 226, 239, 133, 66, 235, 151, 109, 201, 115, 76, 57, 168, 239, 221, 242},
	{248, 158, 236, 68, 1, 161, 228, 247, 95, 152, 58, 132, 26, 157, 101, 241, 204, 192, 250, 1, 127, 81, 89, 73, 242, 54, 132, 121, 65, 149, 229, 115},
	{225, 90, 58, 35, 221, 100, 248, 98, 212, 120, 7, 234, 49, 215, 43, 103, 185, 113, 234, 246, 198, 241, 72, 205, 214, 64, 202, 88, 151, 9, 169, 53},
	{106, 214, 88, 81, 87, 26, 51, 113, 251, 161, 206, 14, 87, 121, 146, 139, 130, 69, 44, 172, 13, 141, 119, 31, 56, 4, 61, 54, 20, 174, 149, 2},
	{136, 17, 72, 230, 170, 211, 207, 178, 172, 210, 25, 14, 26, 14, 37, 214, 96, 254, 48, 254, 64, 87, 116, 83, 213, 84, 219, 169, 104, 13, 15, 45},
	{107, 80, 172, 203, 34, 194, 192, 78, 131, 144, 95, 5, 74, 19, 38, 25, 174, 54, 25, 26, 208, 68, 37, 166, 135, 206, 185, 195, 225, 242, 94, 221},
	{218, 119, 216, 179, 224, 136, 209, 184, 200, 206, 48, 14, 200, 64, 243, 139, 213, 97, 46, 188, 101, 172, 99, 139, 224, 195, 141, 167, 156, 164, 120, 233},
	{83, 46, 41, 150, 246, 58, 234, 161, 178, 4, 236, 241, 246, 151, 46, 131, 189, 99, 184, 175, 28, 77, 252, 201, 195, 104, 222, 87, 7, 233, 227, 62},
	{177, 182, 22, 198, 67, 120, 196, 92, 105, 99, 113, 59, 109, 198, 172, 60, 84, 71, 44, 127, 155, 157, 68, 157, 34, 148, 252, 182, 196, 28, 40, 139},
	{2, 36, 190, 90, 194, 75, 188, 53, 89, 233, 96, 102, 150, 108, 132, 6, 63, 49, 67, 133, 102, 250, 131, 77, 5, 110, 195, 214, 216, 160, 143, 228},
	{135, 228, 128, 93, 249, 110, 2, 217, 95, 85, 178, 21, 133, 167, 78, 30, 49, 173, 4, 184, 56, 75, 210, 99, 247, 187, 137, 29, 18, 247, 255, 28},
	{99, 31, 248, 236, 233, 254, 239, 56, 66, 140, 118, 15, 195, 27, 38, 73, 161, 254, 122, 65, 130, 65, 196, 168, 39, 73, 173, 99, 60, 88, 23, 167},
	{186, 164, 255, 233, 234, 188, 233, 212, 208, 174, 1, 214, 177, 244, 126, 1, 185, 189, 231, 183, 193, 231, 165, 221, 214, 189, 139, 60, 211, 100, 39, 221},
	{195, 37, 19, 10, 38, 28, 215, 139, 17, 216, 62, 245, 177, 176, 185, 176, 23, 97, 240, 195, 95, 161, 212, 120, 115, 60, 144, 43, 52, 175, 35, 151},
	{164, 113, 137, 31, 174, 97, 241, 35, 47, 139, 190, 52, 201, 158, 82, 245, 213, 67, 131, 157, 73, 254, 151, 83, 66, 134, 159, 185, 109, 196, 16, 187},
	{129, 107, 198, 100, 171, 170, 148, 159, 62, 109, 90, 101, 194, 94, 121, 27, 62, 45, 237, 79, 57, 139, 199, 114, 116, 142, 11, 135, 188, 224, 21, 6},
	{34, 111, 199, 39, 107, 43, 2, 48, 144, 18, 190, 145, 197, 129, 76, 143, 145, 237, 166, 86, 212, 31, 50, 229, 68, 32, 142, 217, 216, 232, 11, 194},
	{87, 129, 149, 54, 180, 180, 165, 4, 47, 194, 115, 10, 143, 230, 68, 127, 165, 117, 82, 196, 253, 144, 175, 181, 202, 182, 229, 170, 15, 78, 185, 170},
	{25, 130, 10, 154, 153, 57, 11, 59, 71, 169, 237, 67, 46, 26, 62, 58, 1, 11, 183, 17, 154, 108, 78, 83, 81, 72, 207, 151, 241, 33, 239, 240},
	{156, 130, 53, 36, 252, 9, 172, 231, 5, 158, 136, 96, 78, 55, 136, 165, 187, 76, 255, 208, 35, 183, 136, 4, 236, 204, 222, 208, 95, 142, 56, 71},
	{240, 32, 225, 141, 33, 241, 46, 194, 139, 140, 47, 39, 35, 39, 252, 243, 129, 232, 159, 152, 245, 115, 54, 105, 56, 30, 102, 213, 229, 98, 79, 30},
	{38, 209, 177, 108, 233, 162, 117, 142, 206, 107, 167, 108, 37, 37, 68, 227, 239, 28, 39, 143, 66, 102, 1, 15, 22, 33, 251, 48, 244, 34, 108, 25},
	{50, 40, 118, 75, 237, 130, 232, 48, 101, 186, 62, 143, 4, 186, 111, 210, 180, 87, 88, 109, 234, 19, 130, 241, 181, 145, 157, 225, 50, 124, 45, 20},
	{39, 131, 100, 238, 168, 62, 250, 21, 184, 169, 182, 118, 64, 160, 164, 81, 191, 42, 2, 181, 84, 84, 143, 60, 121, 32, 103, 250, 55, 244, 122, 44},
	{164, 94, 141, 169, 68, 138, 31, 74, 216, 65, 196, 29, 113, 113, 59, 63, 243, 121, 163, 255, 234, 169, 208, 197, 17, 148, 86, 254, 122, 234, 164, 197},
	{27, 79, 67, 70, 237, 55, 48, 219, 191, 17, 57, 128, 196, 24, 184, 178, 0, 183, 70, 23, 252, 82, 17, 236, 241, 139, 255, 234, 101, 227, 235, 186},
	{207, 163, 184, 48, 219, 16, 115, 124, 157, 63, 38, 212, 125, 66, 86, 146, 22, 130, 198, 110, 75, 54, 209, 162, 172, 26, 102, 105, 185, 191, 33, 210},
}

var precannedKMACs = [][][]byte{
	{{70, 71, 236, 3, 86, 234, 80, 95, 143, 25, 253, 135, 231, 96, 138, 216, 4, 218, 104, 248, 224, 165, 133, 53, 118, 254, 185, 129, 32, 26, 196, 138}, {195, 253, 50, 212, 9, 116, 73, 20, 8, 81, 245, 172, 91, 39, 176, 114, 125, 54, 35, 213, 131, 124, 218, 150, 25, 171, 30, 72, 176, 236, 71, 182}, {130, 55, 242, 81, 125, 153, 173, 102, 170, 98, 44, 169, 114, 195, 144, 170, 5, 4, 57, 147, 89, 226, 190, 51, 254, 176, 34, 46, 72, 17, 185, 25}},
	{{171, 85, 12, 113, 114, 132, 194, 229, 7, 228, 71, 245, 201, 164, 13, 15, 74, 4, 250, 209, 159, 238, 101, 190, 77, 156, 94, 119, 97, 240, 208, 43}, {70, 177, 80, 214, 200, 103, 2, 18, 123, 183, 18, 133, 98, 48, 87, 217, 58, 129, 73, 133, 89, 96, 180, 168, 167, 163, 53, 67, 155, 136, 4, 46}, {60, 53, 203, 163, 237, 177, 194, 141, 43, 204, 36, 18, 138, 223, 48, 209, 215, 254, 57, 207, 55, 123, 42, 187, 125, 112, 41, 97, 93, 163, 60, 252}},
	{{123, 92, 185, 168, 182, 70, 65, 58, 75, 116, 219, 64, 160, 148, 193, 250, 124, 194, 32, 137, 134, 37, 0, 44, 195, 250, 244, 169, 24, 250, 182, 179}, {27, 242, 206, 234, 208, 48, 139, 74, 73, 214, 229, 91, 160, 204, 110, 39, 165, 245, 172, 60, 246, 244, 110, 216, 25, 132, 30, 204, 8, 145, 36, 145}, {236, 140, 85, 12, 142, 10, 70, 160, 158, 21, 27, 100, 77, 85, 165, 215, 128, 10, 240, 41, 118, 101, 70, 62, 38, 230, 158, 122, 45, 68, 153, 128}},
	{{238, 165, 73, 97, 187, 185, 244, 169, 103, 150, 254, 59, 19, 9, 112, 161, 242, 27, 10, 210, 118, 217, 70, 156, 5, 107, 166, 89, 208, 167, 218, 50}, {104, 237, 95, 220, 125, 103, 79, 44, 221, 242, 31, 9, 28, 72, 98, 139, 86, 178, 146, 108, 92, 101, 51, 238, 60, 114, 251, 244, 248, 0, 126, 44}, {129, 30, 211, 187, 43, 177, 233, 170, 148, 213, 40, 172, 224, 16, 169, 127, 114, 142, 227, 51, 42, 79, 84, 65, 116, 42, 220, 178, 243, 151, 201, 101}},
	{{244, 210, 73, 117, 2, 13, 202, 10, 25, 159, 5, 220, 166, 220, 210, 121, 198, 126, 109, 87, 175, 99, 9, 34, 100, 218, 103, 7, 44, 246, 174, 194}, {24, 244, 38, 122, 85, 239, 23, 135, 175, 205, 238, 81, 209, 163, 244, 104, 188, 253, 253, 137, 223, 131, 247, 192, 160, 98, 36, 147, 111, 29, 195, 25}, {69, 53, 216, 122, 35, 85, 82, 25, 121, 123, 110, 34, 241, 25, 73, 88, 53, 180, 113, 100, 191, 11, 212, 8, 141, 134, 147, 3, 222, 7, 188, 226}},
	{{52, 140, 240, 62, 15, 157, 244, 234, 154, 129, 214, 97, 66, 121, 187, 114, 210, 83, 78, 248, 171, 36, 177, 37, 185, 252, 108, 238, 28, 84, 12, 135}, {154, 193, 15, 235, 5, 210, 113, 64, 22, 106, 239, 244, 99, 59, 251, 20, 214, 174, 185, 183, 92, 43, 54, 39, 25, 35, 181, 182, 18, 73, 62, 244}, {161, 136, 117, 192, 29, 107, 253, 105, 159, 192, 101, 78, 97, 210, 34, 97, 84, 4, 237, 102, 84, 250, 220, 131, 101, 214, 92, 89, 84, 190, 41, 19}},
	{{218, 15, 88, 145, 107, 84, 85, 72, 137, 66, 32, 97, 241, 15, 104, 60, 155, 225, 109, 216, 152, 215, 226, 58, 51, 249, 205, 121, 215, 102, 93, 4}, {76, 157, 177, 32, 156, 98, 69, 229, 48, 159, 237, 248, 208, 55, 231, 22, 144, 251, 206, 49, 94, 122, 80, 152, 171, 92, 149, 194, 121, 161, 159, 171}, {52, 27, 55, 101, 38, 248, 245, 231, 249, 6, 65, 64, 54, 190, 246, 153, 146, 83, 85, 115, 11, 171, 12, 96, 248, 105, 15, 227, 151, 9, 114, 187}},
	{{17, 141, 243, 64, 83, 140, 250, 169, 227, 164, 50, 21, 47, 176, 60, 246, 33, 140, 94, 170, 139, 101, 205, 113, 12, 31, 197, 247, 252, 83, 25, 5}, {248, 75, 247, 231, 249, 9, 126, 224, 236, 9, 204, 252, 98, 30, 47, 210, 16, 142, 121, 47, 25, 69, 167, 230, 158, 238, 49, 78, 78, 93, 61, 166}, {230, 234, 235, 222, 154, 126, 204, 7, 87, 78, 253, 255, 150, 207, 17, 166, 252, 151, 151, 106, 188, 217, 122, 179, 15, 65, 204, 14, 223, 79, 179, 20}},
	{{214, 128, 101, 172, 23, 3, 153, 105, 203, 97, 36, 18, 131, 181, 234, 62, 126, 8, 241, 141, 234, 124, 254, 90, 8, 89, 76, 126, 35, 242, 83, 76}, {5, 104, 53, 232, 130, 123, 153, 73, 143, 137, 44, 227, 26, 237, 243, 125, 42, 186, 33, 247, 249, 219, 128, 211, 7, 196, 145, 169, 119, 252, 5, 142}, {164, 4, 164, 160, 178, 108, 186, 79, 122, 235, 120, 202, 15, 113, 124, 13, 24, 63, 225, 165, 94, 117, 241, 83, 78, 29, 77, 249, 201, 205, 228, 240}},
	{{157, 254, 112, 108, 191, 200, 189, 181, 131, 156, 193, 236, 101, 235, 14, 153, 127, 228, 217, 184, 129, 250, 252, 107, 45, 93, 57, 143, 198, 202, 253, 86}, {181, 169, 18, 190, 129, 190, 248, 125, 156, 233, 109, 237, 248, 145, 137, 151, 160, 16, 208, 109, 102, 14, 232, 127, 214, 172, 172, 115, 251, 223, 178, 87}, {171, 112, 217, 216, 160, 102, 222, 143, 236, 80, 58, 156, 157, 121, 161, 155, 249, 34, 239, 9, 28, 152, 107, 240, 214, 30, 53, 115, 68, 169, 200, 162}},
}

func grpTest() *cyclic.Group {
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

	p := large.NewIntFromString(primeString, 16)
	g := large.NewInt(2)
	return cyclic.NewGroup(p, g)
}
