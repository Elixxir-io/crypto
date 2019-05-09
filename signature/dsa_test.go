////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package signature

import (
	"bytes"
	cryptoRand "crypto/rand"
	"errors"
	"gitlab.com/elixxir/crypto/large"
	"math/big"
	"math/rand"
	"reflect"
	"testing"
)

// Test CustomDSA Param generation accessors
// to ensure P, Q, G values are stored correctly internally
func TestCustomDSAParams_Accessors(t *testing.T) {

	var pExpected, qExpected, gExpected int64 = 1, 1, 1

	p := large.NewInt(pExpected)
	q := large.NewInt(qExpected)
	g := large.NewInt(gExpected)

	dsaParams := CustomDSAParams(p, q, g)

	pActual := dsaParams.params.P.Int64()
	qActual := dsaParams.params.Q.Int64()
	gActual := dsaParams.params.G.Int64()

	if pActual != pExpected {
		t.Errorf("p value doesn't match")
	}
	if qActual != qExpected {
		t.Errorf("q value doesn't match")
	}
	if gActual != gExpected {
		t.Errorf("g value doesn't match")
	}

	pExpected, qExpected, gExpected = 1, 2, 3

	p = large.NewInt(pExpected)
	q = large.NewInt(qExpected)
	g = large.NewInt(gExpected)

	dsaParams = CustomDSAParams(p, q, g)

	pActual = dsaParams.params.P.Int64()
	qActual = dsaParams.params.Q.Int64()
	gActual = dsaParams.params.G.Int64()

	if pActual != pExpected {
		t.Errorf("p value doesn't match")
	}
	if qActual != qExpected {
		t.Errorf("q value doesn't match")
	}
	if gActual != gExpected {
		t.Errorf("g value doesn't match")
	}

	pExpected, qExpected, gExpected = 123, 456, 789

	p = large.NewInt(pExpected)
	q = large.NewInt(qExpected)
	g = large.NewInt(gExpected)

	dsaParams = CustomDSAParams(p, q, g)

	pActual = dsaParams.params.P.Int64()
	qActual = dsaParams.params.Q.Int64()
	gActual = dsaParams.params.G.Int64()

	if pActual != pExpected {
		t.Errorf("p value doesn't match")
	}
	if qActual != qExpected {
		t.Errorf("q value doesn't match")
	}
	if gActual != gExpected {
		t.Errorf("g value doesn't match")
	}

}

type AlwaysErrorReader struct{}

func (r *AlwaysErrorReader) Read(b []byte) (int, error) {
	return 1, errors.New("external system error")
}

// Test NewDSAParams to ensure a panic occurs on external rng failure
func TestNewDSAParamsPanic(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NewDSAParams should panic on reader error!")
		}
	}()

	r := AlwaysErrorReader{}
	NewDSAParams(&r, L1024N160)

}

// Test PrivateKeyGen from params generates a valid private key
func TestPrivateKeyGen_Valid(t *testing.T) {

	source := rand.NewSource(42)
	rng := rand.New(source)

	p := fromHex("A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF")
	q := fromHex("E1D3391245933D68A0714ED34BBCB7A1F422B9C1")
	g := fromHex("634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA")

	params := CustomDSAParams(p, q, g)

	privateKey := params.PrivateKeyGen(rng)

	k := privateKey.GetKey().TextVerbose(10, 16)

	if k != "4769794528446378..." {
		t.Errorf("Invalid private key generated")
	}

}

func TestPrivateKey_HasValidParams(t *testing.T) {
	source := rand.NewSource(42)
	rng := rand.New(source)

	sizes := L1024N160

	params := NewDSAParams(rng, sizes)
	pExp := params.GetP().TextVerbose(16, 0)
	qExp := params.GetQ().TextVerbose(16, 0)
	gExp := params.GetG().TextVerbose(16, 0)

	privateKey := params.PrivateKeyGen(rng)

	pActual := privateKey.key.Parameters.P.Text(16)
	qActual := privateKey.key.Parameters.Q.Text(16)
	gActual := privateKey.key.Parameters.G.Text(16)

	if pExp != pActual {
		t.Errorf("P value doesn't match in accessor\n\treceived: %v\n\texpected: %v", pActual, pExp)
	}
	if qExp != qActual {
		t.Errorf("Q value doesn't match in accessor\n\treceived: %v\n\texpected: %v", qActual, qExp)
	}
	if gExp != gActual {
		t.Errorf("G value doesn't match in accessor\n\treceived: %v\n\texpected: %v", gActual, gExp)
	}
}

// Test PrivateKeyGen panics on external rng failure
func TestPrivateKeyGen_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("AlwaysErrorReader should panic on reader error!")
		}
	}()

	r := AlwaysErrorReader{}
	params := DSAParameters{}

	params.PrivateKeyGen(&r)
}

// Test that DSAParams has valid values for accessors
func TestDSAParams_Accessors(t *testing.T) {

	r := rand.New(rand.NewSource(0))

	params := NewDSAParams(r, L1024N160)

	// Verify

	p := params.GetP()
	q := params.GetQ()
	g := params.GetG()

	pActual := p.TextVerbose(16, 40)
	if pActual != "d99d2415ea76c2d9853e10285f47c26e644cb3e3..." {
		t.Errorf("Invalid p")
	}

	qActual := q.TextVerbose(16, 40)
	if qActual != "9a67144642e88f4b76cdabfa7a9c828765081f9d" {
		t.Errorf("Invalid q")
	}

	gActual := g.TextVerbose(16, 40)
	if gActual != "82b9856ebad01214503a5bfe28c5cda17e455c21..." {
		t.Errorf("Invalid g")
	}

}

func TestDSAPublicKeyGetters(t *testing.T) {
	r := rand.New(rand.NewSource(0))

	params := NewDSAParams(r, L1024N160)

	key := large.NewInt(500)

	pubKey := ReconstructPublicKey(params, key)

	actualParams := pubKey.GetParams()

	p := actualParams.GetP()
	q := actualParams.GetQ()
	g := actualParams.GetG()

	y := pubKey.GetKey()

	pActual := p.TextVerbose(16, 40)
	if pActual != "d99d2415ea76c2d9853e10285f47c26e644cb3e3..." {
		t.Errorf("Invalid p")
	}

	qActual := q.TextVerbose(16, 40)
	if qActual != "9a67144642e88f4b76cdabfa7a9c828765081f9d" {
		t.Errorf("Invalid q")
	}

	gActual := g.TextVerbose(16, 40)
	if gActual != "82b9856ebad01214503a5bfe28c5cda17e455c21..." {
		t.Errorf("Invalid g")
	}

	yActual := y.TextVerbose(16, 40)
	if yActual != "1f4" {
		t.Errorf("Invalid y")
	}

}

// Generate a public key from a private key and make sure
// it is consistent when getting from privKey and pubKey obj
/*
func TestPublicKeyGen_Consistent(t *testing.T) {

	expectedPubKey := "3316816248309085..."
	source := rand.NewSource(42)
	rand := rand.New(source)

	p := fromHex("A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF")
	q := fromHex("E1D3391245933D68A0714ED34BBCB7A1F422B9C1")
	g := fromHex("634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA")

	params := CustomDSAParams(p, q, g)

	privateKey := params.PrivateKeyGen(rand)

	pubKey := privateKey.PublicKeyGen()

	pubKeyFromPrivateKey := privateKey.PublicKeyGen().GetKey().Bytes()
	pubKeyYValue := pubKey.GetKey().TextVerbose(10, 16)

	if pubKeyFromPrivateKey != expectedPubKey {
		t.Errorf("Public key accessed from private key is not correct")
	}

	if pubKeyYValue != expectedPubKey {
		t.Errorf("Public key accessed from pubKey objcet is not correct")
	}

}*/

// Test helper which converts a hex string into a large int
func fromHex(s string) *large.Int {
	result, ok := new(big.Int).SetString(s, 16)

	if !ok {
		panic(s)
	}

	return large.NewIntFromBigInt(result)
}

// Sign and verify that has param, pub & priv key values ported from go sdk dsa impl. tests.
// It creates a pub key structre and then a priv key from params and passes it to sign and verify helper
func TestSignAndVerify(t *testing.T) {

	p := fromHex("A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF")
	q := fromHex("E1D3391245933D68A0714ED34BBCB7A1F422B9C1")
	g := fromHex("634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA")

	y := fromHex("32969E5780CFE1C849A1C276D7AEB4F38A23B591739AA2FE197349AEEBD31366AEE5EB7E6C6DDB7C57D02432B30DB5AA66D9884299FAA72568944E4EEDC92EA3FBC6F39F53412FBCC563208F7C15B737AC8910DBC2D9C9B8C001E72FDC40EB694AB1F06A5A2DBD18D9E36C66F31F566742F11EC0A52E9F7B89355C02FB5D32D2")
	x := fromHex("5078D4D29795CBE76D3AACFE48C9AF0BCDBEE91A")

	params := CustomDSAParams(p, q, g)

	pubKey := ReconstructPublicKey(params, y)

	privKey := ReconstructPrivateKey(pubKey, x)

	testSignAndVerify(t, 0, privKey)

}

// Helper which verifies a hash is signed correctly by a priv key
func testSignAndVerify(t *testing.T, i int, priv *DSAPrivateKey) {

	hashed := []byte("testing")

	signature, err := priv.Sign(hashed, cryptoRand.Reader)

	if err != nil {
		t.Errorf("%d: error signing: %s", i, err)
		return
	}

	publicKey := priv.PublicKeyGen()

	if !publicKey.Verify(hashed, *signature) {

		t.Errorf("%d: Verify failed", i)
	}

}

// Test ported from SDK dsa impl. to ensure we don't hit an inf. loop
func TestSigningWithDegenerateKeys(t *testing.T) {
	// Signing with degenerate private keys should not cause an infinite
	// loop.
	badKeys := []struct {
		p, q, g, y, x string
	}{
		{"00", "01", "00", "00", "00"},
		{"01", "ff", "00", "00", "00"},
	}

	for i, test := range badKeys {

		p := fromHex(test.p)
		q := fromHex(test.q)
		g := fromHex(test.g)

		y := fromHex(test.y)
		x := fromHex(test.x)

		params := CustomDSAParams(p, q, g)

		pubKey := ReconstructPublicKey(params, y)

		privKey := ReconstructPrivateKey(pubKey, x)

		hashed := []byte("testing")

		_, err := privKey.Sign(hashed, cryptoRand.Reader)

		if err == nil {
			t.Errorf("#%d: unexpected success", i)
		}

	}
}

// Ported from SDK to test different parameter sizes for param generation
func TestParameterGeneration(t *testing.T) {
	testParameterGeneration(t, L1024N160, 1024, 160)
	testParameterGeneration(t, L2048N224, 2048, 224)
	testParameterGeneration(t, L2048N256, 2048, 256)
	testParameterGeneration(t, L3072N256, 3072, 256)
}

func testParameterGeneration(t *testing.T, sizes ParameterSizes, L, N int) {

	r := rand.New(rand.NewSource(0))

	params := NewDSAParams(r, sizes)

	if params.GetP().BitLen() != L {
		t.Errorf("%d: params.BitLen got:%d want:%d", int(sizes), params.GetP().BitLen(), L)
	}

	if params.GetQ().BitLen() != N {
		t.Errorf("%d: q.BitLen got:%d want:%d", int(sizes), params.GetQ().BitLen(), L)
	}

	one := new(big.Int)
	one.SetInt64(1)
	pm1 := new(big.Int).Sub(params.GetP().BigInt(), one)
	quo, rem := new(big.Int).DivMod(pm1, params.GetQ().BigInt(), new(big.Int))
	if rem.Sign() != 0 {
		t.Errorf("%d: p-1 mod q != 0", int(sizes))
	}
	x := new(big.Int).Exp(params.GetG().BigInt(), quo, params.GetP().BigInt())
	if x.Cmp(one) == 0 {
		t.Errorf("%d: invalid generator", int(sizes))
	}

	privKey := params.PrivateKeyGen(cryptoRand.Reader)

	testSignAndVerify(t, int(sizes), privKey)
}

// Tests that a DSAParameters structure that is encoded and then decoded, as a
// glob, is the same as the initial values.
func TestDSAParameters_GobEncode_GobDecode(t *testing.T) {
	param1 := GetDefaultDSAParams()

	b, _ := param1.GobEncode()

	param2 := &DSAParameters{}
	_ = param2.GobDecode(b)

	if !reflect.DeepEqual(*param1, *param2) {
		t.Errorf("GobDecode() did not produce the the same original undecoded data\n\treceived: %v\n\texpected: %v", *param1, *param2)
	}
}

// Tests that a GobDecode() for DSAParameters structure throws an error for a
// malformed byte array.
func TestDSAParameters_GobDecode(t *testing.T) {
	param2 := &DSAParameters{}
	err := param2.GobDecode([]byte{})

	if !reflect.DeepEqual(err, errors.New("EOF")) {
		t.Errorf("GobDecode() did not produce the expected error\n\treceived: %v\n\texpected: %v", err, errors.New("EOF"))
	}
}

// Tests that a DSAPrivateKey structure that is encoded and then decoded, as a
// glob, is the same as the initial values.
func TestDSAPrivateKey_GobEncode_GobDecode(t *testing.T) {
	source := rand.NewSource(42)
	param1 := GetDefaultDSAParams().PrivateKeyGen(rand.New(source))

	b, _ := param1.GobEncode()

	param2 := &DSAPrivateKey{}
	_ = param2.GobDecode(b)

	if !reflect.DeepEqual(*param1, *param2) {
		t.Errorf("GobDecode() did not produce the the same original undecoded data\n\treceived: %v\n\texpected: %v", *param1, *param2)
	}
}

// Tests that a GobDecode() for DSAPrivateKey structure throws an error for a
// malformed byte array.
func TestDSAPrivateKey_GobDecode(t *testing.T) {
	param2 := &DSAPrivateKey{}
	err := param2.GobDecode([]byte{})

	if !reflect.DeepEqual(err, errors.New("EOF")) {
		t.Errorf("GobDecode() did not produce the expected error\n\treceived: %v\n\texpected: %v", err, errors.New("EOF"))
	}
}

// Tests that a DSAPublicKey structure that is encoded and then decoded, as a
// glob, is the same as the initial values.
func TestDSAPublicKey_GobEncode_GobDecode(t *testing.T) {
	source := rand.NewSource(42)
	param1 := GetDefaultDSAParams().PrivateKeyGen(rand.New(source)).PublicKeyGen()

	b, _ := param1.GobEncode()

	param2 := &DSAPublicKey{}
	_ = param2.GobDecode(b)

	if !reflect.DeepEqual(*param1, *param2) {
		t.Errorf("GobDecode() did not produce the the same original undecoded data\n\treceived: %v\n\texpected: %v", *param1, *param2)
	}
}

// Tests that a GobDecode() for DSAPublicKey structure throws an error for a
// malformed byte array.
func TestDSAPublicKey_GobDecode(t *testing.T) {
	param2 := &DSAPublicKey{}
	err := param2.GobDecode([]byte{})

	if !reflect.DeepEqual(err, errors.New("EOF")) {
		t.Errorf("GobDecode() did not produce the expected error\n\treceived: %v\n\texpected: %v", err, errors.New("EOF"))
	}
}

// Tests that JsonEncode() produces a correct JSON encoding of a DSAPublicKey by
// encoding it and then decoding and checking for the same initial values.
func TestDSAPublicKey_JsonEncode(t *testing.T) {
	src := rand.NewSource(42)
	pubKey := GetDefaultDSAParams().PrivateKeyGen(rand.New(src)).PublicKeyGen()
	test := GetDefaultDSAParams().PrivateKeyGen(rand.New(src)).PublicKeyGen()

	encodedKey, _ := pubKey.MarshalJSON()
	decodedKey, _ := test.UnmarshalJSON(encodedKey)

	if !reflect.DeepEqual(pubKey, decodedKey) {
		t.Errorf("JsonEncode() and JsonDecode() did not encode and decode correctly\n\treceived: %v\n\texpected: %v", decodedKey, pubKey)
	}
}

// Tests that a DSAPublicKey can be encoded in the PEM format using PemEncode()
// and then decoded using PemDecode()
func TestPemEncodeDecode(t *testing.T) {
	src := rand.NewSource(42)
	pubKey := GetDefaultDSAParams().PrivateKeyGen(rand.New(src)).PublicKeyGen()
	test := GetDefaultDSAParams().PrivateKeyGen(rand.New(src)).PublicKeyGen()

	encodedKey, _ := pubKey.PemEncode()
	decodedKey, _ := test.PemDecode(encodedKey)

	if !reflect.DeepEqual(pubKey, decodedKey) {
		t.Errorf("PemEncode() and PemDecode() did not encode and decode "+
			"correctly\n\treceived: %v\n\texpected: %v", decodedKey, pubKey)
	}
}

// Tests that a PemDecode() produces an error when the block data is incorrect.
func TestPemDecode_WrongPemData(t *testing.T) {
	src := rand.NewSource(42)
	pubKey := GetDefaultDSAParams().PrivateKeyGen(rand.New(src)).PublicKeyGen()
	test := GetDefaultDSAParams().PrivateKeyGen(rand.New(src)).PublicKeyGen()

	encodedKey, _ := pubKey.PemEncode()
	modifiedKey := bytes.ReplaceAll(encodedKey, []byte("--"), []byte{})
	_, err := test.PemDecode(modifiedKey)

	if !reflect.DeepEqual(err, ErrPemData) {
		t.Errorf("PemDecode() did not correctly error on incorrect "+
			"block data\n\treceived: %#v\n\texpected: %#v", err, ErrPemData)
	}
}

// Tests that a PemDecode() produces an error when the block type is incorrect.
func TestPemDecode_WrongType(t *testing.T) {
	src := rand.NewSource(42)
	pubKey := GetDefaultDSAParams().PrivateKeyGen(rand.New(src)).PublicKeyGen()
	test := GetDefaultDSAParams().PrivateKeyGen(rand.New(src)).PublicKeyGen()

	encodedKey, _ := pubKey.PemEncode()
	modifiedKey := bytes.ReplaceAll(encodedKey, []byte("PUBLIC KEY"), []byte("PRIVATE KEY"))
	_, err := test.PemDecode(modifiedKey)

	if !reflect.DeepEqual(err, ErrPemType) {
		t.Errorf("PemDecode() did not correctly error on incorrect "+
			"block type\n\treceived: %#v\n\texpected: %#v", err, ErrPemType)
	}
}
