////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

//go:build js && wasm

package rsa

import (
	"crypto"
	"crypto/rand"
	gorsa "crypto/rsa"
	"encoding/base64"
	"io"
	mRand "math/rand"
	"strconv"
	"testing"
)

// Smoke test: ensure that the Go implementation of PublicKey.VerifyPSS can
// verify the output for the Javascript implementation of PrivateKey.SignPSS.
func Test_SignJS_VerifyGo_PSS(t *testing.T) {
	// Generate keys
	sLocal := GetScheme()
	// rng := rand.Reader
	rng := mRand.New(mRand.NewSource(42))

	privKey, err := sLocal.GenerateDefault(rng)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	// Construct signing options
	opts := NewDefaultPSSOptions()
	opts.Hash = crypto.SHA256
	hashFunc := opts.HashFunc()
	opts.SaltLength = 32

	// for i := 0; i < numTest; i++ {
	// Create hash
	h := hashFunc.New()
	h.Write([]byte(strconv.Itoa(0) + "test12345"))
	hashed := h.Sum(nil)

	// Construct signature
	signed, err2 := privKey.SignPSS(rng, hashFunc, hashed, opts)
	if err2 != nil {
		t.Fatalf("SignPSS error: %+v", err2)
	}

	t.Logf("hashed: %X", hashed)

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rng, salt); err != nil {
		t.Fatal(err)
	}

	t.Logf("salt: %x", salt)

	gorsaSigned, err2 := gorsa.SignPSS(rng, privKey.GetGoRSA(), hashFunc, hashed, &opts.PSSOptions)
	if err2 != nil {
		t.Fatalf("gorsa SignPSS error: %+v", err2)
	}

	t.Logf("javascript:\n%X", signed)
	t.Logf("go:\n%X", gorsaSigned)

	// Verify signature
	err = gorsa.VerifyPSS(
		pubKey.GetGoRSA(), hashFunc, hashed, signed, &opts.PSSOptions)
	if err != nil {
		t.Fatalf("VerifyPSS error: %+v", err)
	}
	// }
}

// Smoke test: ensure that the Javascript implementation of PublicKey.VerifyPSS
// can verify the output for the Go implementation of PrivateKey.SignPSS.
func Test_SignGo_VerifyJS_PSS(t *testing.T) {
	// Generate keys
	sLocal := GetScheme()
	rng := rand.Reader

	privKey, err := sLocal.GenerateDefault(rng)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	// Construct signing options
	opts := NewDefaultPSSOptions()
	opts.Hash = crypto.SHA256
	hashFunc := opts.HashFunc()

	for i := 0; i < numTest; i++ {
		// Create hash
		h := hashFunc.New()
		h.Write([]byte(strconv.Itoa(i) + "test12345"))
		hashed := h.Sum(nil)

		// Construct signature
		signed, err2 := gorsa.SignPSS(
			rng, privKey.GetGoRSA(), hashFunc, hashed, &opts.PSSOptions)
		if err2 != nil {
			t.Fatalf("SignPSS error: %+v", err2)
		}

		// Verify signature
		err = pubKey.(*public).VerifyPSS(hashFunc, hashed, signed, opts)
		if err != nil {
			t.Fatalf("VerifyPSS error: %+v", err)
		}
	}
}

// Smoke test: ensure that PublicKey.VerifyPKCS1v15 can verify the output for
// PrivateKey.SignPKCS1v15.
func TestPrivate_SignVerifyPKCS1v152(t *testing.T) {
	// Generate keys
	sLocal := GetScheme()
	// rng := rand.Reader
	rng := mRand.New(mRand.NewSource(42))

	privKey, err := sLocal.UnmarshalPrivateKeyPEM([]byte(testPrivKey))
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	// Construct signature hashing functions
	hashFunc := crypto.SHA256

	// Construct hash
	h := hashFunc.New()
	h.Write([]byte("AAAAAA"))
	hashed := h.Sum(nil)

	t.Logf("hashed: %X", hashed)

	// Construct signature
	signed, err := privKey.SignPKCS1v15(rng, hashFunc, hashed)
	if err != nil {
		t.Fatalf("SignPKCS1v15 error: %+v", err)
	}

	goSigned, err := gorsa.SignPKCS1v15(rng, privKey.GetGoRSA(), hashFunc, hashed)
	if err != nil {
		t.Fatalf("SignPKCS1v15 error: %+v", err)
	}

	t.Logf("javascript b64:\n%s", base64.StdEncoding.EncodeToString(signed))
	t.Logf("go b64:\n%s", base64.StdEncoding.EncodeToString(goSigned))
	t.Logf("javascript:\n%X", signed)
	t.Logf("go:\n%X", goSigned)

	// Verify signature
	err = gorsa.VerifyPKCS1v15(pubKey.GetGoRSA(), hashFunc, hashed, signed)
	if err != nil {
		t.Fatalf("VerifyPKCS1v15 error: %+v", err)
	}
}

const testPrivKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
