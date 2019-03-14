////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package nonce

import (
	"encoding/hex"
	"testing"
	"time"
)

const (
	NormalTTL    = uint(600)
	NormalTTLStr = "10m0s"
	OtherTTL     = uint(75)
	OtherTTLStr  = "1m15s"
	ShortTTL     = uint(1)
	ShortTTLStr  = "1s"
	NumTests     = int(10000)
	TimeWindow   = 10 * time.Millisecond
)

// Test new Nonce generation
// Nonce should be of correct size and valid
func TestNewNonce(t *testing.T) {
	n := NewNonce(NormalTTL)

	val := n.Bytes()

	if len(val) != NonceLen {
		t.Errorf("TestNewNonce: Nonce size is %d bytes instead of %d", len(val), NonceLen)
	}

	if !n.IsValid() {
		t.Errorf("Nonce was just created, so it should be valid")
	}
}

// Test new Nonce repeated times and see if random values repeat
func TestNewNonceMultiple(t *testing.T) {
	tmap := make(map[string]bool)

	for i := 0; i < NumTests; i++ {
		n := NewNonce(NormalTTL)
		tmap[hex.EncodeToString(n.Bytes())] = true
	}

	if len(tmap) < NumTests {
		t.Errorf("At least two nonces out of %d have the same value", NumTests)
	}
}

// Test new Nonce generation with various TTLs
func TestNewNonceVarious(t *testing.T) {
	for i := 0; i < NumTests; i++ {
		n := NewNonce(ShortTTL + uint(i))

		val := n.Bytes()

		if len(val) != NonceLen {
			t.Errorf("TestNewNonce: Nonce size is %d bytes instead of %d", len(val), NonceLen)
		}

		if !n.IsValid() {
			t.Errorf("Nonce was just created, so it should be valid")
		}
	}
}

// Test panic if TTL is 0
func TestNewNoncePanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Nonce should panic on 0 TTL")
		}
	}()
	NewNonce(0)
}

// Test TTL correctly set
func TestNonceTTLStr(t *testing.T) {
	ttls := []uint{
		NormalTTL,
		OtherTTL,
		ShortTTL,
	}

	expected := []string{
		NormalTTLStr,
		OtherTTLStr,
		ShortTTLStr,
	}

	tests := len(ttls)
	pass := 0

	for i := 0; i < tests; i++ {
		n := NewNonce(ttls[i])

		if ttlStr := n.TTLStr(); ttlStr != expected[i] {
			t.Errorf("Nonce TTL is %s instead of %s", ttlStr, expected[i])
		} else {
			pass++
		}
	}

	println("TestNonceTTLStr()", pass, "out of", tests, "tests passed.")
}

// Test Generation Time correctly generated
func TestNonceGenTime(t *testing.T) {
	n := NewNonce(NormalTTL)
	diff := time.Now().Sub(n.GenTime)

	if diff > TimeWindow {
		t.Errorf("Nonce generation time not correct (more than 100ms discrepancy)")
	}
}

// Test Expiry Time correctly calculated
func TestNonceExpiryTime(t *testing.T) {
	n := NewNonce(NormalTTL)

	ttl := n.TTL
	genTime := n.GenTime
	expTime := n.ExpiryTime

	if calcTime := genTime.Add(ttl); !calcTime.Equal(expTime) {
		t.Errorf("Nonce expiry time %s doesn't match with generation time %s + TTL %s: %s",
			n.ExpiryTimeStr(), n.GenTimeStr(), n.TTLStr(), calcTime.Format(time.RFC3339))
	}
}

// Test Nonce expiration
func TestNonceExpiration(t *testing.T) {
	n := NewNonce(ShortTTL)

	wait := time.After(time.Duration(ShortTTL)*time.Second + TimeWindow)
	select {
	case <-wait:
	}

	if n.IsValid() {
		t.Errorf("Nonce should be expired")
	}
}