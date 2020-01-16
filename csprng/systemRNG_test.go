////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package csprng

import (
	"math/rand"
	"reflect"
	"testing"
)

//Tests that the NewSystemRNG meets the source constructor and returns a valid SystemRNG in the interface
func TestNewSystemRNG(t *testing.T) {

	var sc SourceConstructor

	sc = NewSystemRNG

	csprig := sc()

	_, ok := csprig.(*SystemRNG)

	if !ok {
		t.Errorf("TestNewSystemRNG failed: did not return a SystemRNG pointer under the interface")
	}
}

//Spot check that the results of the rng vary
func TestSystemRNG_Read(t *testing.T) {
	csprig := NewSystemRNG()

	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 10; i++ {
		size := rng.Uint32()%10000 + 20
		var outputs [][]byte
		for j := 0; j < 50; j++ {
			out := make([]byte, size)
			csprig.Read(out)
			outputs = append(outputs, out)
		}

		for x := 0; x < 50; x++ {
			for y := x + 1; y < 50; y++ {
				if reflect.DeepEqual(outputs[x], outputs[y]) {
					t.Errorf("TestSystemRNG_Read failed: two randomly generated byte slices of length %v were the same", size)
				}
			}
		}
	}
}

//Spot check that the set seed function does nothing
func TestSystemRNG_SetSeed(t *testing.T) {
	csprig := NewSystemRNG()

	err := csprig.SetSeed([]byte{})

	if err != nil {
		t.Errorf("TestSystemRNG_SetSeed failed: returned unexpected error: %s", err.Error())
	}
}
