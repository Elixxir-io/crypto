////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"crypto/rand"
	"io"
)

type Random struct {
	min    *Int
	max    *Int
	fmax   *Int
	one    *Int
	reader io.Reader
}

// The random range is inclusive of both the minimum and maximum boundaries of
// the random range
func (r *Random) recalculateRange() {
	r.fmax.Sub(r.max, r.min)
	r.fmax.Add(r.fmax, r.one)
}

// SetMin sets Minimum value for the lower boundary of the random range
func (r *Random) SetMin(newMin *Int) {
	r.min.Set(newMin)
	r.recalculateRange()
}

// SetMinFromInt64 sets Min value for the lower boundary of the random range (int 64 version)
func (r *Random) SetMinFromInt64(newMin int64) {
	r.min.SetInt64(newMin)
	r.recalculateRange()
}

// SetMax sets Max value for the upper boundary of the random range
func (r *Random) SetMax(newMax *Int) {
	r.max.Set(newMax)
	r.recalculateRange()
}

// SetMaxFromInt64 sets Max val for the upper boundary of the random range (int 64 version)
func (r *Random) SetMaxFromInt64(newMax int64) {
	r.max.SetInt64(newMax)
	r.recalculateRange()
}

// NewRandom initializes a new Random with min and max values
func NewRandom(min, max *Int) Random {
	fmax := NewInt(0)
	gen := Random{min, max, fmax.Sub(max, min), NewInt(1), rand.Reader}
	return gen
}

// Rand generates a random Int x, min <= x < max
func (gen *Random) Rand(x *Int) *Int {
	ran, err := rand.Int(gen.reader, gen.fmax.value)
	if err != nil {
		panic(err.Error())
	}
	x.value = ran
	x = x.Add(x, gen.min)
	return x
}
