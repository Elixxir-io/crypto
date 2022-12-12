////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package message

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/xx_network/primitives/id"
)

// Verify ID adheres to the stringer interface
var _ fmt.Stringer = ID{}

// Verifies that MakeID does not obviously duplicate returned ID
// objects with different inputs.
func TestMakeID_Unique(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	inputs := make([][]byte, numTests)
	prng := rand.New(rand.NewSource(42))
	chID := &id.ID{}

	// Generate results
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		inputs[i] = contents
		results[i] = MakeID(contents, chID)
	}

	// Check the results are different
	for i := 0; i < numTests; i++ {
		for j := 0; j < numTests; j++ {
			if i != j {
				require.NotEqual(t, results[i], results[j])
			}
		}
	}
}

// Verifies that MakeID does not obviously duplicate returned ID
// objects with the same inputs but different channel IDs.
func TestMakeID_Channels_Unique(t *testing.T) {
	const numTests = 100
	prng := rand.New(rand.NewSource(42))

	chID1, chID2 := &id.ID{}, &id.ID{}
	chID2[0] = 1

	// Generate results
	for i := 0; i < numTests; i++ {
		contents := make([]byte, 1000)
		prng.Read(contents)

		a := MakeID(contents, chID1)
		b := MakeID(contents, chID2)
		require.NotEqual(t, a, b)
	}
}

// Ensures that the output of MakeID is consistent does not change.
func TestMakeID_Constancy(t *testing.T) {
	prng := rand.New(rand.NewSource(69))
	expectedResults := []string{
		"ChMsgID-936YPj78YUr6bJ9LrGILBeCBFCwB3aIwxX0UL3mMjtE=",
		"ChMsgID-m+7QPDIGaDR2TFeksDH2JlikZAeU+E/f0amzCVlTYrY=",
		"ChMsgID-ob/cikchYn1MBymZv8O0kv3Y5cxA3h4u2sCnlkSVaWM=",
		"ChMsgID-ATMGXTjZL/GjY8HhS3hAUzAGudluCVA/062dhQsNvBw=",
		"ChMsgID-spm/UbyfvrkmLiwZWB7DkyY30gXDWnwZM/90t0UsfFg=",
	}
	results := make([]ID, len(expectedResults))

	// Generate results
	chID := &id.ID{}
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = MakeID(contents, chID)
	}

	// Check the results are different
	for i, expected := range expectedResults {
		require.Equal(t, results[i].String(), expected)
	}
}

// Tests that ID.Equals accurately determines two of the same ID
// objects are the same and that different IDs are different.
func TestID_Equals(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	prng := rand.New(rand.NewSource(42))
	chID := &id.ID{}

	// Generate results
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = MakeID(contents, chID)
	}

	// Check that equals is equal when it shouldn't be, and is equal when it
	// should be
	for i := 0; i < numTests; i++ {
		for j := 0; j < numTests; j++ {
			if i != j {
				require.NotEqual(t, results[i], results[j])
			} else {
				require.Equal(t, results[i], results[j])
			}
		}
	}
}

// Tests that byte slice returned by ID.Bytes contains the same data that
// is in the ID and that the result is a copy.
func TestID_Bytes(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	prng := rand.New(rand.NewSource(9001))
	chID := &id.ID{}

	// Generate message IDs
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = MakeID(contents, chID)
	}

	// Check the bytes are the same and that modifying the copy
	// does not reflect on the original
	for i := range results {
		b := results[i].Bytes()

		require.Equal(t, results[i][:], b)

		// Fill the bytes with random data
		prng.Read(b)

		require.NotEqual(t, results[i], b)
	}
}

// Tests that ID returned by ID.DeepCopy is a copy.
func TestID_DeepCopy(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	prng := rand.New(rand.NewSource(1337))
	chID := &id.ID{}

	// Generate message IDs
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = MakeID(contents, chID)
	}

	// Check the objects are the same and that modifying the copy does not
	// reflect on the original
	for i := range results {
		dc := results[i].DeepCopy()

		// Check that the deep copy and messageID are the same
		require.Equal(t, results[i], dc)

		// Fill the bytes with random data
		prng.Read(dc[:])

		// Check that the bytes and the message ID are different
		require.NotEqual(t, results[i], dc)
	}
}

// Tests that a ID marshalled via ID.Marshal and unmarshalled with
// UnmarshalID matches the original.
func TestID_Marshal_UnmarshalID(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	prng := rand.New(rand.NewSource(1337))
	chID := &id.ID{}

	// Generate message IDs
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = MakeID(contents, chID)
	}

	for _, result := range results {
		data := result.Marshal()
		mid, err := UnmarshalID(data)
		require.NoError(t, err)

		require.Equal(t, result, mid)
	}
}

// Error path: Tests that UnmarshalID returns an error for data that is
// not of the correct length
func TestUnmarshalID(t *testing.T) {
	data := make([]byte, IDLen+1)
	expectedErr := fmt.Sprintf(
		unmarshalDataLenErr, len(data), IDLen)

	_, err := UnmarshalID(data)
	require.Error(t, err)
	require.Equal(t, err.Error(), expectedErr)
}

// Tests that a ID JSON marshalled and unmarshalled matches the original.
func TestID_MarshalJSON_UnmarshalJSON(t *testing.T) {
	prng := rand.New(rand.NewSource(1337))
	chID, _ := id.NewRandomID(prng, id.User)
	contents := make([]byte, 1000)
	prng.Read(contents)
	mid := MakeID(contents, chID)

	data, err := json.Marshal(mid)
	if err != nil {
		t.Fatalf("Failed to JSON marshal ID: %+v", err)
	}

	var newMID ID
	err = json.Unmarshal(data, &newMID)
	if err != nil {
		t.Fatalf("Failed to JSON unmarshal ID: %+v", err)
	}

	if mid != newMID {
		t.Errorf("JSON marshaled and unamrshalled ID does not match "+
			"expected.\nexpected: %s\nreceived: %s", mid, newMID)
	}
}

// Tests that the output of json.Marshal on the ID is consistent. This
// test is important because the ID is saved to storage using the JSON
// marshaler and any changes to this format will break storage.
func TestID_MarshalJSON_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(1337))
	expectedData := []string{
		`"JK2k7J12VtoLtHRwLwPoXKbsuDXt+b2oyWCYJyk/xFc="`,
		`"STtKvxCEDy/UCfwIyq9v23B3X8eV1KqSB1CoAtitdk8="`,
		`"uFts/Ug2D/A1A5WDifVuX7e5UZCelEo7rpLBLmhc/sI="`,
		`"KZbCLx+aFVghkYymeU4/f18db8TDKRjcCoRW79WmEzY="`,
		`"WEEwQ7d8b+UpcvymJliO7O4L5seD5FozTbWZIQQAcrY="`,
		`"QEF6vG9W+/gerI3ThHtPtn4KKYCW69ebBfKLnyj6yqI="`,
		`"fLBJTa6VkGxzHslAwpPIvr33enRNKmNAGLsGYjfocRk="`,
		`"n2RCe4m55XkwPiV2tig6gA28cLUDQK9dwDrELlePTxI="`,
		`"YmUVG3T41F70bhrNlx+8J6CYt51iKf2qJmKHsmIpBPY="`,
		`"Qt1hNDqE8g4gEOa0OCk2BSEPBoY34WhT7B1+UyGh2Zg="`,
	}

	for _, expected := range expectedData {
		chID, _ := id.NewRandomID(prng, id.User)
		contents := make([]byte, 1000)
		prng.Read(contents)
		mid := MakeID(contents, chID)

		data, err := json.Marshal(mid)
		require.NoError(t, err)

		require.Equal(t, expected, string(data))
	}
}
