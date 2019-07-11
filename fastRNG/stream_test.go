///////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package fastRNG

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"gitlab.com/elixxir/crypto/csprng"
	"io"
	"reflect"
	"testing"
	"time"
)

type mockRNG struct {
}

func newMockRNG() csprng.Source {
	return &mockRNG{}
}
func (m *mockRNG) Read(b []byte) (int, error) {
	return 0, nil
}
func (m *mockRNG) SetSeed(seed []byte) error {
	return nil
}

//Test the creation of a new stream generator and that it is configured correctly
func TestNewStreamGenerator(t *testing.T) {
	sg := NewStreamGenerator(12, 20)
	if sg.maxStreams != 20 || sg.scalingFactor != 12 {
		t.Errorf("Failure to initialize a stream generator correctly")
	}
}

//Test the creation of new streams and that the counters are in fact working
func TestNewStream(t *testing.T) {
	sg := NewStreamGenerator(12, 3)
	sg.NewStream()
	sg.NewStream()
	sg.NewStream()
	//See if there are the appropriate amount of streams in the streams slice and the stream count
	if sg.numStreams != uint(len(sg.streams)) && sg.numStreams != 3 {
		t.Errorf("New streams bookkeeping is not working.")
	}
}

//Test that the stream generator panics when there are too many streams being made
func TestNewStream_DoesPanic(t *testing.T) {
	//The defer function will catch the panic
	defer func() {
		if r := recover(); r != nil {

		}
	}()
	//Stream count is 2, but 3 streams are being created, thus it should panic
	sg := NewStreamGenerator(12, 2)
	sg.NewStream()
	sg.NewStream()
	sg.NewStream()
	//It should panic after the 3rd newStream and get deffered. If it doesn't it has failed
	t.Errorf("FastRNG should panic when too many streams are made!")

}

//Test that it does not panic when it reaches capacity
func TestNewStream_NotPanic(t *testing.T) {
	//The defer function should not be encountered here, as we are not exceeding capactity, we are at it
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("FastRNG should not panic when there are exactly maxStream Streams")
		}
	}()
	//Stream count is 2, and 2 streams are being created, thus it should not panic
	sg := NewStreamGenerator(12, 2)
	sg.NewStream()
	sg.NewStream()
}

//Test that the getStream calls newStream correctly/appropriately
func TestGetStream_NewStream(t *testing.T) {
	sg := NewStreamGenerator(12, 3)
	sg.GetStream()
	sg.GetStream()
	sg.GetStream()

	if sg.numStreams != uint(len(sg.streams)) && sg.numStreams != 3 {
		t.Errorf("New streams bookkeeping is not working.")
	}
}

//Test that a blocked channel will grab a stream when it becomes available
func TestGetStream_GrabsWaitingStream(t *testing.T) {
	sg := NewStreamGenerator(12, 3)
	stream0 := sg.GetStream()
	sg.GetStream()
	sg.GetStream()
	//Allow the main thread to block as streams aren't available, then close it
	go func() {
		time.Sleep(500 * time.Millisecond)
		sg.Close(stream0)
	}()
	newStream := sg.GetStream()
	if !reflect.DeepEqual(newStream, stream0) {
		t.Errorf("The next stream did not grab the correct stream")
	}
}

func TestClose_WaitingChannelLength(t *testing.T) {
	sg := NewStreamGenerator(12, 3)
	stream0 := sg.GetStream()
	stream1 := sg.GetStream()
	stream2 := sg.GetStream()

	//Close all the streams created
	sg.Close(stream0)
	sg.Close(stream1)
	sg.Close(stream2)

	//Check that the waiting streams channel is the appropriate length
	if len(sg.waitingStreams) != 3 {
		t.Errorf("Waiting channel isn't the appropriate size after closing streams")
	}
}

// Checking the functionality of appending the source using the Fortuna construction
func TestRead_ReadMoreThanSource(t *testing.T) {

	//A large byte array, of which you will read size from src byte array
	requestedBytes := make([]byte, 4125)

	/*Initialize everything needed for stream*/

	//Mock random source, of arbitrarily insufficient (small) size
	testSource := make([]byte, 8, 8)
	_, err := io.ReadFull(rand.Reader, testSource)
	if err != nil {
		panic(err.Error())
	}
	//Mock block cipher
	testKey := make([]byte, 32)
	testIV := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(testKey[:aes.BlockSize])
	if err != nil {
		panic(err)
	}
	ciph := cipher.NewCTR(block, testIV)

	//Initialize streamGenerator & streams
	sg := NewStreamGenerator(20, 2)
	stream := sg.GetStream()
	stream.src = testSource
	stream.AESCtr = ciph
	stream.rng = csprng.NewSystemRNG()
	//Initialize the stream with the generator
	stream.Read(requestedBytes)
	//Make sure that the original source and the original entropyCnt are not same after read
	if bytes.Compare(stream.src, testSource) == 0 || stream.entropyCnt == 0 {
		t.Errorf("Fortuna construction did not add randomness to the source")
	}
}

// Read read a length smaller than the currently existing source
//In this case, extend source should not be called, thus the len of src should not change
func TestRead_ReadLessThanSource(t *testing.T) {
	sg := NewStreamGenerator(20, 2)
	stream := sg.GetStream()
	requestedBytes := make([]byte, 20)
	origSrcLen := 2048
	testSource := make([]byte, origSrcLen, origSrcLen)

	//Initialize everything needed in stream for a read
	_, err := io.ReadFull(rand.Reader, testSource)
	if err != nil {
		panic(err.Error())
	}
	//Mock block cipher
	testKey := make([]byte, 32)
	testIV := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(testKey[:aes.BlockSize])
	if err != nil {
		panic(err)
	}
	ciph := cipher.NewCTR(block, testIV)

	stream.src = testSource
	stream.AESCtr = ciph
	stream.rng = csprng.NewSystemRNG()

	stream.Read(requestedBytes)
	if len(stream.src) != origSrcLen || stream.entropyCnt == 0 {
		t.Errorf("Unexpected lengthening of the stream's source")
	}
}

//Test with a mock read that returns predictably every time
func TestRead_MockRNG(t *testing.T) {
	sg := NewStreamGenerator(20, 2)
	read := make([]byte, 24)
	stream := sg.GetStream()
	stream.rng = newMockRNG()
	length, err := stream.rng.Read(read)
	if length != 0 || err != nil {
		t.Errorf("Mock read failed")
	}
}

//Test that extend source actually adds to source
func TestExtendSource(t *testing.T) {
	requestedBytes := make([]byte, 4125)

	/*Initialize everything needed for stream*/
	//Mock random source, of arbitrarily insufficient (small) size
	origSrcLen := 2048
	testSource := make([]byte, origSrcLen, origSrcLen)
	_, err := io.ReadFull(rand.Reader, testSource)
	if err != nil {
		panic(err.Error())
	}

	sg := NewStreamGenerator(20, 2)
	stream := sg.GetStream()

	stream.extendSource(len(requestedBytes))

	if origSrcLen == len(stream.src) || len(stream.src) < len(requestedBytes) {
		t.Errorf("Extend source did not append to source when it should have")
	}
}

// Checking whether requiredRandomness returns zero when the entropyCount is less than the requestedLen
func TestGetEntropy_ReturnsZero(t *testing.T) {
	//Initialize a streamGenerator and stream
	sg := NewStreamGenerator(16, 2)

	stream := sg.GetStream()
	//Try to read less that the amount of entropy
	var lessThanEqualEntropy uint = 0
	requiredRandomness := stream.getEntropyNeeded(lessThanEqualEntropy)
	//Since we are reading less than entropy, reqLen-entropy<0, in which case we return 0
	//This is tested
	if requiredRandomness != 0 {
		t.Errorf("Required randomness is not being calculated correctly")
	}

}

func TestGetEntropy_ReturnsNonZero(t *testing.T) {
	//Initialize a streamGenerator and stream
	sg := NewStreamGenerator(16, 20)

	stream := sg.GetStream()
	//Try to read more that the amount of entropy
	var greaterThanEntropy uint = 1
	requiredRandomness := stream.getEntropyNeeded(greaterThanEntropy)
	if requiredRandomness == 0 {
		t.Errorf("Required randomness is not being calculated correctly")
	}
}

//Testing whether the entropy count is being set correctly
func TestStream_SetEntropyCount(t *testing.T) {
	sg := NewStreamGenerator(16, 20)

	stream := sg.GetStream()
	stream.SetEntropyCount(2)
	var testVal uint = 0 + 2*16

	if stream.entropyCnt != testVal {
		t.Errorf("Entropy count not reset correctly")
	}
}
