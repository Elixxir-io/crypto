////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package message

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
)

const (
	// IDLen is the length of a MessageID.
	IDLen  = 32
	idSalt = "ChannelsMessageIdSalt"
)

// Error messages.
const (
	unmarshalDataLenErr = "received %d bytes when %d bytes required"
)

// ID is the unique identifier of a channel message.
type ID [IDLen]byte

// MakeMessageID returns the MessageID for the given serialized message.
//
// Due to the fact that messages contain the round they are sent in, they are
// replay resistant. This property, when combined with the collision resistance
// of the hash function, ensures that an adversary will not be able to cause
// multiple messages to have the same ID.
//
// The MessageID contain the channel ID as well to ensure that if a user is in
// two channels that have messages with the same text sent to them in the same
// round, the message IDs will differ.
//
// Before the message has been encrypted but after padding has been added, the
// MessageID is defined as:
//
//	H(message | chID | salt)
func MakeID(message []byte, chID *id.ID) ID {
	h, err := blake2b.New256(nil)
	if err != nil {
		jww.FATAL.Panicf("Failed to get Hash: %+v", err)
	}
	h.Write(message)
	h.Write(chID[:])
	h.Write([]byte(idSalt))
	midBytes := h.Sum(nil)

	mid := ID{}
	copy(mid[:], midBytes)
	return mid
}

// Equals checks if two message IDs are the same.
//
// Not constant time.
func (mid ID) Equals(mid2 ID) bool {
	return hmac.Equal(mid[:], mid2[:])
}

// String returns a base64 encoded MessageID for debugging. This function
// adheres to the fmt.Stringer interface.
func (mid ID) String() string {
	return "ChMsgID-" + base64.StdEncoding.EncodeToString(mid[:])
}

// Bytes returns a copy of the bytes in the message.
func (mid ID) Bytes() []byte {
	return mid.Marshal()
}

// DeepCopy returns a copy Message ID
func (mid ID) DeepCopy() ID {
	return mid
}

// Marshal marshals the MessageID into a byte slice.
func (mid ID) Marshal() []byte {
	bytesCopy := make([]byte, len(mid))
	copy(bytesCopy, mid[:])
	return bytesCopy
}

// UnmarshalMessageID unmarshalls the byte slice into a MessageID.
func UnmarshalID(data []byte) (ID, error) {
	mid := ID{}
	if len(data) != IDLen {
		return mid, errors.Errorf(
			unmarshalDataLenErr, len(data), IDLen)
	}

	copy(mid[:], data)
	return mid, nil
}

// MarshalJSON handles the JSON marshaling of the MessageID. This function
// adheres to the [json.Marshaler] interface.
func (mid ID) MarshalJSON() ([]byte, error) {
	// Note: Any changes to the output of this function can break storage in
	// higher levels. Take care not to break the consistency test.
	return json.Marshal(mid.Marshal())
}

// UnmarshalJSON handles the JSON unmarshalling of the MessageID. This function
// adheres to the [json.Unmarshaler] interface.
func (mid *ID) UnmarshalJSON(b []byte) error {
	var buff []byte
	if err := json.Unmarshal(b, &buff); err != nil {
		return err
	}

	newMID, err := UnmarshalID(buff)
	if err != nil {
		return err
	}

	*mid = newMID

	return nil
}
