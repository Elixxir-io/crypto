package channel

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"gitlab.com/xx_network/crypto/signature/rsa"
)

var (
	tsBound        = 60 * time.Second
	timestampError = errors.New(
		"error timestamp is not within 60 seconds of current time")
)

// hashRequestInfo is a helper which handles hashing info for channel requests
func hashRequestInfo(userEdPub ed25519.PublicKey, ts time.Time) []byte {
	tsBytes := make([]byte, binary.MaxVarintLen64)
	binary.PutVarint(tsBytes, ts.UnixNano())
	h := crypto.BLAKE2b_256.New()
	h.Write(userEdPub)
	h.Write(tsBytes)
	return h.Sum(nil)
}

// SignChannelIdentityRequest accepts a User's ED public key & a timestamp and
// signs them using the given private key. It is used by clients to sign their
// ED public key for verification when requesting a channel identity from User
// Discovery.
func SignChannelIdentityRequest(userEdPub ed25519.PublicKey,
	ts time.Time, userRsaPriv *rsa.PrivateKey, rng io.Reader) ([]byte, error) {
	hashed := hashRequestInfo(userEdPub, ts)
	return rsa.Sign(rng, userRsaPriv, crypto.BLAKE2b_256, hashed,
		rsa.NewDefaultOptions())
}

// VerifyChannelIdentityRequest verifies a user's request generated by
// SignChannelIdentityRequest, accepting the same information and a
// corresponding public key.  It is used by User Discovery to verify the
// authenticity of channel identity requests from users.  It also ensures that
// the received timestamp is fresh based on passed in current timestamp.
func VerifyChannelIdentityRequest(sig []byte,
	userEdPub ed25519.PublicKey, now, ts time.Time,
	userRsaPub *rsa.PublicKey) error {
	// Check that the message is recently signed, ensuring freshness
	if ts.After(now.Add(tsBound)) || ts.Before(now.Add(-1*tsBound)) {
		return timestampError
	}
	hashed := hashRequestInfo(userEdPub, ts)
	return rsa.Verify(userRsaPub, crypto.BLAKE2b_256, hashed, sig,
		rsa.NewDefaultOptions())
}
