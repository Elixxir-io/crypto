////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
	"hash"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"

	"gitlab.com/elixxir/crypto/broadcast/escape"
	"gitlab.com/elixxir/crypto/cmix"
	"gitlab.com/elixxir/crypto/rsa"
)

const (
	currentPrettyPrintVersion = 4

	hkdfInfo      = "XX_Network_Broadcast_Channel_HKDF_Blake2b"
	labelConstant = "XX_Network_Broadcast_Channel_Constant"
	saltSize      = 32 // 256 bits
	secretSize    = 32 // 256 bits

	// packetWrapperReserveSize is the approximate size of a user packet
	// wrapper, with some extra padding for safety, in bytes.
	packetWrapperReserveSize = 160 // 1280 bits

	// NameMinChars is the minimum number of UTF-8 characters allowed in a
	// channel name.
	NameMinChars = 3 // 3 characters

	// NameMaxChars is the maximum number of UTF-8 characters allowed in a
	// channel name.
	NameMaxChars = 24 // 24 characters

	// DescriptionMaxChars is the maximum number of UTF-8 characters allowed in
	// a channel description.
	DescriptionMaxChars = 144 // 144 characters
)

var channelHash = blake2b.New256

// Error messages.
var (
	// ErrSecretSizeIncorrect indicates an incorrect sized secret.
	ErrSecretSizeIncorrect = errors.New(
		"NewChannelID secret must be 32 bytes long.")

	// ErrSaltSizeIncorrect indicates an incorrect sized salt.
	ErrSaltSizeIncorrect = errors.New(
		"NewChannelID salt must be 32 bytes long.")

	// ErrMalformedPrettyPrintedChannel indicates the channel description blob
	// was malformed.
	ErrMalformedPrettyPrintedChannel = errors.New(
		"Malformed pretty printed channel.")

	// MinNameCharLenErr is returned when the name is shorter than the minimum
	// character limit.
	MinNameCharLenErr = errors.Errorf(
		"name cannot be shorter than %d characters", NameMinChars)

	// MaxNameCharLenErr is returned when the name is longer than the maximum
	// character limit.
	MaxNameCharLenErr = errors.Errorf(
		"name cannot be longer than %d characters", NameMaxChars)

	// NameInvalidCharErr is returned when the name contains disallowed
	// characters.
	NameInvalidCharErr = errors.New("name contains disallowed characters")

	// MaxDescriptionCharLenErr is returned when the description is longer than
	// the maximum character limit.
	MaxDescriptionCharLenErr = errors.Errorf(
		"description cannot be longer than %d characters", DescriptionMaxChars)

	// InvalidPrivacyLevelErr is returned when the PrivacyLevel is not one of
	// the valid chooses.
	InvalidPrivacyLevelErr = errors.New("invalid privacy Level")
)

// Channel is a multicast communication channel that retains the various privacy
// notions that this mix network provides.
type Channel struct {
	ReceptionID *id.ID
	Name        string
	Description string

	// Determines the amount of information displayed as plaintext vs encrypted
	// when sharing channel information.
	//
	// When sharing via a URL comes in one of three forms based on the privacy
	// Level set when generating the channel. Each privacy Level hides more
	// information than the last with the lowest Level revealing everything and
	// the highest Level revealing nothing. For any Level above the lowest, a
	// password is returned, which will be required when decoding the URL.
	Level PrivacyLevel

	// Time the channel is created. It is used as a hint as to when to start
	// picking up messages. Note that this is converted to Unix nano (int64) for
	// all processing and transportation.
	Created time.Time

	// Announcement indicates if the channel should only allow messages sent by
	// the admin.
	Announcement bool

	Salt            []byte
	RsaPubKeyHash   []byte
	RsaPubKeyLength int
	RSASubPayloads  int
	Secret          []byte

	// This key only appears in memory; it is not contained in the marshalled
	// version. It is lazily evaluated on first use.
	//  key = H(ReceptionID)
	key []byte
}

// NewChannel creates a new channel with a variable RSA key size calculated
// based off of recommended security parameters.
//
// The name and description can be at most [NameMaxChars] and
// [DescriptionMaxChars] long, respectively. If announcement is true, only admin
// messages will be allowed to be sent to/received on the channel.
func NewChannel(name, description string, level PrivacyLevel, announcement bool,
	packetPayloadLength int, rng csprng.Source) (*Channel, rsa.PrivateKey, error) {
	return NewChannelVariableKeyUnsafe(name, description, level, netTime.Now(),
		announcement, packetPayloadLength, rng)
}

// NewChannelVariableKeyUnsafe creates a new channel with a variable RSA key
// size calculated to optimally use space in the packer.
//
// Do not use this function unless you know what you are doing.
//
// packetPayloadLength is in bytes.
func NewChannelVariableKeyUnsafe(name, description string, level PrivacyLevel,
	created time.Time, announcement bool, packetPayloadLength int,
	rng csprng.Source) (*Channel, rsa.PrivateKey, error) {

	if err := VerifyName(name); err != nil {
		return nil, nil, err
	}
	if err := VerifyDescription(description); err != nil {
		return nil, nil, err
	}
	if !level.Verify() {
		return nil, nil, errors.WithStack(InvalidPrivacyLevelErr)
	}

	// Subtract enough room from the max payload length to accommodate a user
	// message wrapper, which will be required when replaying an admin message
	// When admin messages are replayed by any user, the entire encrypted admin
	// message must fit in a user message. So, the max size of a payload is
	// limited to always include enough room for the user message wrapper, which
	// is subtracted here.
	packetPayloadLength -= packetWrapperReserveSize

	// Get the key size and the number of fields
	keySize, numSubPayloads :=
		calculateKeySize(packetPayloadLength)

	// Multiply the key size by 8 because Scheme.Generate expects a key size in
	// bits not bytes
	pk, err := rsa.GetScheme().Generate(rng, keySize*8)
	if err != nil {
		return nil, nil, err
	}
	if pk.Size() != keySize {
		return nil, nil, errors.Errorf("Generated rsa key not "+
			"the passed in size! input: %d bits, generated: %d bits",
			keySize*8, pk.Size()*8)
	}
	salt := cmix.NewSalt(rng, saltSize)

	secret := make([]byte, secretSize)
	n, err := rng.Read(secret)
	if err != nil {
		jww.FATAL.Panicf("Failed to generate channel secret: %+v", err)
	} else if n != secretSize {
		jww.FATAL.Panicf(
			"Secret requires %d bytes, found %d bytes", secretSize, n)
	}

	pubKeyHash := HashPubKey(pk.Public())

	channelID, err := NewChannelID(name, description, level, created,
		announcement, salt, pubKeyHash, HashSecret(secret))
	if err != nil {
		return nil, nil, err
	}

	return &Channel{
		ReceptionID:     channelID,
		Name:            name,
		Description:     description,
		Level:           level,
		Created:         created.Round(0),
		Announcement:    announcement,
		Salt:            salt,
		RsaPubKeyHash:   pubKeyHash,
		RsaPubKeyLength: keySize,
		RSASubPayloads:  numSubPayloads,
		Secret:          secret,
	}, pk, nil
}

// UnmarshalChannel JSON marshals a Channel.
func UnmarshalChannel(data []byte) (*Channel, error) {
	var c Channel
	return &c, json.Unmarshal(data, &c)
}

// Marshal serialises the Channel into JSON.
func (c *Channel) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

func (c *Channel) label() []byte {
	l := append([]byte(c.Name), []byte(c.Description)...)
	return append(l, []byte(labelConstant)...)
}

// Verify checks that the channel ID is the same one generated by the channel
// primitives.
func (c *Channel) Verify() bool {
	gen, err := NewChannelID(c.Name, c.Description, c.Level, c.Created,
		c.Announcement, c.Salt, c.RsaPubKeyHash, HashSecret(c.Secret))
	if err != nil {
		jww.ERROR.Printf("Channel verify failed due to error from "+
			"channel generation: %+v", err)
		return false
	}
	return c.ReceptionID.Cmp(gen)
}

// NewChannelID creates a new channel [id.ID] with a type [id.User].
//
// The 32-byte identity is derived as described below:
//
//	intermediary = H(name | description | level | created | announcement | salt | rsaPubHash | hashedSecret)
//	identityBytes = HKDF(intermediary, salt, hkdfInfo)
func NewChannelID(name, description string, level PrivacyLevel,
	created time.Time, announcement bool, salt, rsaPubHash, secretHash []byte) (
	*id.ID, error) {
	if len(salt) != saltSize {
		return nil, ErrSaltSizeIncorrect
	}

	hkdfHash := func() hash.Hash {
		h, err := blake2b.New256(nil)
		if err != nil {
			jww.FATAL.Panic(err)
		}
		return h
	}

	intermediary := deriveIntermediary(name, description, level, created,
		announcement, salt, rsaPubHash, secretHash)
	hkdf1 := hkdf.New(hkdfHash, intermediary, salt, []byte(hkdfInfo))

	const identitySize = 32
	identityBytes := make([]byte, identitySize)
	n, err := io.ReadFull(hkdf1, identityBytes)
	if err != nil {
		jww.FATAL.Panic(err)
	}
	if n != identitySize {
		jww.FATAL.Panicf(
			"channel identity requires %d bytes, HKDF provided %d bytes",
			identitySize, n)
	}

	sid := &id.ID{}
	copy(sid[:], identityBytes)
	sid.SetType(id.User)

	return sid, nil
}

// PrivacyLevel returns the Level of privacy set for this channel.
func (c *Channel) PrivacyLevel() PrivacyLevel {
	return c.Level
}

const (
	ppHead         = "<Speakeasy-v"
	ppVerDelim     = ":"
	ppTail         = ">"
	ppDelim        = '|'
	ppDesc         = "description:"
	ppLevel        = "level:"
	ppCreated      = "created:"
	ppAnnouncement = "announcement:"
	ppSecrets      = "secrets:"

	ppNumFields = 10
)

// PrettyPrint prints a human-readable serialization of this Channel that can b
// copy and pasted.
//
// Example:
//
//	<Speakeasy-v3:Test_Channel|description:Channel description.|level:Public|created:1666718081766741100|announcement:false|secrets:+oHcqDbJPZaT3xD5NcdLY8OjOMtSQNKdKgLPmr7ugdU=|rCI0wr01dHFStjSFMvsBzFZClvDIrHLL5xbCOPaUOJ0=|493|1|7cBhJxVfQxWo+DypOISRpeWdQBhuQpAZtUbQHjBm8NQ=>
func (c *Channel) PrettyPrint() string {
	shouldEscape := func(s []rune, i int) bool { return s[i] == ppDelim }

	fields := [ppNumFields]string{
		escape.HexEscape(c.Name, shouldEscape),
		ppDesc + escape.HexEscape(c.Description, shouldEscape),
		ppLevel + c.Level.Marshal(),
		ppCreated + strconv.FormatInt(c.Created.UnixNano(), 10),
		ppAnnouncement + strconv.FormatBool(c.Announcement),
		ppSecrets + base64.StdEncoding.EncodeToString(c.Salt),
		base64.StdEncoding.EncodeToString(c.RsaPubKeyHash),
		strconv.Itoa(c.RsaPubKeyLength),
		strconv.Itoa(c.RSASubPayloads),
		base64.StdEncoding.EncodeToString(c.Secret),
	}

	return ppHead + strconv.Itoa(currentPrettyPrintVersion) + ppVerDelim +
		strings.Join(fields[:], string(ppDelim)) + ppTail
}

// NewChannelFromPrettyPrint creates a new Channel given a valid pretty printed
// Channel serialization generated using the Channel.PrettyPrint method.
func NewChannelFromPrettyPrint(p string) (*Channel, error) {
	// Strip the header and return an error if it is not present
	if !strings.HasPrefix(p, ppHead) {
		return nil, errors.New("missing header")
	}
	p = strings.TrimPrefix(p, ppHead)

	// Strip the tail and return an error if it is not present
	if !strings.HasSuffix(p, ppTail) {
		return nil, errors.New("missing tail")
	}
	p = strings.TrimSuffix(p, ppTail)

	// Split at the version separator and return error if not present
	fields := strings.SplitN(p, ppVerDelim, 2)
	if len(fields) != 2 {
		return nil, errors.New("missing version separator")
	}
	p = fields[1]

	// Parse and check that the version is correct
	versionString := fields[0]
	version, err := strconv.Atoi(versionString)
	if err != nil {
		return nil, errors.Errorf("failed to parse version: %+v", err)
	} else if version != currentPrettyPrintVersion {
		return nil, errors.Errorf("requires version %d; received version %d",
			currentPrettyPrintVersion, version)
	}

	// Split into separate fields
	fields = strings.Split(p, string(ppDelim))
	if len(fields) != ppNumFields {
		return nil, errors.Errorf(
			"expected %d fields, found %d fields", ppNumFields, len(fields))
	}

	// Privacy level
	level, err := UnmarshalPrivacyLevel(strings.TrimPrefix(fields[2], ppLevel))
	if err != nil {
		return nil, errors.Errorf("could not decode privacy level: %+v", err)
	}

	// Creation time
	createdUnixNano, err :=
		strconv.ParseInt(strings.TrimPrefix(fields[3], ppCreated), 10, 64)
	if err != nil {
		return nil, errors.Errorf("could not parse creation time int: %+v", err)
	}

	// Announcement bool
	announcement, err :=
		strconv.ParseBool(strings.TrimPrefix(fields[4], ppAnnouncement))
	if err != nil {
		return nil, errors.Errorf("could not parse announcemment bool: %+v", err)
	}

	// Salt
	salt, err := base64.StdEncoding.DecodeString(
		strings.TrimPrefix(fields[5], ppSecrets))
	if err != nil {
		return nil, errors.Errorf("could not decode salt: %+v", err)
	}

	// RSA public key hash
	rsaPubKeyHash, err := base64.StdEncoding.DecodeString(fields[6])
	if err != nil {
		return nil, errors.Errorf("could not decode RSA public key: %+v", err)
	}

	// RSA public key length
	rsaPubKeyLength, err := strconv.Atoi(fields[7])
	if err != nil {
		return nil, errors.Errorf(
			"could not decode RSA public key length: %+v", err)
	}

	// RSA sub payloads
	rsaSubPayloads, err := strconv.Atoi(fields[8])
	if err != nil {
		return nil, errors.Errorf("could not decode RSA sub payloads: %+v", err)
	}

	// Secret
	secret, err := base64.StdEncoding.DecodeString(fields[9])
	if err != nil {
		return nil, errors.Errorf("could not decode secret: %+v", err)
	}

	c := &Channel{
		Name:            escape.HexUnescape(fields[0]),
		Description:     strings.TrimPrefix(escape.HexUnescape(fields[1]), ppDesc),
		Level:           level,
		Created:         time.Unix(0, createdUnixNano),
		Announcement:    announcement,
		Salt:            salt,
		RsaPubKeyHash:   rsaPubKeyHash,
		RsaPubKeyLength: rsaPubKeyLength,
		RSASubPayloads:  rsaSubPayloads,
		Secret:          secret,
	}

	// Ensure that the name, description, and privacy Level are valid
	if err = VerifyName(c.Name); err != nil {
		return nil, err
	}
	if err := VerifyDescription(c.Description); err != nil {
		return nil, err
	}
	if !c.Level.Verify() {
		return nil, errors.WithStack(InvalidPrivacyLevelErr)
	}

	c.ReceptionID, err = NewChannelID(c.Name, c.Description, c.Level, c.Created,
		c.Announcement, c.Salt, c.RsaPubKeyHash, HashSecret(c.Secret))
	if err != nil {
		return nil, ErrMalformedPrettyPrintedChannel
	}

	return c, nil
}

// nameMatch is the regular expressions that channel names are checked against.
// It only allows letters, numbers, and underscores.
//
// Regex explains:
//
//	^       must start with any of the characters enumerated below
//	\p{L}   any kind of letter from any language
//	0-9     any digit 0 through 9
//	_       underscore
//	$       must end with any of the characters enumerated above
//	+       match any number of character enumerated above
var nameMatch = regexp.MustCompile(`[^\p{L}0-9_$]+`)

// VerifyName verifies that the name is a valid channel name.
func VerifyName(name string) error {
	nameLen := len([]rune(name))

	if nameLen < NameMinChars {
		return errors.WithStack(MinNameCharLenErr)
	} else if nameLen > NameMaxChars {
		return errors.WithStack(MaxNameCharLenErr)
	} else if nameMatch.MatchString(name) {
		return errors.WithStack(NameInvalidCharErr)
	}

	return nil
}

// VerifyDescription verifies that the description is a valid channel
// description.
func VerifyDescription(description string) error {
	if len([]rune(description)) > DescriptionMaxChars {
		return errors.WithStack(MaxDescriptionCharLenErr)
	}

	return nil
}
