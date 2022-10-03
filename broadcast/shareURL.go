////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"github.com/pkg/errors"
	"github.com/sethvargo/go-diceware/diceware"
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"net/url"
	"strconv"
	"strings"
)

// The current version number of the share URL structure.
const shareUrlVersion = 0

// Names for keys in the URL.
const (
	versionKey         = "v"
	nameKey            = "0Name"
	descKey            = "1Description"
	levelKey           = "2Level"
	saltKey            = "s"
	rsaPubKeyHashKey   = "k"
	rsaPubKeyLengthKey = "l"
	rSASubPayloadsKey  = "p"
	secretKey          = "e"
	dataKey            = "d"
)

// ShareURL generates a URL that can be used to share this channel with others
// on the given host.
//
// The RNG is only used for generating passwords for Private or Secret channels.
// It can be set to nil for Public channels. No password is returned for Public
// channels.
//
// A URL comes in one of three forms based on the privacy level set when
// generating the channel. Each privacy level hides more information than the
// last with the lowest level revealing everything and the highest level
// revealing nothing. For any level above the lowest, a password is returned,
// which will be required when decoding the URL.
func (c *Channel) ShareURL(host string, csprng io.Reader) (string, string, error) {
	u, err := url.Parse(host)
	if err != nil {
		return "", "", err
	}

	// If the privacy level is Private or Secret, then generate a password
	var password string
	if c.level != Public {
		password, err = generatePhrasePassword(8, csprng)
		if err != nil {
			return "", "", err
		}
	}

	q := u.Query()
	q.Set(versionKey, strconv.Itoa(shareUrlVersion))

	// Generate URL queries based on the privacy level
	switch c.level {
	case Public:
		u.RawQuery = c.encodePublicShareURL(q).Encode()
	case Private:
		u.RawQuery = c.encodePrivateShareURL(q, password, csprng).Encode()
	case Secret:
		u.RawQuery = c.encodeSecretShareURL(q, password, csprng).Encode()
	}

	u.RawQuery = q.Encode()

	return u.String(), password, err
}

// DecodeShareURL decodes the given URL to a Channel. If the channel is Private
// or Secret, then a password is required. Otherwise, an error is returned.
func DecodeShareURL(address, password string) (*Channel, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}

	q := u.Query()

	// Check the version
	versionString := q.Get(versionKey)
	if versionString == "" {
		return nil, errors.New("no version found")
	}
	v, err := strconv.Atoi(versionString)
	if err != nil {
		return nil, errors.Errorf("failed to parse version: %+v", err)
	} else if v != shareUrlVersion {
		return nil, errors.Errorf(
			"version mismatch: require v%d, found v%d", shareUrlVersion, v)
	}

	c := &Channel{}

	// Decode the URL based on the information available (e.g., only the public
	// URL has a salt, so if the saltKey is specified, it is a public URL)
	switch {
	case q.Has(saltKey):
		err = c.decodePublicShareURL(q)
		if err != nil {
			return nil, errors.Errorf(
				"could not decode public share URL: %+v", err)
		}
	case q.Has(nameKey):
		if password == "" {
			return nil, errors.New("no password specified")
		}
		err = c.decodePrivateShareURL(q, password)
		if err != nil {
			return nil, errors.Errorf(
				"could not decode private share URL: %+v", err)
		}
	case q.Has(dataKey):
		if password == "" {
			return nil, errors.New("no password specified")
		}
		err = c.decodeSecretShareURL(q, password)
		if err != nil {
			return nil, errors.Errorf(
				"could not decode secret share URL: %+v", err)
		}
	default:
		return nil, errors.New("URL is missing required data")
	}

	// Generate the channel ID
	c.ReceptionID, err = NewChannelID(c.Name, c.Description, c.level, c.Salt,
		c.RsaPubKeyHash, HashSecret(c.Secret))
	if err != nil {
		return nil, errors.Errorf("could not create new channel ID: %+v", err)
	}

	return c, nil
}

func generatePhrasePassword(numWords int, csprng io.Reader) (string, error) {
	g, err := diceware.NewGenerator(&diceware.GeneratorInput{RandReader: csprng})
	if err != nil {
		return "", err
	}

	words, err := g.Generate(numWords)
	if err != nil {
		return "", err
	}

	return strings.Join(words, " "), nil
}

// encodePublicShareURL encodes the channel to a Public share URL.
func (c *Channel) encodePublicShareURL(q url.Values) url.Values {
	q.Set(nameKey, c.Name)
	q.Set(descKey, c.Description)
	q.Set(levelKey, c.level.Marshal())
	q.Set(saltKey, base64.StdEncoding.EncodeToString(c.Salt))
	q.Set(rsaPubKeyHashKey, base64.StdEncoding.EncodeToString(c.RsaPubKeyHash))
	q.Set(rsaPubKeyLengthKey, strconv.Itoa(c.RsaPubKeyLength))
	q.Set(rSASubPayloadsKey, strconv.Itoa(c.RSASubPayloads))
	q.Set(secretKey, base64.StdEncoding.EncodeToString(c.Secret))

	return q
}

// decodePublicShareURL decodes the values in the url.Values from a Public share
// URL to a channel.
func (c *Channel) decodePublicShareURL(q url.Values) error {
	var err error

	c.Name = q.Get(nameKey)
	c.Description = q.Get(descKey)
	c.level, err = UnmarshalPrivacyLevel(q.Get(levelKey))
	if err != nil {
		return errors.Errorf("failed to parse privacy level: %+v", err)
	}

	c.Salt, err = base64.StdEncoding.DecodeString(q.Get(saltKey))
	if err != nil {
		return errors.Errorf("failed to parse Salt: %+v", err)
	}

	c.RsaPubKeyHash, err = base64.StdEncoding.DecodeString(q.Get(rsaPubKeyHashKey))
	if err != nil {
		return errors.Errorf("failed to parse RsaPubKeyHash: %+v", err)
	}

	c.RsaPubKeyLength, err = strconv.Atoi(q.Get(rsaPubKeyLengthKey))
	if err != nil {
		return errors.Errorf("failed to parse RsaPubKeyLength: %+v", err)
	}

	c.RSASubPayloads, err = strconv.Atoi(q.Get(rSASubPayloadsKey))
	if err != nil {
		return errors.Errorf("failed to parse RSASubPayloads: %+v", err)
	}

	c.Secret, err = base64.StdEncoding.DecodeString(q.Get(secretKey))
	if err != nil {
		return errors.Errorf("failed to parse Secret: %+v", err)
	}

	return nil
}

// encodePrivateShareURL encodes the channel to a Private share URL.
func (c *Channel) encodePrivateShareURL(
	q url.Values, password string, csprng io.Reader) url.Values {
	marshalledSecrets := c.marshalPrivateShareUrlSecrets()
	encryptedSecrets := encryptShareURL(marshalledSecrets, password, csprng)

	q.Set(nameKey, c.Name)
	q.Set(descKey, c.Description)
	q.Set(dataKey, base64.StdEncoding.EncodeToString(encryptedSecrets))

	return q
}

// decodePrivateShareURL decodes the values in the url.Values from a Private
// share URL to a channel.
func (c *Channel) decodePrivateShareURL(q url.Values, password string) error {
	c.Name = q.Get(nameKey)
	c.Description = q.Get(descKey)

	encryptedData, err := base64.StdEncoding.DecodeString(q.Get(dataKey))
	if err != nil {
		return errors.Errorf("could not decode encrypted data string: %+v", err)
	}

	data, err := decryptShareURL(encryptedData, password)
	if err != nil {
		return errors.Errorf("could not decrypt encrypted data: %+v", err)
	}

	err = c.unmarshalPrivateShareUrlSecrets(data)
	if err != nil {
		return errors.Errorf("could not unmarshal data: %+v", err)
	}

	return nil
}

// encodeSecretShareURL encodes the channel to a Secret share URL.
func (c *Channel) encodeSecretShareURL(
	q url.Values, password string, csprng io.Reader) url.Values {
	marshalledSecrets := c.marshalSecretShareUrlSecrets()
	encryptedSecrets := encryptShareURL(marshalledSecrets, password, csprng)

	q.Set(versionKey, strconv.Itoa(shareUrlVersion))
	q.Set(dataKey, base64.StdEncoding.EncodeToString(encryptedSecrets))

	return q
}

// decodePrivateShareURL decodes the values in the url.Values from a Secret
// share URL to a channel.
func (c *Channel) decodeSecretShareURL(q url.Values, password string) error {
	encryptedData, err := base64.StdEncoding.DecodeString(q.Get(dataKey))
	if err != nil {
		return errors.Errorf("could not decode encrypted data string: %+v", err)
	}

	data, err := decryptShareURL(encryptedData, password)
	if err != nil {
		return errors.Errorf("could not decrypt encrypted data: %+v", err)
	}

	err = c.unmarshalSecretShareUrlSecrets(data)
	if err != nil {
		return errors.Errorf("could not unmarshal data: %+v", err)
	}

	return nil
}

// marshalPrivateShareUrlSecrets marshals the channel's level, Salt,
// RsaPubKeyHash, RsaPubKeyLength, RSASubPayloads, and Secret into a byte slice.
func (c *Channel) marshalPrivateShareUrlSecrets() []byte {
	var buff bytes.Buffer
	buff.Grow(1 + saltSize + 8 + len(c.RsaPubKeyHash) + 8 + 8 + secretSize)

	// Privacy level byte
	buff.WriteByte(byte(c.level))

	// Salt (fixed length of saltSize)
	buff.Write(c.Salt)

	// Length of RsaPubKeyHash
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(len(c.RsaPubKeyHash)))
	buff.Write(b)

	// RsaPubKeyHash
	buff.Write(c.RsaPubKeyHash)

	// RsaPubKeyLength
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(c.RsaPubKeyLength))
	buff.Write(b)

	// RSASubPayloads
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(c.RSASubPayloads))
	buff.Write(b)

	// Secret (fixed length of secretSize)
	buff.Write(c.Secret)

	return buff.Bytes()
}

// unmarshalPrivateShareUrlSecrets unmarshalls the byte slice into the channel's
// level, Salt, RsaPubKeyHash, RsaPubKeyLength, RSASubPayloads, and Secret.
func (c *Channel) unmarshalPrivateShareUrlSecrets(data []byte) error {
	buff := bytes.NewBuffer(data)

	// Privacy level
	level, err := buff.ReadByte()
	if err != nil {
		return errors.Errorf("could not read privacy level byte: %+v", err)
	}
	c.level = PrivacyLevel(level)

	// Salt
	c.Salt = make([]byte, saltSize)
	_, err = buff.Read(c.Salt)
	if err != nil {
		return errors.Errorf("could not read salt: %+v", err)
	}

	// Get length of RsaPubKeyHash
	b := make([]byte, 8)
	_, err = buff.Read(b)
	if err != nil {
		return errors.Errorf("could not read RsaPubKeyHash length: %+v", err)
	}

	// RsaPubKeyHash
	c.RsaPubKeyHash = make([]byte, binary.LittleEndian.Uint64(b))
	_, err = buff.Read(c.RsaPubKeyHash)
	if err != nil {
		return errors.Errorf("could not read RsaPubKeyHash: %+v", err)
	}

	// RsaPubKeyLength
	b = make([]byte, 8)
	_, err = buff.Read(b)
	if err != nil {
		return errors.Errorf("could not read RsaPubKeyLength: %+v", err)
	}
	c.RsaPubKeyLength = int(binary.LittleEndian.Uint64(b))

	// RSASubPayloads
	b = make([]byte, 8)
	_, err = buff.Read(b)
	if err != nil {
		return errors.Errorf("could not read RSASubPayloads: %+v", err)
	}
	c.RSASubPayloads = int(binary.LittleEndian.Uint64(b))

	// Secret
	c.Secret = make([]byte, secretSize)
	_, err = buff.Read(c.Secret)
	if err != nil {
		return errors.Errorf("could not read Secret: %+v", err)
	}

	return nil
}

// marshalSecretShareUrlSecrets marshals the channel's level, Name, Description,
// Salt, RsaPubKeyHash, RsaPubKeyLength, RSASubPayloads, and Secret into a byte
// slice.
func (c *Channel) marshalSecretShareUrlSecrets() []byte {
	var buff bytes.Buffer
	buff.Grow(1 + 8 + len(c.Name) + 8 + len(c.Description) + saltSize + 8 +
		len(c.RsaPubKeyHash) + 8 + 8 + secretSize)

	// Privacy level byte
	buff.WriteByte(byte(c.level))

	// Length of Name
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(len(c.Name)))
	buff.Write(b)

	// Name
	buff.WriteString(c.Name)

	// Length of Description
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(len(c.Description)))
	buff.Write(b)

	// Description
	buff.WriteString(c.Description)

	// Salt (fixed length of saltSize)
	buff.Write(c.Salt)

	// Length of RsaPubKeyHash
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(len(c.RsaPubKeyHash)))
	buff.Write(b)

	// RsaPubKeyHash
	buff.Write(c.RsaPubKeyHash)

	// RsaPubKeyLength
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(c.RsaPubKeyLength))
	buff.Write(b)

	// RSASubPayloads
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(c.RSASubPayloads))
	buff.Write(b)

	// Secret (fixed length of secretSize)
	buff.Write(c.Secret)

	return buff.Bytes()
}

// unmarshalPrivateShareUrlSecrets unmarshalls the byte slice into the channel's
// level, Name, Description, Salt, RsaPubKeyHash, RsaPubKeyLength,
// RSASubPayloads, and Secret.
func (c *Channel) unmarshalSecretShareUrlSecrets(data []byte) error {
	buff := bytes.NewBuffer(data)

	// Privacy level
	level, err := buff.ReadByte()
	if err != nil {
		return errors.Errorf("could not read privacy level byte: %+v", err)
	}
	c.level = PrivacyLevel(level)

	// Length of Name
	b := make([]byte, 8)
	_, err = buff.Read(b)
	if err != nil {
		return errors.Errorf("could not read Name length: %+v", err)
	}

	// Name
	name := make([]byte, binary.LittleEndian.Uint64(b))
	_, err = buff.Read(name)
	if err != nil {
		return errors.Errorf("could not read Name: %+v", err)
	}
	c.Name = string(name)

	// Length of Description
	b = make([]byte, 8)
	_, err = buff.Read(b)
	if err != nil {
		return errors.Errorf("could not read Description length: %+v", err)
	}

	// Description
	description := make([]byte, binary.LittleEndian.Uint64(b))
	_, err = buff.Read(description)
	if err != nil {
		return errors.Errorf("could not read Description: %+v", err)
	}
	c.Description = string(description)

	// Salt
	c.Salt = make([]byte, saltSize)
	_, err = buff.Read(c.Salt)
	if err != nil {
		return errors.Errorf("could not read Salt: %+v", err)
	}

	// Get length of RsaPubKeyHash
	b = make([]byte, 8)
	_, err = buff.Read(b)
	if err != nil {
		return errors.Errorf("could not read RsaPubKeyHash length: %+v", err)
	}

	// RsaPubKeyHash
	c.RsaPubKeyHash = make([]byte, binary.LittleEndian.Uint64(b))
	_, err = buff.Read(c.RsaPubKeyHash)
	if err != nil {
		return errors.Errorf("could not read RsaPubKeyHash: %+v", err)
	}

	// RsaPubKeyLength
	b = make([]byte, 8)
	_, err = buff.Read(b)
	if err != nil {
		return errors.Errorf("could not read RsaPubKeyLength: %+v", err)
	}
	c.RsaPubKeyLength = int(binary.LittleEndian.Uint64(b))

	// RSASubPayloads
	b = make([]byte, 8)
	_, err = buff.Read(b)
	if err != nil {
		return errors.Errorf("could not read RSASubPayloads: %+v", err)
	}
	c.RSASubPayloads = int(binary.LittleEndian.Uint64(b))

	// Secret
	c.Secret = make([]byte, secretSize)
	_, err = buff.Read(c.Secret)
	if err != nil {
		return errors.Errorf("could not read Secret: %+v", err)
	}

	return nil
}

// encryptShareURL encrypts the data for a shared URL using XChaCha20-Poly1305.
func encryptShareURL(data []byte, password string, csprng io.Reader) []byte {
	chaCipher := initChaCha20Poly1305(password)
	nonce := make([]byte, chaCipher.NonceSize())
	if _, err := io.ReadFull(csprng, nonce); err != nil {
		jww.FATAL.Panicf("Could not generate nonce %+v", err)
	}
	ciphertext := chaCipher.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// decryptShareURL decrypts the encrypted data from a shared URL using
// XChaCha20-Poly1305.
func decryptShareURL(data []byte, password string) ([]byte, error) {
	chaCipher := initChaCha20Poly1305(password)
	nonceLen := chaCipher.NonceSize()
	if (len(data) - nonceLen) <= 0 {
		return nil, errors.Errorf(
			"Read %d bytes, too short to decrypt", len(data))
	}
	nonce, ciphertext := data[:nonceLen], data[nonceLen:]
	plaintext, err := chaCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Errorf("Cannot decrypt with password: %+v", err)
	}
	return plaintext, nil
}

// initChaCha20Poly1305 returns a XChaCha20-Poly1305 cipher.AEAD that uses the
// given password hashed into a 256-bit key.
func initChaCha20Poly1305(password string) cipher.AEAD {
	pwHash := blake2b.Sum256([]byte(password))
	chaCipher, err := chacha20poly1305.NewX(pwHash[:])
	if err != nil {
		jww.FATAL.Panicf("Could not init XChaCha20Poly1305 mode: %+v", err)
	}

	return chaCipher
}
