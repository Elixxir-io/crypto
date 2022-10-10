////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/backup"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"strings"
)

// Error messages.
const (
	// PrivateIdentity.export
	encryptErr = "could not encrypt PrivateIdentity: %+v"

	// ImportPrivateIdentity
	noDataErr         = "len of data is 0"
	noHeadFootTagsErr = "invalid format: %+v"
	noVersionErr      = "version not found: %+v"
	noEncryptedData   = "no encrypted data found"
	wrongVersionErr   = "version must be %s or lower; received version %s"

	// decodeVer0
	base64DecodeErr    = "could not base 64 decode string: %+v"
	unmarshalParamsErr = "could not unmarshal params: %+v"
	decryptionErr      = "could not decrypt identity data: %+v"
	decodeErr          = "could not decode decrypted identity data: %+v"

	// getTagContents
	noOpenTagErr  = "missing opening tag"
	noCloseTagErr = "missing closing tag"
	swappedTagErr = "tags in wrong order"

	// decodePrivateIdentity
	unmarshalDataLenErr = "data must be %d bytes, length of data received is %d bytes"
	versionMismatchErr  = "version received %d is not compatible with current version %d"
)

// Tags indicate the start and end of data. The tags must only contain printable
// ASCII characters.
const (
	headTag     = "<xxChannelIdentity" // Indicates the start of the encoded data
	footTag     = "xxChannelIdentity>" // Indicates the end of the encoded data
	openVerTag  = "("                  // Indicates the start of the encoding version number
	closeVerTag = ")"                  // Indicates the end of the encoding version number
)

// Data lengths.
const (
	versionLen = 1
	codesetLen = 1

	// Length of the encoded output of PrivateIdentity.encode
	encodedLen = versionLen + codesetLen + ed25519.PrivateKeySize + ed25519.PublicKeySize

	// Length of the data part of the exported string returned by
	// PrivateIdentity.encode
	exportedLen = saltLen + backup.ParamsLen + encodedLen

	// keyLen is the length of the key used for encryption
	keyLen = chacha20poly1305.KeySize

	// saltLen is the length of the salt used in key generation. The recommended
	// size is 16 bytes, mentioned here:
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-04#section-3.1
	saltLen = 16
)

// The current version of the encoded format returned by PrivateIdentity.encode.
const currentEncryptedVersion = uint8(0)

// Current version of the string returned by PrivateIdentity.Export.
const currentExportedVersion = "0"

// map of exported encoding version numbers to their decoding functions.
var decodeVersions = map[string]func(password string, data []byte) (PrivateIdentity, error){
	currentExportedVersion: decodeVer0,
}

// export encrypts and marshals the PrivateIdentity into a portable string.
//  +----------------+---------------------+----------------------------------------------+--------+
//  |     Header     | Encryption Metadata |                Encrypted Data                | Footer |
//  +------+---------+----------+----------+---------+---------+-------------+------------+--------+
//  | Open |         |   Salt   |  Argon   | Version | Codeset |   ed25519   |  ed25519   | Close  |
//  | Tag  | Version |          |  params  |         | Version | Private Key | Public Key |  Tag   |
//  |      |         | 16 bytes | 9 bytes  | 1 byte  | 1 byte  |   64 bytes  |  32 bytes  |        |
//  +------+---------+----------+----------+---------+---------+-------------+------------+--------+
//  |     string     |                          base 64 encoded                           | string |
//  +----------------+--------------------------------------------------------------------+--------+
func (i PrivateIdentity) export(password string, params backup.Params,
	csprng io.Reader) (string, error) {

	// Encrypt the PrivateIdentity with the user password
	encryptedData, salt, err := i.encrypt(password, params, csprng)
	if err != nil {
		return "", errors.Errorf(encryptErr, err)
	}

	// Add encryption metadata and encrypted data to buffer
	buff := bytes.NewBuffer(nil)
	buff.Grow(exportedLen)
	buff.Write(salt)
	buff.Write(params.Marshal())
	buff.Write(encryptedData)

	// Add header tag, version number, and footer tag
	encodedData := strings.Builder{}
	encodedData.WriteString(headTag)
	encodedData.WriteString(openVerTag)
	encodedData.WriteString(currentExportedVersion)
	encodedData.WriteString(closeVerTag)
	encodedData.WriteString(base64.StdEncoding.EncodeToString(buff.Bytes()))
	encodedData.WriteString(footTag)

	return encodedData.String(), nil
}

func ImportPrivateIdentity(password string, data []byte) (PrivateIdentity, error) {
	var err error

	// Ensure the data is of sufficient length
	if len(data) == 0 {
		return PrivateIdentity{}, errors.New(noDataErr)
	}

	// Get data from between the header and footer tags
	data, err = getTagContents(data, headTag, footTag)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(noHeadFootTagsErr, err)
	}

	// Get the version number
	version, err := getTagContents(data, openVerTag, closeVerTag)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(noVersionErr, err)
	}

	// Strip version number from the data
	data = data[len(version)+len(openVerTag)+len(closeVerTag):]

	// Return an error if no encoded data is found between the tags
	if len(data) == 0 {
		return PrivateIdentity{}, errors.New(noEncryptedData)
	}

	// Unmarshal the data according to its version
	decodeFunc, exists := decodeVersions[string(version)]
	if exists {
		return decodeFunc(password, data)
	}

	return PrivateIdentity{},
		errors.Errorf(wrongVersionErr, currentExportedVersion, version)
}

// decodeVer0 decodes the PrivateIdentity encoded data. This function is for
// version "1" of the structure, defined below.
// +---------------------+----------------------------------------------+
// | Encryption Metadata |                Encrypted Data                |
// +----------+----------+---------+---------+-------------+------------+
// |   Salt   |  Argon   | Version | Codeset |   ed25519   |  ed25519   |
// |          |  params  |         | Version | Private Key | Public Key |
// | 16 bytes | 9 bytes  | 1 byte  | 1 byte  |   64 bytes  |  32 bytes  |
// +----------+----------+---------+---------+-------------+------------+
// |                          base 64 encoded                           |
// +--------------------------------------------------------------------+
func decodeVer0(password string, data []byte) (PrivateIdentity, error) {
	// Create a new buffer from a base64 decoder so that the data can be read
	// and decoded at the same time.
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data))
	var buff bytes.Buffer
	_, err := buff.ReadFrom(decoder)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(base64DecodeErr, err)
	}

	// Get salt
	salt := buff.Next(saltLen)

	// Get and unmarshal Argon2 parameters
	var params backup.Params
	err = params.Unmarshal(buff.Next(backup.ParamsLen))
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(unmarshalParamsErr, err)
	}

	// Derive decryption key and decrypt the data
	key := deriveKey(password, salt, params)
	decryptedData, err := decryptIdentity(buff.Bytes(), key)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(decryptionErr, err)
	}

	pi, err := decodePrivateIdentity(decryptedData)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(decodeErr, err)
	}

	return pi, nil
}

// encrypt generates a salt and encrypts the PrivateIdentity with the user's
// password and Argon2 parameters.
func (i PrivateIdentity) encrypt(password string, params backup.Params,
	csprng io.Reader) (encryptedData, salt []byte, err error) {
	// Generate salt used for key derivation
	salt, err = makeSalt(csprng)
	if err != nil {
		return nil, nil, err
	}

	// Derive key used to encrypt data
	key := deriveKey(password, salt, params)

	// Marshal identity data to be encrypted
	data := i.encode()

	// Encrypt the data
	encryptedData = encryptIdentity(data, key, csprng)

	return encryptedData, salt, nil
}

// encode marshals the public key, private key, and codeset along with a version
// number of this encoding. The length of the output is encodedLen.
//
// Marshalled data structure:
//  +---------+---------+---------------------+--------------------+
//  | Version | Codeset | ed25519 Private Key | ed25519 Public Key |
//  | 1 byte  | 1 byte  |      64 bytes       |      32 bytes      |
//  +---------+---------+---------------------+--------------------+
func (i PrivateIdentity) encode() []byte {
	buff := bytes.NewBuffer(nil)
	buff.Grow(encodedLen)

	buff.Write([]byte{currentEncryptedVersion})
	buff.Write([]byte{i.CodesetVersion})
	buff.Write(*i.Privkey)
	buff.Write(i.PubKey)

	return buff.Bytes()
}

// decodePrivateIdentity unmarshalls the private and public keys into a private
// identity from a marshaled version that was decrypted.
//
// Refer to [PrivateIdentity.encode] for the structure.
func decodePrivateIdentity(data []byte) (PrivateIdentity, error) {
	if len(data) != encodedLen {
		return PrivateIdentity{}, errors.Errorf(
			unmarshalDataLenErr, encodedLen, len(data))
	}
	buff := bytes.NewBuffer(data)

	version := buff.Next(versionLen)[0]
	if version != currentEncryptedVersion {
		return PrivateIdentity{}, errors.Errorf(
			versionMismatchErr, version, currentEncryptedVersion)
	}

	codesetVersion := buff.Next(codesetLen)[0]
	privKey := ed25519.PrivateKey(buff.Next(ed25519.PrivateKeySize))
	pubKey := ed25519.PublicKey(buff.Next(ed25519.PublicKeySize + codesetLen))

	pi := PrivateIdentity{
		Privkey:  &privKey,
		Identity: constructIdentity(pubKey, codesetVersion),
	}

	return pi, nil
}

// getTagContents returns the bytes between the two tags. An error is returned
// if one or more tags cannot be found or closing tag precedes the opening tag.
func getTagContents(b []byte, openTag, closeTag string) ([]byte, error) {
	// Search for opening tag
	openIndex := strings.Index(string(b), openTag)
	if openIndex < 0 {
		return nil, errors.New(noOpenTagErr)
	}

	// Search for closing tag
	closeIndex := strings.Index(string(b), closeTag)
	if closeIndex < 0 {
		return nil, errors.New(noCloseTagErr)
	}

	// Return an error if the closing tag comes first
	if openIndex > closeIndex {
		return nil, errors.New(swappedTagErr)
	}

	return b[openIndex+len(openTag) : closeIndex], nil
}
