package broadcast

import (
	"bytes"
	"gitlab.com/elixxir/crypto/cmix"
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/xx_network/crypto/csprng"
	"testing"
)

func TestRSAToPublic_Encrypt_Decrypt_BigKey(t *testing.T) {
	rng := csprng.NewSystemRNG()

	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keysize, n := calculateKeySize(internalPacketSize, internalPacketSize)

	if n!=1{
		t.Fatalf("Keysize isnt big")
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keysize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(name, desc, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		RsaPubKeyLength: keysize,
		Secret:          secret,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RSASubPayloads: n,
	}

	maxPayloadLen, _, _ := ac.GetRSAToPublicMessageLength()

	payload := make([]byte, maxPayloadLen)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, mac, nonce, err := ac.EncryptRSAToPublic(payload, pk, internalPacketSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPublic(encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if bytes.Compare(decrypted, payload) != 0 {
		t.Errorf("Decrypt did not return expected data\n\tExpected: %+v\n\tReceived: %+v\n", payload, decrypted)
	}
}


func TestRSAToPublic_Encrypt_Decrypt_BigKey_SmallPayload(t *testing.T) {
	rng := csprng.NewSystemRNG()

	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keysize, n := calculateKeySize(internalPacketSize, internalPacketSize)

	if n!=1{
		t.Fatalf("Keysize isnt big")
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keysize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(name, desc, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		RsaPubKeyLength: keysize,
		Secret:          secret,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RSASubPayloads: n,
	}

	payload := make([]byte, 10)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, mac, nonce, err := ac.EncryptRSAToPublic(payload, pk, internalPacketSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPublic(encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if bytes.Compare(decrypted, payload) != 0 {
		t.Errorf("Decrypt did not return expected data\n\tExpected: %+v\n\tReceived: %+v\n", payload, decrypted)
	}
}

func TestRSAToPublic_Encrypt_Decrypt_SmallKey(t *testing.T) {
	rng := csprng.NewSystemRNG()

	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keysize, n := calculateKeySize(internalPacketSize, internalPacketSize/5)
	if n<4{
		t.Fatalf("Keysize isnt small")
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keysize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(name, desc, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		RsaPubKeyLength: keysize,
		Secret:          secret,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RSASubPayloads: n,
	}

	maxPayloadLen, _, _ := ac.GetRSAToPublicMessageLength()

	payload := make([]byte, maxPayloadLen)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, mac, nonce, err := ac.EncryptRSAToPublic(payload, pk, internalPacketSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPublic(encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if bytes.Compare(decrypted, payload) != 0 {
		t.Errorf("Decrypt did not return expected data\n\tExpected: %+v\n\tReceived: %+v\n", payload, decrypted)
	}
}


func TestRSAToPublic_Encrypt_Decrypt_SmallKey_SmallPayload(t *testing.T) {
	rng := csprng.NewSystemRNG()

	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keysize, n := calculateKeySize(internalPacketSize, internalPacketSize/5)
	if n<4{
		t.Fatalf("Keysize isnt small")
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keysize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(name, desc, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		RsaPubKeyLength: keysize,
		Secret:          secret,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RSASubPayloads: n,
	}

	payload := make([]byte, 10)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, mac, nonce, err := ac.EncryptRSAToPublic(payload, pk, internalPacketSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPublic(encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if bytes.Compare(decrypted, payload) != 0 {
		t.Errorf("Decrypt did not return expected data\n\tExpected: %+v\n\tReceived: %+v\n", payload, decrypted)
	}
}



func TestRSAToPrivate_Encrypt_Decrypt_BigKey(t *testing.T) {
	rng := csprng.NewSystemRNG()

	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keysize, n := calculateKeySize(internalPacketSize, internalPacketSize)

	if n!=1{
		t.Fatalf("Keysize isnt big")
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keysize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(name, desc, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		RsaPubKeyLength: keysize,
		Secret:          secret,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RSASubPayloads: n,
	}

	maxPayloadLen, _, _ := ac.GetRSAToPublicMessageLength()

	payload := make([]byte, maxPayloadLen)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, mac, nonce, err := ac.EncryptRSAToPrivate(payload, pk.Public(), internalPacketSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPrivate(pk, encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if bytes.Compare(decrypted, payload) != 0 {
		t.Errorf("Decrypt did not return expected data\n\tExpected: %+v\n\tReceived: %+v\n", payload, decrypted)
	}
}


func TestRSAToPrivate_Encrypt_Decrypt_BigKey_SmallPacket(t *testing.T) {
	rng := csprng.NewSystemRNG()

	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keysize, n := calculateKeySize(internalPacketSize, internalPacketSize)

	if n!=1{
		t.Fatalf("Keysize isnt big")
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keysize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(name, desc, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		RsaPubKeyLength: keysize,
		Secret:          secret,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RSASubPayloads: n,
	}

	payload := make([]byte, 10)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, mac, nonce, err := ac.EncryptRSAToPrivate(payload, pk.Public(), internalPacketSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPrivate(pk, encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if bytes.Compare(decrypted, payload) != 0 {
		t.Errorf("Decrypt did not return expected data\n\tExpected: %+v\n\tReceived: %+v\n", payload, decrypted)
	}
}

func TestRSAToPrivate_Encrypt_Decrypt_SmallKey(t *testing.T) {
	rng := csprng.NewSystemRNG()

	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keysize, n := calculateKeySize(internalPacketSize, internalPacketSize/5)

	if n<4{
		t.Fatalf("Keysize isnt small")
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keysize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(name, desc, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		RsaPubKeyLength: keysize,
		Secret:          secret,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RSASubPayloads: n,
	}

	maxPayloadLen, _, _ := ac.GetRSAToPublicMessageLength()

	payload := make([]byte, maxPayloadLen)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, mac, nonce, err := ac.EncryptRSAToPrivate(payload, pk.Public(), internalPacketSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPrivate(pk, encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if bytes.Compare(decrypted, payload) != 0 {
		t.Errorf("Decrypt did not return expected data\n\tExpected: %+v\n\tReceived: %+v\n", payload, decrypted)
	}
}

func TestRSAToPrivate_Encrypt_Decrypt_SmallKey_SmallPacket(t *testing.T) {
	rng := csprng.NewSystemRNG()

	packetSize := 1000
	internalPacketSize := MaxSizedBroadcastPayloadSize(packetSize)
	keysize, n := calculateKeySize(internalPacketSize, internalPacketSize/5)

	if n<4{
		t.Fatalf("Keysize isnt small")
	}

	s := rsa.GetScheme()
	pk, err := s.Generate(rng, keysize*8)
	if err != nil {
		t.Fatalf("Failed to generate private key: %+v", err)
	}
	name := "Asymmetric channel"
	desc := "Asymmetric channel description"
	salt := cmix.NewSalt(rng, 32)

	secret := make([]byte, 32)
	_, err = rng.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	rid, err := NewChannelID(name, desc, salt, HashPubKey(pk.Public()), secret)
	if err != nil {
		t.Fatal(err)
	}
	ac := Channel{
		RsaPubKeyLength: keysize,
		Secret:          secret,
		ReceptionID:     rid,
		Name:            name,
		Description:     desc,
		Salt:            salt,
		RsaPubKeyHash:   HashPubKey(pk.Public()),
		RSASubPayloads: n,
	}

	payload := make([]byte, 10)
	_, err = rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to read random data to payload: %+v", err)
	}
	encrypted, mac, nonce, err := ac.EncryptRSAToPrivate(payload, pk.Public(), internalPacketSize, rng)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %+v", err)
	}

	decrypted, err := ac.DecryptRSAToPrivate(pk, encrypted, mac, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %+v", err)
	}

	if bytes.Compare(decrypted, payload) != 0 {
		t.Errorf("Decrypt did not return expected data\n\tExpected: %+v\n\tReceived: %+v\n", payload, decrypted)
	}
}