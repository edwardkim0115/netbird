package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCryptoRoundtrip(t *testing.T) {
	// Generate admin keypair
	adminPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	adminPubB64 := base64.StdEncoding.EncodeToString(adminPriv.PublicKey().Bytes())
	adminPrivB64 := base64.StdEncoding.EncodeToString(adminPriv.Bytes())

	// Create encryptor (recording side)
	enc, err := newRecCrypto(adminPubB64)
	require.NoError(t, err)
	assert.Len(t, enc.ephemeralPub, 32)

	ephPubB64 := base64.StdEncoding.EncodeToString(enc.ephemeralPub)

	// Encrypt some frames
	plaintext1 := []byte("frame data one - PNG bytes would go here")
	plaintext2 := []byte("frame data two - different content")
	plaintext3 := make([]byte, 1024*100) // 100KB frame
	rand.Read(plaintext3)

	ct1 := enc.encrypt(plaintext1)
	ct2 := enc.encrypt(plaintext2)
	ct3 := enc.encrypt(plaintext3)

	// Ciphertext should differ from plaintext
	assert.NotEqual(t, plaintext1, ct1)
	// Ciphertext is larger (GCM tag overhead)
	assert.Greater(t, len(ct1), len(plaintext1))

	// Create decryptor (playback side)
	dec, err := DecryptRecording(adminPrivB64, ephPubB64)
	require.NoError(t, err)

	// Decrypt in same order
	got1, err := dec.Decrypt(ct1)
	require.NoError(t, err)
	assert.Equal(t, plaintext1, got1)

	got2, err := dec.Decrypt(ct2)
	require.NoError(t, err)
	assert.Equal(t, plaintext2, got2)

	got3, err := dec.Decrypt(ct3)
	require.NoError(t, err)
	assert.Equal(t, plaintext3, got3)
}

func TestCryptoWrongKey(t *testing.T) {
	// Admin key
	adminPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	adminPubB64 := base64.StdEncoding.EncodeToString(adminPriv.PublicKey().Bytes())

	// Encrypt with admin's public key
	enc, err := newRecCrypto(adminPubB64)
	require.NoError(t, err)
	ephPubB64 := base64.StdEncoding.EncodeToString(enc.ephemeralPub)

	ct := enc.encrypt([]byte("secret frame data"))

	// Try to decrypt with a different private key
	wrongPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	wrongPrivB64 := base64.StdEncoding.EncodeToString(wrongPriv.Bytes())

	dec, err := DecryptRecording(wrongPrivB64, ephPubB64)
	require.NoError(t, err)

	_, err = dec.Decrypt(ct)
	assert.Error(t, err, "decryption with wrong key should fail")
}

func TestCryptoInvalidKey(t *testing.T) {
	_, err := newRecCrypto("")
	assert.Error(t, err, "empty key should fail")

	_, err = newRecCrypto("not-base64!!!")
	assert.Error(t, err, "invalid base64 should fail")

	_, err = newRecCrypto(base64.StdEncoding.EncodeToString([]byte("too-short")))
	assert.Error(t, err, "wrong-length key should fail")

	_, err = DecryptRecording("", "validbutirrelevant")
	assert.Error(t, err, "empty private key should fail")

	_, err = DecryptRecording("not-base64!!!", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	assert.Error(t, err, "invalid base64 private key should fail")
}

func TestCryptoOutOfOrderFails(t *testing.T) {
	adminPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	adminPubB64 := base64.StdEncoding.EncodeToString(adminPriv.PublicKey().Bytes())
	adminPrivB64 := base64.StdEncoding.EncodeToString(adminPriv.Bytes())

	enc, err := newRecCrypto(adminPubB64)
	require.NoError(t, err)
	ephPubB64 := base64.StdEncoding.EncodeToString(enc.ephemeralPub)

	ct0 := enc.encrypt([]byte("frame 0"))
	ct1 := enc.encrypt([]byte("frame 1"))

	dec, err := DecryptRecording(adminPrivB64, ephPubB64)
	require.NoError(t, err)

	// Skip frame 0, try to decrypt frame 1 first (wrong nonce)
	_, err = dec.Decrypt(ct1)
	assert.Error(t, err, "out-of-order decryption should fail due to nonce mismatch")

	// But frame 0 with a fresh decryptor should work
	dec2, err := DecryptRecording(adminPrivB64, ephPubB64)
	require.NoError(t, err)
	got, err := dec2.Decrypt(ct0)
	require.NoError(t, err)
	assert.Equal(t, []byte("frame 0"), got)
}
