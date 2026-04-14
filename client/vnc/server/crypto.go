package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"

	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

const (
	aesKeySize   = 32 // AES-256
	gcmNonceSize = 12
)

// recCrypto holds per-session encryption state.
type recCrypto struct {
	gcm          cipher.AEAD
	frameCounter uint64
	// ephemeralPub is stored in the recording header so the admin can derive the same key.
	ephemeralPub []byte
}

// newRecCrypto sets up encryption for a new recording session.
// adminPubKeyB64 is the base64-encoded X25519 public key from management settings.
func newRecCrypto(adminPubKeyB64 string) (*recCrypto, error) {
	adminPubBytes, err := base64.StdEncoding.DecodeString(adminPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode admin public key: %w", err)
	}

	adminPub, err := ecdh.X25519().NewPublicKey(adminPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse admin X25519 public key: %w", err)
	}

	// Generate ephemeral keypair
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// ECDH shared secret
	shared, err := ephemeral.ECDH(adminPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Derive AES-256 key via HKDF
	aesKey, err := deriveKey(shared, ephemeral.PublicKey().Bytes())
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &recCrypto{
		gcm:          gcm,
		ephemeralPub: ephemeral.PublicKey().Bytes(),
	}, nil
}

// encrypt encrypts plaintext using a counter-based nonce. Each call increments the counter.
func (c *recCrypto) encrypt(plaintext []byte) []byte {
	nonce := make([]byte, gcmNonceSize)
	binary.LittleEndian.PutUint64(nonce, c.frameCounter)
	c.frameCounter++
	return c.gcm.Seal(nil, nonce, plaintext, nil)
}

// DecryptRecording creates a decryptor from the admin's private key and the ephemeral public key from the header.
func DecryptRecording(adminPrivKeyB64 string, ephemeralPubB64 string) (*recDecryptor, error) {
	adminPrivBytes, err := base64.StdEncoding.DecodeString(adminPrivKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode admin private key: %w", err)
	}

	adminPriv, err := ecdh.X25519().NewPrivateKey(adminPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("parse admin X25519 private key: %w", err)
	}

	ephPubBytes, err := base64.StdEncoding.DecodeString(ephemeralPubB64)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral public key: %w", err)
	}

	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	shared, err := adminPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	aesKey, err := deriveKey(shared, ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &recDecryptor{gcm: gcm}, nil
}

type recDecryptor struct {
	gcm          cipher.AEAD
	frameCounter uint64
}

// Decrypt decrypts a frame. Must be called in the same order as encryption.
func (d *recDecryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonce := make([]byte, gcmNonceSize)
	binary.LittleEndian.PutUint64(nonce, d.frameCounter)
	d.frameCounter++
	return d.gcm.Open(nil, nonce, ciphertext, nil)
}

func deriveKey(shared, ephemeralPub []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, shared, ephemeralPub, []byte("netbird-recording"))
	key := make([]byte, aesKeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}
