package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestImage(w, h int, c color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i] = c.R
		img.Pix[i+1] = c.G
		img.Pix[i+2] = c.B
		img.Pix[i+3] = c.A
	}
	return img
}

func TestRecorderWriteAndReadHeader(t *testing.T) {
	dir := t.TempDir()
	logger := log.WithField("test", t.Name())

	meta := &RecordingMeta{
		User:       "alice",
		RemoteAddr: "100.0.1.5:12345",
		JWTUser:    "google|123",
		Mode:       "session",
	}

	rec, err := newVNCRecorder(dir, 800, 600, meta, "", logger)
	require.NoError(t, err)

	// Write some frames
	red := makeTestImage(800, 600, color.RGBA{255, 0, 0, 255})
	blue := makeTestImage(800, 600, color.RGBA{0, 0, 255, 255})

	rec.writeFrame(red)
	rec.writeFrame(red) // duplicate, should be skipped
	rec.writeFrame(blue)
	rec.close()

	// Read back the header
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 1)

	filePath := filepath.Join(dir, files[0].Name())
	header, err := ReadRecordingHeader(filePath)
	require.NoError(t, err)

	assert.Equal(t, 800, header.Width)
	assert.Equal(t, 600, header.Height)
	assert.Equal(t, "alice", header.Meta.User)
	assert.Equal(t, "100.0.1.5:12345", header.Meta.RemoteAddr)
	assert.Equal(t, "google|123", header.Meta.JWTUser)
	assert.Equal(t, "session", header.Meta.Mode)
	assert.False(t, header.Meta.Encrypted)

	// Verify file is valid by checking size is reasonable
	fi, err := os.Stat(filePath)
	require.NoError(t, err)
	assert.Greater(t, fi.Size(), int64(100), "recording should have content")
}

func TestRecorderDuplicateFrameSkip(t *testing.T) {
	dir := t.TempDir()
	logger := log.WithField("test", t.Name())

	rec, err := newVNCRecorder(dir, 100, 100, &RecordingMeta{RemoteAddr: "test"}, "", logger)
	require.NoError(t, err)

	img := makeTestImage(100, 100, color.RGBA{128, 128, 128, 255})

	rec.writeFrame(img)
	rec.writeFrame(img) // duplicate
	rec.writeFrame(img) // duplicate
	rec.close()

	files, _ := os.ReadDir(dir)
	filePath := filepath.Join(dir, files[0].Name())

	// Count frames by parsing
	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	_, err = parseRecHeader(f)
	require.NoError(t, err)

	frameCount := 0
	var hdr [8]byte
	for {
		if _, err := f.Read(hdr[:]); err != nil {
			break
		}
		pngLen := int64(hdr[4])<<24 | int64(hdr[5])<<16 | int64(hdr[6])<<8 | int64(hdr[7])
		f.Seek(pngLen, 1)
		frameCount++
	}

	assert.Equal(t, 1, frameCount, "duplicate frames should be skipped")
}

func TestRecorderEncrypted(t *testing.T) {
	dir := t.TempDir()
	logger := log.WithField("test", t.Name())

	// Generate admin keypair
	adminPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	adminPubB64 := base64.StdEncoding.EncodeToString(adminPriv.PublicKey().Bytes())

	meta := &RecordingMeta{
		RemoteAddr: "100.0.1.5:12345",
		Mode:       "attach",
	}

	rec, err := newVNCRecorder(dir, 200, 150, meta, adminPubB64, logger)
	require.NoError(t, err)

	img := makeTestImage(200, 150, color.RGBA{255, 0, 0, 255})
	rec.writeFrame(img)
	rec.close()

	// Read header and verify encryption metadata
	files, _ := os.ReadDir(dir)
	filePath := filepath.Join(dir, files[0].Name())

	header, err := ReadRecordingHeader(filePath)
	require.NoError(t, err)

	assert.True(t, header.Meta.Encrypted)
	assert.NotEmpty(t, header.Meta.EphemeralKey)
	assert.Equal(t, 200, header.Width)
	assert.Equal(t, 150, header.Height)
}

func TestRecorderEncryptedDecryptRoundtrip(t *testing.T) {
	dir := t.TempDir()
	logger := log.WithField("test", t.Name())

	adminPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	adminPubB64 := base64.StdEncoding.EncodeToString(adminPriv.PublicKey().Bytes())
	adminPrivB64 := base64.StdEncoding.EncodeToString(adminPriv.Bytes())

	rec, err := newVNCRecorder(dir, 100, 100, &RecordingMeta{RemoteAddr: "test"}, adminPubB64, logger)
	require.NoError(t, err)

	red := makeTestImage(100, 100, color.RGBA{255, 0, 0, 255})
	green := makeTestImage(100, 100, color.RGBA{0, 255, 0, 255})

	rec.writeFrame(red)
	rec.writeFrame(green)
	rec.close()

	// Read back and decrypt
	files, _ := os.ReadDir(dir)
	filePath := filepath.Join(dir, files[0].Name())

	header, err := ReadRecordingHeader(filePath)
	require.NoError(t, err)
	require.True(t, header.Meta.Encrypted)

	dec, err := DecryptRecording(adminPrivB64, header.Meta.EphemeralKey)
	require.NoError(t, err)

	// Read raw frames and decrypt
	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	_, err = parseRecHeader(f)
	require.NoError(t, err)

	decryptedFrames := 0
	var hdr [8]byte
	for {
		if _, readErr := f.Read(hdr[:]); readErr != nil {
			break
		}
		frameLen := int(hdr[4])<<24 | int(hdr[5])<<16 | int(hdr[6])<<8 | int(hdr[7])
		ct := make([]byte, frameLen)
		f.Read(ct)

		_, err := dec.Decrypt(ct)
		require.NoError(t, err, "frame %d decrypt should succeed", decryptedFrames)
		decryptedFrames++
	}

	assert.Equal(t, 2, decryptedFrames)
}
