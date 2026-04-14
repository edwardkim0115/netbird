package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Recording file format:
//
//	Header: magic(6) + width(2) + height(2) + startTime(8) + metaLen(4) + metaJSON
//	Frames: offsetMs(4) + pngLen(4) + PNG image data
//
// Each frame is a PNG-encoded screenshot. Only changed frames are stored.
const recMagic = "NBVNC\x01"

// RecordingMeta holds metadata written to the recording file header.
type RecordingMeta struct {
	User         string `json:"user,omitempty"`
	RemoteAddr   string `json:"remote_addr"`
	JWTUser      string `json:"jwt_user,omitempty"`
	Mode         string `json:"mode,omitempty"`
	Encrypted    bool   `json:"encrypted,omitempty"`
	EphemeralKey string `json:"ephemeral_key,omitempty"`
}

// vncRecorder writes VNC session frames to a recording file.
type vncRecorder struct {
	mu        sync.Mutex
	file      *os.File
	startTime time.Time
	closed    bool
	log       *log.Entry
	prevFrame *image.RGBA
	pngEnc    *png.Encoder
	pngBuf    bytes.Buffer
	crypto    *recCrypto
}

func newVNCRecorder(dir string, width, height int, meta *RecordingMeta, encryptionKey string, logger *log.Entry) (*vncRecorder, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create recording dir: %w", err)
	}

	now := time.Now().UTC()
	filename := fmt.Sprintf("%s_vnc.rec", now.Format("20060102-150405"))
	filePath := filepath.Join(dir, filename)

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create recording file: %w", err)
	}

	var crypto *recCrypto
	if encryptionKey != "" {
		var cryptoErr error
		crypto, cryptoErr = newRecCrypto(encryptionKey)
		if cryptoErr != nil {
			f.Close()
			os.Remove(filePath)
			return nil, fmt.Errorf("init encryption: %w", cryptoErr)
		}
		meta.Encrypted = true
		meta.EphemeralKey = base64.StdEncoding.EncodeToString(crypto.ephemeralPub)
	}

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		f.Close()
		os.Remove(filePath)
		return nil, fmt.Errorf("marshal meta: %w", err)
	}

	var hdr [6 + 2 + 2 + 8 + 4]byte
	copy(hdr[:6], recMagic)
	binary.BigEndian.PutUint16(hdr[6:8], uint16(width))
	binary.BigEndian.PutUint16(hdr[8:10], uint16(height))
	binary.BigEndian.PutUint64(hdr[10:18], uint64(now.UnixMilli()))
	binary.BigEndian.PutUint32(hdr[18:22], uint32(len(metaJSON)))

	if _, err := f.Write(hdr[:]); err != nil {
		f.Close()
		os.Remove(filePath)
		return nil, fmt.Errorf("write header: %w", err)
	}
	if _, err := f.Write(metaJSON); err != nil {
		f.Close()
		os.Remove(filePath)
		return nil, fmt.Errorf("write meta: %w", err)
	}

	r := &vncRecorder{
		file:      f,
		startTime: now,
		log:       logger.WithField("recording", filepath.Base(filePath)),
		pngEnc:    &png.Encoder{CompressionLevel: png.BestSpeed},
		crypto:    crypto,
	}
	if crypto != nil {
		r.log.Infof("VNC recording started (encrypted): %s", filePath)
	} else {
		r.log.Infof("VNC recording started: %s", filePath)
	}
	return r, nil
}

// writeFrame records a screen frame. Only writes if the frame differs from the previous one.
func (r *vncRecorder) writeFrame(img *image.RGBA) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}

	if r.prevFrame != nil && bytes.Equal(r.prevFrame.Pix, img.Pix) {
		return
	}

	offsetMs := uint32(time.Since(r.startTime).Milliseconds())

	r.pngBuf.Reset()
	if err := r.pngEnc.Encode(&r.pngBuf, img); err != nil {
		r.log.Debugf("encode PNG frame: %v", err)
		return
	}

	frameData := r.pngBuf.Bytes()
	if r.crypto != nil {
		frameData = r.crypto.encrypt(frameData)
	}

	var frameHdr [8]byte
	binary.BigEndian.PutUint32(frameHdr[0:4], offsetMs)
	binary.BigEndian.PutUint32(frameHdr[4:8], uint32(len(frameData)))

	if _, err := r.file.Write(frameHdr[:]); err != nil {
		r.log.Debugf("write frame header: %v", err)
		return
	}
	if _, err := r.file.Write(frameData); err != nil {
		r.log.Debugf("write frame data: %v", err)
		return
	}

	if r.prevFrame == nil {
		r.prevFrame = image.NewRGBA(img.Rect)
	}
	copy(r.prevFrame.Pix, img.Pix)
}

func (r *vncRecorder) close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}
	r.closed = true

	duration := time.Since(r.startTime)
	r.log.Infof("VNC recording stopped after %v", duration.Round(time.Millisecond))
	r.file.Close()
}

