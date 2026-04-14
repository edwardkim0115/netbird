package server

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// RecordingHeader holds parsed header data from a VNC recording file.
type RecordingHeader struct {
	Width     int
	Height    int
	StartTime time.Time
	Meta      RecordingMeta
}

// ReadRecordingHeader parses and returns the recording header without loading frames.
func ReadRecordingHeader(filePath string) (*RecordingHeader, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseRecHeader(f)
}

func parseRecHeader(r io.Reader) (*RecordingHeader, error) {
	var hdr [22]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if string(hdr[:6]) != recMagic {
		return nil, fmt.Errorf("invalid magic: %x", hdr[:6])
	}

	width := int(binary.BigEndian.Uint16(hdr[6:8]))
	height := int(binary.BigEndian.Uint16(hdr[8:10]))
	startMs := int64(binary.BigEndian.Uint64(hdr[10:18]))
	metaLen := binary.BigEndian.Uint32(hdr[18:22])

	if metaLen > 1<<20 {
		return nil, fmt.Errorf("meta too large: %d bytes", metaLen)
	}

	metaJSON := make([]byte, metaLen)
	if _, err := io.ReadFull(r, metaJSON); err != nil {
		return nil, fmt.Errorf("read meta: %w", err)
	}

	var meta RecordingMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, fmt.Errorf("parse meta: %w", err)
	}

	return &RecordingHeader{
		Width:     width,
		Height:    height,
		StartTime: time.UnixMilli(startMs),
		Meta:      meta,
	}, nil
}
