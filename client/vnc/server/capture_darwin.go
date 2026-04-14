//go:build darwin && !ios

package server

import (
	"errors"
	"fmt"
	"hash/maphash"
	"image"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	log "github.com/sirupsen/logrus"
)


var darwinCaptureOnce sync.Once

var (
	cgMainDisplayID                func() uint32
	cgDisplayPixelsWide            func(uint32) uintptr
	cgDisplayPixelsHigh            func(uint32) uintptr
	cgDisplayCreateImage           func(uint32) uintptr
	cgImageGetWidth                func(uintptr) uintptr
	cgImageGetHeight               func(uintptr) uintptr
	cgImageGetBytesPerRow          func(uintptr) uintptr
	cgImageGetBitsPerPixel         func(uintptr) uintptr
	cgImageGetDataProvider         func(uintptr) uintptr
	cgDataProviderCopyData         func(uintptr) uintptr
	cgImageRelease                 func(uintptr)
	cfDataGetLength                func(uintptr) int64
	cfDataGetBytePtr               func(uintptr) uintptr
	cfRelease                      func(uintptr)
	cgPreflightScreenCaptureAccess func() bool
	cgRequestScreenCaptureAccess   func() bool
	darwinCaptureReady             bool
)

func initDarwinCapture() {
	darwinCaptureOnce.Do(func() {
		cg, err := purego.Dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			log.Debugf("load CoreGraphics: %v", err)
			return
		}
		cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			log.Debugf("load CoreFoundation: %v", err)
			return
		}

		purego.RegisterLibFunc(&cgMainDisplayID, cg, "CGMainDisplayID")
		purego.RegisterLibFunc(&cgDisplayPixelsWide, cg, "CGDisplayPixelsWide")
		purego.RegisterLibFunc(&cgDisplayPixelsHigh, cg, "CGDisplayPixelsHigh")
		purego.RegisterLibFunc(&cgDisplayCreateImage, cg, "CGDisplayCreateImage")
		purego.RegisterLibFunc(&cgImageGetWidth, cg, "CGImageGetWidth")
		purego.RegisterLibFunc(&cgImageGetHeight, cg, "CGImageGetHeight")
		purego.RegisterLibFunc(&cgImageGetBytesPerRow, cg, "CGImageGetBytesPerRow")
		purego.RegisterLibFunc(&cgImageGetBitsPerPixel, cg, "CGImageGetBitsPerPixel")
		purego.RegisterLibFunc(&cgImageGetDataProvider, cg, "CGImageGetDataProvider")
		purego.RegisterLibFunc(&cgDataProviderCopyData, cg, "CGDataProviderCopyData")
		purego.RegisterLibFunc(&cgImageRelease, cg, "CGImageRelease")
		purego.RegisterLibFunc(&cfDataGetLength, cf, "CFDataGetLength")
		purego.RegisterLibFunc(&cfDataGetBytePtr, cf, "CFDataGetBytePtr")
		purego.RegisterLibFunc(&cfRelease, cf, "CFRelease")

		// Screen capture permission APIs (macOS 11+). Might not exist on older versions.
		if sym, err := purego.Dlsym(cg, "CGPreflightScreenCaptureAccess"); err == nil {
			purego.RegisterFunc(&cgPreflightScreenCaptureAccess, sym)
		}
		if sym, err := purego.Dlsym(cg, "CGRequestScreenCaptureAccess"); err == nil {
			purego.RegisterFunc(&cgRequestScreenCaptureAccess, sym)
		}

		darwinCaptureReady = true
	})
}

// errFrameUnchanged signals that the raw capture bytes matched the previous
// frame, so the caller can skip the expensive BGRA to RGBA conversion.
var errFrameUnchanged = errors.New("frame unchanged")

// CGCapturer captures the macOS main display using Core Graphics.
type CGCapturer struct {
	displayID uint32
	w, h      int
	// downscale is 1 for pixel-perfect, 2 for Retina 2:1 box-filter downscale.
	downscale int
	hashSeed  maphash.Seed
	lastHash  uint64
	hasHash   bool
}

// NewCGCapturer creates a screen capturer for the main display.
func NewCGCapturer() (*CGCapturer, error) {
	initDarwinCapture()
	if !darwinCaptureReady {
		return nil, fmt.Errorf("CoreGraphics not available")
	}

	// Request Screen Recording permission (shows system dialog on macOS 11+).
	if cgPreflightScreenCaptureAccess != nil && !cgPreflightScreenCaptureAccess() {
		if cgRequestScreenCaptureAccess != nil {
			cgRequestScreenCaptureAccess()
		}
		openPrivacyPane("Privacy_ScreenCapture")
		log.Warn("Screen Recording permission not granted. " +
			"Opened System Settings > Privacy & Security > Screen Recording; enable netbird and restart.")
	}

	displayID := cgMainDisplayID()
	c := &CGCapturer{displayID: displayID, downscale: 1, hashSeed: maphash.MakeSeed()}

	// Probe actual pixel dimensions via a test capture. CGDisplayPixelsWide/High
	// returns logical points on Retina, but CGDisplayCreateImage produces native
	// pixels (often 2x), so probing the image is the only reliable source.
	img, err := c.Capture()
	if err != nil {
		return nil, fmt.Errorf("probe capture: %w", err)
	}
	nativeW := img.Rect.Dx()
	nativeH := img.Rect.Dy()
	c.hasHash = false
	if nativeW == 0 || nativeH == 0 {
		return nil, errors.New("display dimensions are zero")
	}

	logicalW := int(cgDisplayPixelsWide(displayID))
	logicalH := int(cgDisplayPixelsHigh(displayID))

	// Enable 2:1 downscale on Retina unless explicitly disabled. Cuts pixel
	// count 4x, shrinking convert, diff, and wire data proportionally.
	if !retinaDownscaleDisabled() && nativeW >= 2*logicalW && nativeH >= 2*logicalH && nativeW%2 == 0 && nativeH%2 == 0 {
		c.downscale = 2
	}
	c.w = nativeW / c.downscale
	c.h = nativeH / c.downscale

	log.Infof("macOS capturer ready: %dx%d (native %dx%d, logical %dx%d, downscale=%d, display=%d)",
		c.w, c.h, nativeW, nativeH, logicalW, logicalH, c.downscale, displayID)
	return c, nil
}

func retinaDownscaleDisabled() bool {
	v := os.Getenv(EnvVNCDisableDownscale)
	if v == "" {
		return false
	}
	disabled, err := strconv.ParseBool(v)
	if err != nil {
		log.Warnf("parse %s: %v", EnvVNCDisableDownscale, err)
		return false
	}
	return disabled
}

// Width returns the screen width.
func (c *CGCapturer) Width() int { return c.w }

// Height returns the screen height.
func (c *CGCapturer) Height() int { return c.h }

// Capture returns the current screen as an RGBA image.
func (c *CGCapturer) Capture() (*image.RGBA, error) {
	cgImage := cgDisplayCreateImage(c.displayID)
	if cgImage == 0 {
		return nil, fmt.Errorf("CGDisplayCreateImage returned nil (screen recording permission?)")
	}
	defer cgImageRelease(cgImage)

	w := int(cgImageGetWidth(cgImage))
	h := int(cgImageGetHeight(cgImage))
	bytesPerRow := int(cgImageGetBytesPerRow(cgImage))
	bpp := int(cgImageGetBitsPerPixel(cgImage))

	provider := cgImageGetDataProvider(cgImage)
	if provider == 0 {
		return nil, fmt.Errorf("CGImageGetDataProvider returned nil")
	}

	cfData := cgDataProviderCopyData(provider)
	if cfData == 0 {
		return nil, fmt.Errorf("CGDataProviderCopyData returned nil")
	}
	defer cfRelease(cfData)

	dataLen := int(cfDataGetLength(cfData))
	dataPtr := cfDataGetBytePtr(cfData)
	if dataPtr == 0 || dataLen == 0 {
		return nil, fmt.Errorf("empty image data")
	}

	src := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), dataLen)

	hash := maphash.Bytes(c.hashSeed, src)
	if c.hasHash && hash == c.lastHash {
		return nil, errFrameUnchanged
	}
	c.lastHash = hash
	c.hasHash = true

	ds := c.downscale
	if ds < 1 {
		ds = 1
	}
	outW := w / ds
	outH := h / ds
	img := image.NewRGBA(image.Rect(0, 0, outW, outH))

	bytesPerPixel := bpp / 8
	if bytesPerPixel == 4 && ds == 1 {
		convertBGRAToRGBA(img.Pix, img.Stride, src, bytesPerRow, w, h)
	} else if bytesPerPixel == 4 && ds == 2 {
		convertBGRAToRGBADownscale2(img.Pix, img.Stride, src, bytesPerRow, outW, outH)
	} else {
		for row := 0; row < outH; row++ {
			srcOff := row * ds * bytesPerRow
			dstOff := row * img.Stride
			for col := 0; col < outW; col++ {
				si := srcOff + col*ds*bytesPerPixel
				di := dstOff + col*4
				img.Pix[di+0] = src[si+2]
				img.Pix[di+1] = src[si+1]
				img.Pix[di+2] = src[si+0]
				img.Pix[di+3] = 0xff
			}
		}
	}

	return img, nil
}

// convertBGRAToRGBADownscale2 averages every 2x2 BGRA block into one RGBA
// output pixel, parallelised across GOMAXPROCS cores. outW and outH are the
// destination dimensions (source is 2*outW by 2*outH).
func convertBGRAToRGBADownscale2(dst []byte, dstStride int, src []byte, srcStride, outW, outH int) {
	workers := runtime.GOMAXPROCS(0)
	if workers > outH {
		workers = outH
	}
	if workers < 1 || outH < 32 {
		workers = 1
	}

	convertRows := func(y0, y1 int) {
		for row := y0; row < y1; row++ {
			srcRow0 := 2 * row * srcStride
			srcRow1 := srcRow0 + srcStride
			dstOff := row * dstStride
			for col := 0; col < outW; col++ {
				s0 := srcRow0 + col*8
				s1 := srcRow1 + col*8
				b := (uint32(src[s0]) + uint32(src[s0+4]) + uint32(src[s1]) + uint32(src[s1+4])) >> 2
				g := (uint32(src[s0+1]) + uint32(src[s0+5]) + uint32(src[s1+1]) + uint32(src[s1+5])) >> 2
				r := (uint32(src[s0+2]) + uint32(src[s0+6]) + uint32(src[s1+2]) + uint32(src[s1+6])) >> 2
				di := dstOff + col*4
				dst[di+0] = byte(r)
				dst[di+1] = byte(g)
				dst[di+2] = byte(b)
				dst[di+3] = 0xff
			}
		}
	}

	if workers == 1 {
		convertRows(0, outH)
		return
	}

	var wg sync.WaitGroup
	chunk := (outH + workers - 1) / workers
	for i := 0; i < workers; i++ {
		y0 := i * chunk
		y1 := y0 + chunk
		if y1 > outH {
			y1 = outH
		}
		if y0 >= y1 {
			break
		}
		wg.Add(1)
		go func(y0, y1 int) {
			defer wg.Done()
			convertRows(y0, y1)
		}(y0, y1)
	}
	wg.Wait()
}

// convertBGRAToRGBA swaps R/B channels using uint32 word operations, and
// parallelises across GOMAXPROCS cores for large images.
func convertBGRAToRGBA(dst []byte, dstStride int, src []byte, srcStride, w, h int) {
	workers := runtime.GOMAXPROCS(0)
	if workers > h {
		workers = h
	}
	if workers < 1 || h < 64 {
		workers = 1
	}

	convertRows := func(y0, y1 int) {
		rowBytes := w * 4
		for row := y0; row < y1; row++ {
			dstRow := dst[row*dstStride : row*dstStride+rowBytes]
			srcRow := src[row*srcStride : row*srcStride+rowBytes]
			dstU := unsafe.Slice((*uint32)(unsafe.Pointer(&dstRow[0])), w)
			srcU := unsafe.Slice((*uint32)(unsafe.Pointer(&srcRow[0])), w)
			for i, p := range srcU {
				dstU[i] = (p & 0xff00ff00) | ((p & 0x000000ff) << 16) | ((p & 0x00ff0000) >> 16) | 0xff000000
			}
		}
	}

	if workers == 1 {
		convertRows(0, h)
		return
	}

	var wg sync.WaitGroup
	chunk := (h + workers - 1) / workers
	for i := 0; i < workers; i++ {
		y0 := i * chunk
		y1 := y0 + chunk
		if y1 > h {
			y1 = h
		}
		if y0 >= y1 {
			break
		}
		wg.Add(1)
		go func(y0, y1 int) {
			defer wg.Done()
			convertRows(y0, y1)
		}(y0, y1)
	}
	wg.Wait()
}

// MacPoller wraps CGCapturer in a continuous capture loop.
type MacPoller struct {
	mu    sync.Mutex
	frame *image.RGBA
	w, h  int
	done  chan struct{}
	// wake shortens the init-retry backoff when a client is trying to connect,
	// so granting Screen Recording mid-session takes effect immediately.
	wake chan struct{}
}

// NewMacPoller creates a capturer that continuously grabs the macOS display.
func NewMacPoller() *MacPoller {
	p := &MacPoller{
		done: make(chan struct{}),
		wake: make(chan struct{}, 1),
	}
	go p.loop()
	return p
}

// Wake pokes the init-retry loop so it doesn't wait out the full backoff
// before trying again. Safe to call from any goroutine; extra calls while a
// wake is pending are dropped.
func (p *MacPoller) Wake() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Close stops the capture loop.
func (p *MacPoller) Close() {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

// Width returns the screen width.
func (p *MacPoller) Width() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.w
}

// Height returns the screen height.
func (p *MacPoller) Height() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.h
}

// Capture returns the most recent frame.
func (p *MacPoller) Capture() (*image.RGBA, error) {
	p.mu.Lock()
	img := p.frame
	p.mu.Unlock()
	if img != nil {
		return img, nil
	}
	return nil, fmt.Errorf("no frame available yet")
}

func (p *MacPoller) loop() {
	var capturer *CGCapturer
	var initFails int

	for {
		select {
		case <-p.done:
			return
		default:
		}

		if capturer == nil {
			var err error
			capturer, err = NewCGCapturer()
			if err != nil {
				initFails++
				// Retry forever with backoff: the user may grant Screen
				// Recording after the server started, and we need to pick it
				// up whenever that happens.
				delay := 2 * time.Second
				if initFails > 15 {
					delay = 30 * time.Second
				} else if initFails > 5 {
					delay = 10 * time.Second
				}
				if initFails == 1 || initFails%10 == 0 {
					log.Warnf("macOS capturer: %v (attempt %d, retrying every %s)", err, initFails, delay)
				} else {
					log.Debugf("macOS capturer: %v (attempt %d)", err, initFails)
				}
				select {
				case <-p.done:
					return
				case <-p.wake:
					// Client is trying to connect, retry now.
				case <-time.After(delay):
				}
				continue
			}
			initFails = 0
			p.mu.Lock()
			p.w, p.h = capturer.Width(), capturer.Height()
			p.mu.Unlock()
		}

		img, err := capturer.Capture()
		if errors.Is(err, errFrameUnchanged) {
			select {
			case <-p.done:
				return
			case <-time.After(33 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			log.Debugf("macOS capture: %v", err)
			capturer = nil
			select {
			case <-p.done:
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}

		p.mu.Lock()
		p.frame = img
		p.mu.Unlock()

		select {
		case <-p.done:
			return
		case <-time.After(33 * time.Millisecond): // ~30 fps
		}
	}
}

var _ ScreenCapturer = (*MacPoller)(nil)
