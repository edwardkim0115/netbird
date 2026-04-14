package server

import (
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"os"
)

//go:embed webplayer.html
var webPlayerHTML []byte

// ServeWebPlayer starts a local HTTP server that serves the recording file
// and an HTML player page. Returns the URL to open.
func ServeWebPlayer(recPath, listenAddr string) (string, error) {
	if listenAddr == "" {
		listenAddr = "localhost:0"
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(webPlayerHTML) //nolint:errcheck
	})

	mux.HandleFunc("/recording.rec", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(recPath)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer f.Close()
		fi, _ := f.Stat()
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "recording.rec", fi.ModTime(), f)
	})

	url := fmt.Sprintf("http://%s", ln.Addr())

	go http.Serve(ln, mux) //nolint:errcheck

	return url, nil
}
