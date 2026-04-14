package cmd

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
	"github.com/netbirdio/netbird/util"
)

var vncRecDir string

func init() {
	vncRecPlayCmd.Flags().StringVar(&vncRecDir, "dir", "", "Recording directory (default: auto-detect)")
	vncRecListCmd.Flags().StringVar(&vncRecDir, "dir", "", "Recording directory (default: auto-detect)")
	vncRecCmd.AddCommand(vncRecListCmd)
	vncRecCmd.AddCommand(vncRecPlayCmd)
	vncRecCmd.AddCommand(vncRecKeygenCmd)
	vncCmd.AddCommand(vncRecCmd)
}

var vncRecCmd = &cobra.Command{
	Use:   "rec",
	Short: "Manage VNC session recordings",
}

var vncRecKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an X25519 keypair for recording encryption",
	Long: `Generates an X25519 keypair. Put the public key in management settings
(Session Recording > Encryption Key). Keep the private key safe for decrypting recordings.`,
	RunE: vncRecKeygenFn,
}

var vncRecListCmd = &cobra.Command{
	Use:   "list",
	Short: "List VNC session recordings",
	RunE:  vncRecListFn,
}

var vncRecPlayCmd = &cobra.Command{
	Use:   "play <file-or-name>",
	Short: "Open a VNC recording in the browser",
	Long: `Opens a browser-based player with playback controls:
play/pause, seek, speed (0.25x to 8x), keyboard shortcuts.

Examples:
  netbird vnc rec play last
  netbird vnc rec play 20260416-104433_vnc.rec`,
	Args: cobra.ExactArgs(1),
	RunE: vncRecPlayFn,
}


func vncRecListFn(cmd *cobra.Command, _ []string) error {
	dir, err := resolveVNCRecDir()
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read recording dir %s: %w", dir, err)
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FILE\tSIZE\tDIMENSIONS\tUSER\tREMOTE\tMODE\tDATE")

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rec") {
			continue
		}
		filePath := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		header, err := vncserver.ReadRecordingHeader(filePath)
		if err != nil {
			fmt.Fprintf(w, "%s\t%s\t?\t?\t?\t?\t?\n", entry.Name(), vncFormatSize(info.Size()))
			continue
		}

		fmt.Fprintf(w, "%s\t%s\t%dx%d\t%s\t%s\t%s\t%s\n",
			entry.Name(),
			vncFormatSize(info.Size()),
			header.Width, header.Height,
			header.Meta.User,
			header.Meta.RemoteAddr,
			header.Meta.Mode,
			header.StartTime.Format("2006-01-02 15:04:05"),
		)
	}

	return w.Flush()
}

func vncRecPlayFn(cmd *cobra.Command, args []string) error {
	filePath, err := resolveVNCRecFile(args[0])
	if err != nil {
		return err
	}

	header, err := vncserver.ReadRecordingHeader(filePath)
	if err != nil {
		return fmt.Errorf("read recording: %w", err)
	}

	cmd.Printf("Recording: %s (%dx%d)\n", filepath.Base(filePath), header.Width, header.Height)

	url, err := vncserver.ServeWebPlayer(filePath, "localhost:0")
	if err != nil {
		return fmt.Errorf("start web player: %w", err)
	}
	cmd.Printf("Player: %s\n", url)
	if err := util.OpenBrowser(url); err != nil {
		cmd.Printf("Open %s in your browser\n", url)
	}
	cmd.Printf("Press Ctrl+C to stop.\n")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	return nil
}


func vncRecKeygenFn(cmd *cobra.Command, _ []string) error {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())

	cmd.Printf("Private key (keep secret, for decrypting recordings):\n  %s\n\n", privB64)
	cmd.Printf("Public key (paste into management Settings > Session Recording > Encryption Key):\n  %s\n", pubB64)
	return nil
}

func vncFormatSize(size int64) string {
	switch {
	case size >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(size)/float64(1<<20))
	case size >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(size)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", size)
	}
}

func resolveVNCRecDir() (string, error) {
	if vncRecDir != "" {
		return vncRecDir, nil
	}
	candidates := []string{
		"/var/lib/netbird/recordings/vnc",
		filepath.Join(os.Getenv("HOME"), ".netbird/recordings/vnc"),
	}
	for _, dir := range candidates {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no VNC recording directory found; use --dir to specify")
}

func resolveVNCRecFile(arg string) (string, error) {
	if strings.Contains(arg, "/") || strings.Contains(arg, string(os.PathSeparator)) {
		return arg, nil
	}

	dir, err := resolveVNCRecDir()
	if err != nil && arg != "last" {
		return arg, nil
	}

	if arg == "last" {
		if err != nil {
			return "", err
		}
		return findLatestRec(dir)
	}

	full := filepath.Join(dir, arg)
	if _, err := os.Stat(full); err == nil {
		return full, nil
	}
	return arg, nil
}

func findLatestRec(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read dir: %w", err)
	}

	var latest string
	var latestTime time.Time
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rec") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(latestTime) {
			latestTime = info.ModTime()
			latest = filepath.Join(dir, entry.Name())
		}
	}
	if latest == "" {
		return "", fmt.Errorf("no recordings found in %s", dir)
	}
	return latest, nil
}
