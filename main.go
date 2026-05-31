// solbridge: SSH into iDRAC, run `console com2`, bridge to local TCP port.
//
// Usage: go run . -host <idrac> -i <key> localhost:2300
//        go run . -host <idrac> -i <key> :2301
//
// Once running, `nc localhost 2300` connects you to the serial console.
// Multiple concurrent nc sessions share the same SOL connection (output is broadcast).
// Survives SSH session drops with exponential-backoff reconnection.

package main

import (
	"strings"
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	sshHost := flag.String("host", "", "iDRAC SSH host (resolved from ~/.ssh/config)")
	identityFile := flag.String("i", "", "SSH identity file")
	userFlag := flag.String("u", "root", "SSH user")
	flag.Parse()

	if *sshHost == "" || *identityFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: solbridge -host HOST -i IDENTITY [-u USER] LISTEN_ADDR\n")
		fmt.Fprintf(os.Stderr, "Example: solbridge -host idrac.local -i ~/.ssh/idrac localhost:9119\n")
		os.Exit(1)
	}
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: solbridge -host HOST -i IDENTITY [-u USER] LISTEN_ADDR\n")
		fmt.Fprintf(os.Stderr, "Example: solbridge -host idrac.local -i ~/.ssh/idrac localhost:9119\n")
		os.Exit(1)
	}
	listenAddr := flag.Arg(0)

	keyPath := expandPath(*identityFile)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("read key %s: %v", keyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("parse key: %v", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            *userFlag,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Resolve the host from ~/.ssh/config.
	finalHost, finalPort := resolveSSHConfig(*sshHost)
	addr := fmt.Sprintf("%s:%d", finalHost, finalPort)
	log.Printf("connecting to iDRAC at %s (%s)", *sshHost, addr)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	log.Printf("listening on %s", listenAddr)

	b := &bridge{
		quit:  make(chan struct{}),
		solIn: swappableWriter{w: io.Discard},
	}

	// Signal handling for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		close(b.quit)
		ln.Close()
	}()

	go b.reconnectLoop(addr, sshConfig)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed — exit.
			break
		}
		log.Printf("client connected from %s", conn.RemoteAddr())

		b.mu.Lock()
		b.writers = append(b.writers, conn)
		b.mu.Unlock()

		// Read from TCP client → write to SOL stdin (swappable across reconnects).
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(&b.solIn, c)
			b.mu.Lock()
			for i, w := range b.writers {
				if w == c {
					b.writers = append(b.writers[:i], b.writers[i+1:]...)
					break
				}
			}
			b.mu.Unlock()
			log.Printf("client disconnected from %s", c.RemoteAddr())
		}(conn)
	}
}

// bridge holds the shared state: connected TCP writers and the SOL stdin
// writer, which is atomically swapped on reconnect.
type bridge struct {
	mu      sync.Mutex
	writers []io.Writer
	solIn   swappableWriter
	quit    chan struct{}
}

// readSOL copies from r to all connected writers in 4 KB chunks.
// Returns when r reaches EOF or error.
func (b *bridge) readSOL(r io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			b.mu.Lock()
			active := b.writers[:0]
			for _, w := range b.writers {
				if _, werr := w.Write(buf[:n]); werr != nil {
					continue
				}
				active = append(active, w)
			}
			b.writers = active
			b.mu.Unlock()
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("SOL read error: %v", err)
			}
			return
		}
	}
}

// broadcastMsg sends a fixed string to all connected writers (best-effort).
func (b *bridge) broadcastMsg(msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, w := range b.writers {
		w.Write([]byte(msg))
	}
}

// connectSOL dials SSH, creates a session, requests a PTY, starts
// "console com2", and returns the stdin/stdout pipes and a shutdown
// function that closes the session then the client.
func connectSOL(addr string, sshConfig *ssh.ClientConfig) (shutdown func(), solIn io.WriteCloser, solOut io.Reader, err error) {
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssh dial: %w", err)
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, nil, nil, fmt.Errorf("new session: %w", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:  1,
		ssh.IGNCR: 1,
	}
	if err := session.RequestPty("vt100", 80, 40, modes); err != nil {
		session.Close()
		client.Close()
		return nil, nil, nil, fmt.Errorf("request pty: %w", err)
	}

	if solIn, err = session.StdinPipe(); err != nil {
		session.Close()
		client.Close()
		return nil, nil, nil, fmt.Errorf("stdin pipe: %w", err)
	}
	if solOut, err = session.StdoutPipe(); err != nil {
		session.Close()
		client.Close()
		return nil, nil, nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := session.Start("console com2"); err != nil {
		session.Close()
		client.Close()
		return nil, nil, nil, fmt.Errorf("start console com2: %w", err)
	}

	shutdown = func() { session.Close(); client.Close() }
	return shutdown, solIn, solOut, nil
}

// reconnectLoop dials iDRAC in a loop with exponential backoff, swapping
// the solIn writer and reading SOL output while connected.
func (b *bridge) reconnectLoop(addr string, sshConfig *ssh.ClientConfig) {
	const minBackoff = 2 * time.Second
	const maxBackoff = 30 * time.Second
	delay := minBackoff

	for {
		select {
		case <-b.quit:
			return
		default:
		}

		shutdown, solIn, solOut, err := connectSOL(addr, sshConfig)
		if err != nil {
			log.Printf("SOL connect failed: %v (retry in %v)", err, delay)
			sleepUntil(b.quit, delay)
			delay *= 2
			if delay > maxBackoff {
				delay = maxBackoff
			}
			continue
		}

		log.Printf("SOL connected")
		b.solIn.Swap(solIn)

		connectedAt := time.Now()
		b.readSOL(solOut)

		// Only reset backoff if the connection lasted a decent while.
		// Quick drops (e.g. iDRAC "already in use") should keep backing off.
		if time.Since(connectedAt) > 10*time.Second {
			delay = minBackoff
		} else {
			delay *= 2
			if delay > maxBackoff {
				delay = maxBackoff
			}
		}

		b.broadcastMsg("\r\n--- RECONNECTING ---\r\n")
		shutdown()

		log.Printf("reconnecting in %v", delay)
		sleepUntil(b.quit, delay)
	}
}

// swappableWriter wraps an io.Writer with a mutex so the underlying target
// can be atomically replaced (during reconnect) while concurrent io.Copy
// calls continue to write.
type swappableWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (sw *swappableWriter) Write(p []byte) (int, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.w.Write(p)
}

func (sw *swappableWriter) Swap(w io.Writer) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.w = w
}

// --- helpers (unchanged) ---

func expandPath(p string) string {
	if len(p) >= 2 && p[:2] == "~/" {
		u, err := user.Current()
		if err != nil {
			return p
		}
		return filepath.Join(u.HomeDir, p[2:])
	}
	return p
}

// resolveSSHConfig looks up the real host/port from ~/.ssh/config.
// If nothing found, returns the host as-is with port 22.
func resolveSSHConfig(host string) (string, int) {
	cfgPath := expandPath("~/.ssh/config")
	f, err := os.Open(cfgPath)
	if err != nil {
		return host, 22
	}
	defer f.Close()

	var (
		inHost       bool
		resolved     string = host
		resolvedPort int    = 22
	)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Very simple parser — good enough for ~/.ssh/config.
		trimmed := strings.TrimLeft(line, " \t")
		if len(trimmed) >= 5 && strings.EqualFold(trimmed[:5], "Host ") {
			inHost = false
			for _, pat := range strings.Fields(trimmed[5:]) {
				if pat == host {
					inHost = true
					break
				}
			}
			continue
		}
		if !inHost {
			continue
		}
		if key, val := sshKV(trimmed); key != "" {
			switch {
			case strings.EqualFold(key, "hostname"):
				resolved = val
			case strings.EqualFold(key, "port"):
				fmt.Sscanf(val, "%d", &resolvedPort)
			}
	}
	}
	return resolved, resolvedPort
}

// sshKV splits "Key value" or "Key=value" into key and value.
func sshKV(s string) (string, string) {
	i := strings.IndexAny(s, " \t=")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeft(s[i+1:], " \t=")
}

// sleepUntil sleeps for d or until quit is closed, whichever comes first.
func sleepUntil(quit <-chan struct{}, d time.Duration) {
	timer := time.NewTimer(d)
	select {
	case <-quit:
		timer.Stop()
	case <-timer.C:
	}
}
