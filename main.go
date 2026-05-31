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
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	sshHost := flag.String("host", "", "iDRAC SSH host (resolved from ~/.ssh/config)")
	identityFile := flag.String("i", "", "SSH identity file")
	userFlag := flag.String("u", "root", "SSH user")
	solCmd := flag.String("cmd", "console com2", "iDRAC console command")
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

	// Resolve the host from ~/.ssh/config (purely for display + for ssh binary).
	finalHost, finalPort := resolveSSHConfig(*sshHost)
	addr := fmt.Sprintf("%s:%d", finalHost, finalPort)
	log.Printf("connecting to iDRAC at %s (%s)", *sshHost, addr)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	log.Printf("listening on %s", listenAddr)

	var wg sync.WaitGroup

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
		b.forceClose()
		ln.Close()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		b.reconnectLoop(*sshHost, *userFlag, keyPath, *solCmd)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			wg.Wait()
			break
		}
		log.Printf("client connected from %s", conn.RemoteAddr())

		b.mu.Lock()
		b.writers = append(b.writers, conn)
		b.mu.Unlock()

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
type shutdownFunc func()

type bridge struct {
	mu      sync.Mutex
	writers []io.Writer
	solIn   swappableWriter
	quit    chan struct{}

	shutdownMu sync.Mutex
	shutdown   shutdownFunc
}

func (b *bridge) forceClose() {
	b.shutdownMu.Lock()
	defer b.shutdownMu.Unlock()
	if b.shutdown != nil {
		b.shutdown()
		b.shutdown = nil
	}
}

func (b *bridge) setShutdown(f shutdownFunc) {
	b.shutdownMu.Lock()
	b.shutdown = f
	b.shutdownMu.Unlock()
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

// connectSOL spawns ssh to run "console com2" on the iDRAC and returns
// pipes for bidirectional I/O. Uses the system ssh binary because Go's
// SSH library doesn't handle iDRAC's exec channel quirks.
func connectSOL(host, user, keyPath, solCmd string) (shutdown func(), solIn io.WriteCloser, solOut io.Reader, err error) {
	_, port := resolveSSHConfig(host)
	target := host
	if port != 22 {
		target = fmt.Sprintf("%s:%d", host, port)
	}

	cmd := exec.Command("ssh",
		"-T",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-i", keyPath,
		user+"@"+target,
		solCmd,
	)

	cmd.Stderr = os.Stderr // ssh warnings go to our stderr

	solIn, err = cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssh stdin: %w", err)
	}
	solOut, err = cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssh stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, nil, fmt.Errorf("ssh start: %w", err)
	}

	shutdown = func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	}
	return shutdown, solIn, solOut, nil
}

// reconnectLoop dials iDRAC in a loop with exponential backoff, swapping
// the solIn writer and reading SOL output while connected.
func (b *bridge) reconnectLoop(host, user, keyPath, solCmd string) {
	const minBackoff = 2 * time.Second
	const maxBackoff = 30 * time.Second
	delay := minBackoff

	for {
		select {
		case <-b.quit:
			b.setShutdown(nil)
			return
		default:
		}

		shutdown, solIn, solOut, err := connectSOL(host, user, keyPath, solCmd)
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
		b.setShutdown(shutdown)
		b.solIn.Swap(solIn)

		connectedAt := time.Now()
		b.readSOL(solOut)

		if time.Since(connectedAt) > 10*time.Second {
			delay = minBackoff
		} else {
			delay *= 2
			if delay > maxBackoff {
				delay = maxBackoff
			}
		}

		b.broadcastMsg("\r\n--- RECONNECTING ---\r\n")
		b.setShutdown(nil)
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

// sleepUntil sleeps for d or until quit is closed, whichever comes first.
func sleepUntil(quit <-chan struct{}, d time.Duration) {
	timer := time.NewTimer(d)
	select {
	case <-quit:
		timer.Stop()
	case <-timer.C:
	}
}

// --- SSH config helpers ---

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
