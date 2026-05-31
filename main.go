// solbridge: SSH into iDRAC, run `console com2`, bridge to local TCP port.
//
// Usage: go run . localhost:2300   (listens on 2300, connects to blade.local)
//        go run . -host blade2.local :2301
//
// Once running, `nc localhost 2300` connects you to the serial console.
// Multiple concurrent nc sessions share the same SOL connection (output is broadcast).

package main

import (
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
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	sshHost := flag.String("host", "blade.local", "iDRAC SSH host (must be in ~/.ssh/config)")
	identityFile := flag.String("i", "~/.ssh/blade.local", "SSH identity file")
	userFlag := flag.String("u", "root", "SSH user")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: solbridge [-host HOST] [-i IDENTITY] [-u USER] LISTEN_ADDR\n")
		fmt.Fprintf(os.Stderr, "Example: solbridge localhost:2300\n")
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

	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		log.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("new session: %v", err)
	}
	defer session.Close()

	// Request PTY — iDRAC needs a terminal for console com2.
	modes := ssh.TerminalModes{
		ssh.ECHO:  1,
		ssh.IGNCR: 1,
	}
	if err := session.RequestPty("vt100", 80, 40, modes); err != nil {
		log.Fatalf("request pty: %v", err)
	}

	solIn, err := session.StdinPipe()
	if err != nil {
		log.Fatalf("stdin pipe: %v", err)
	}
	solOut, err := session.StdoutPipe()
	if err != nil {
		log.Fatalf("stdout pipe: %v", err)
	}

	if err := session.Start("console com2"); err != nil {
		log.Fatalf("start console com2: %v", err)
	}
	log.Printf("SOL session started — listening on %s", listenAddr)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Serialized writer for SOL stdin — prevents interleaving from concurrent clients.
	inMu := new(sync.Mutex)
	solInWriter := &lockedWriter{w: solIn, mu: inMu}

	// Fan-out: broadcast SOL output to all connected TCP clients.
	var (
		mu      sync.Mutex
		writers []io.Writer
	)

	// Read from SOL and broadcast to all connected TCP writers.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := solOut.Read(buf)
			if n > 0 {
				mu.Lock()
				active := writers[:0]
				for _, w := range writers {
					if _, werr := w.Write(buf[:n]); werr != nil {
						continue
					}
					active = append(active, w)
				}
				writers = active
				mu.Unlock()
			}
			if err != nil {
				log.Printf("sol read done: %v", err)
				return
			}
		}
	}()

	// Signal handling for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		log.Printf("client connected from %s", conn.RemoteAddr())

		mu.Lock()
		writers = append(writers, conn)
		mu.Unlock()

		// Read from TCP client → write to SOL stdin.
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(solInWriter, c)
			mu.Lock()
			for i, w := range writers {
				if w == c {
					writers = append(writers[:i], writers[i+1:]...)
					break
				}
			}
			mu.Unlock()
			log.Printf("client disconnected from %s", c.RemoteAddr())
		}(conn)
	}
}

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
		trimmed := trimLeft(line)
		if isHostDirective(trimmed) {
			inHost = matchesHost(trimmed, host)
			continue
		}
		if !inHost {
			continue
		}
		if key, val := splitKV(trimmed); key != "" {
			switch {
			case eqFold(key, "hostname"):
				resolved = val
			case eqFold(key, "port"):
				fmt.Sscanf(val, "%d", &resolvedPort)
			}
		}
	}
	return resolved, resolvedPort
}

func trimLeft(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}

func splitKV(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '=' {
			key := s[:i]
			// skip whitespace/equals
			for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '=') {
				i++
			}
			return key, s[i:]
		}
	}
	return s, ""
}

func isHostDirective(line string) bool {
	return len(line) >= 5 && (line[:5] == "Host " || line[:5] == "host ")
}

func matchesHost(line, target string) bool {
	// Parse space-separated patterns after "Host ".
	rest := line[5:]
	for _, pat := range splitFields(rest) {
		if pat == target {
			return true
		}
	}
	return false
}

func splitFields(s string) []string {
	var fields []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				fields = append(fields, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		fields = append(fields, s[start:])
	}
	return fields
}

func eqFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// lockedWriter serializes writes with a mutex to prevent interleaving.
type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}
