package drivers

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	pagerRe = regexp.MustCompile(`(?i)(--\s*more\s*--|<---\s*more\s*--->|press any key to continue|---- more ----|\(q\)uit)`)
	ansiRe  = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]|\x1b[()][AB012]|\x08|\r")
	// defaultPrompt: the last line ends with >, #, ], $ or %.
	defaultPrompt = regexp.MustCompile(`(^|\n)[^\n]{0,80}[>#\]\$%] ?$`)
	enablePwRe    = regexp.MustCompile(`(?i)password:\s*$`)
)

// Clean removes terminal escapes, backspaces and carriage returns.
func Clean(s string) string { return ansiRe.ReplaceAllString(s, "") }

// SSH is a client connection with trust-on-first-use host key pinning: the
// key seen on the first successful connection is saved with the device;
// later connections are refused, before any credential is sent, when the
// server presents another one.
type SSH struct {
	t      Target
	c      Credentials
	port   int
	legacy bool

	mu       sync.Mutex
	client   *ssh.Client
	hostKey  string // learned (authorized_keys format)
	mismatch bool
}

// NewSSH returns a transport; legacy adds the old key exchanges and ciphers
// of older switches (group1 / group14 SHA-1, CBC, ssh-rsa / ssh-dss).
func NewSSH(t Target, c Credentials, legacy bool) *SSH {
	port := 22
	if t.Transport == "ssh" && t.Port > 0 {
		port = t.Port
	}
	return &SSH{t: t, c: c, port: port, legacy: legacy}
}

// HostKey is the key of the server seen on this connection.
func (s *SSH) HostKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hostKey
}

// SameKey compares two keys in authorized_keys format (type and blob).
func SameKey(a, b string) bool {
	fa, fb := strings.Fields(a), strings.Fields(b)
	return len(fa) >= 2 && len(fb) >= 2 && fa[0] == fb[0] && fa[1] == fb[1]
}

func (s *SSH) config() (*ssh.ClientConfig, error) {
	var auth []ssh.AuthMethod
	if s.c.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if s.c.Password != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(s.c.PrivateKey), []byte(s.c.Password))
			if err != nil {
				signer, err = ssh.ParsePrivateKey([]byte(s.c.PrivateKey))
			}
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(s.c.PrivateKey))
		}
		if err != nil {
			return nil, Errorf("%s: the SSH private key cannot be read (%v)", s.t.Host, err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if s.c.Password != "" {
		pw := s.c.Password
		auth = append(auth, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			out := make([]string, len(questions))
			for i := range out {
				out[i] = pw
			}
			return out, nil
		}))
	}
	cfg := &ssh.ClientConfig{
		User:    s.c.Username,
		Auth:    auth,
		Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.t.SSHHostKey != "" && !SameKey(s.t.SSHHostKey, got) {
				s.mismatch = true
				return errors.New("host key mismatch")
			}
			s.hostKey = got
			return nil
		},
	}
	if s.legacy {
		cfg.KeyExchanges = []string{ssh.KeyExchangeCurve25519, ssh.KeyExchangeECDHP256, ssh.KeyExchangeDH14SHA256,
			ssh.InsecureKeyExchangeDH14SHA1, ssh.KeyExchangeDHGEXSHA256, ssh.InsecureKeyExchangeDHGEXSHA1, ssh.InsecureKeyExchangeDH1SHA1}
		cfg.Ciphers = []string{ssh.CipherAES128CTR, ssh.CipherAES256CTR, ssh.CipherAES128GCM, ssh.InsecureCipherAES128CBC,
			ssh.InsecureCipherTripleDESCBC}
		cfg.HostKeyAlgorithms = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512,
			ssh.KeyAlgoRSA, ssh.InsecureKeyAlgoDSA}
	}
	if s.t.SSHHostKey != "" {
		// Offer the pinned key type first so the server shows the same key.
		if f := strings.Fields(s.t.SSHHostKey); len(f) > 0 {
			algos := cfg.HostKeyAlgorithms
			if algos == nil {
				algos = ssh.SupportedAlgorithms().HostKeys
			}
			cfg.HostKeyAlgorithms = pinAlgo(f[0], algos)
		}
	}
	return cfg, nil
}

// pinAlgo puts the algorithms of a key type first.
func pinAlgo(keyType string, algos []string) []string {
	want := []string{keyType}
	if keyType == ssh.KeyAlgoRSA {
		want = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	out := append([]string{}, want...)
	for _, a := range algos {
		dup := false
		for _, w := range want {
			dup = dup || a == w
		}
		if !dup {
			out = append(out, a)
		}
	}
	return out
}

// Connect opens the connection (once).
func (s *SSH) Connect(ctx context.Context) (*ssh.Client, error) {
	s.mu.Lock()
	if s.client != nil {
		c := s.client
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()
	cfg, err := s.config()
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(s.t.Host, strconv.Itoa(s.port))
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, Errorf("%s: SSH is unreachable (%v)", s.t.Host, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		s.mu.Lock()
		mismatch := s.mismatch
		s.mu.Unlock()
		switch {
		case mismatch:
			return nil, Errorf("%s: the SSH host key has changed. If the device was replaced, reset the saved key", s.t.Host)
		case strings.Contains(err.Error(), "unable to authenticate") || strings.Contains(err.Error(), "no supported methods"):
			return nil, Errorf("%s: SSH: wrong login, password or key", s.t.Host)
		}
		return nil, Errorf("%s: SSH is unreachable (%v)", s.t.Host, err)
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(cc, chans, reqs)
	s.mu.Lock()
	s.client = client
	s.mu.Unlock()
	return client, nil
}

// Run runs one command on an exec channel (Linux, RouterOS, OpenWrt, Junos).
func (s *SSH) Run(ctx context.Context, command string, timeout time.Duration) (string, error) {
	client, err := s.Connect(ctx)
	if err != nil {
		return "", err
	}
	sess, err := client.NewSession()
	if err != nil {
		s.Close()
		return "", Errorf("%s: %v", s.t.Host, err)
	}
	defer sess.Close()
	var stdout, stderr bytes.Buffer
	sess.Stdout, sess.Stderr = &stdout, &stderr
	done := make(chan error, 1)
	go func() { done <- sess.Run(command) }()
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case err = <-done:
	case <-t.C:
		_ = sess.Close()
		return "", Errorf("%s: command timed out", s.t.Host)
	case <-ctx.Done():
		_ = sess.Close()
		return "", ctx.Err()
	}
	out := stdout.String()
	if err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) || errors.Is(err, io.EOF) {
			if strings.TrimSpace(out) == "" {
				msg := strings.TrimSpace(stderr.String())
				if msg == "" && exit != nil {
					msg = "exit " + strconv.Itoa(exit.ExitStatus())
				}
				if msg != "" {
					return "", Errorf("%s: %s", s.t.Host, msg)
				}
			}
		} else if strings.TrimSpace(out) == "" {
			var missing *ssh.ExitMissingError
			if !errors.As(err, &missing) {
				return "", Errorf("%s: %v", s.t.Host, err)
			}
		}
	}
	return Clean(out), nil
}

// ShellOptions configure an interactive CLI session.
type ShellOptions struct {
	Prompt  *regexp.Regexp // default: a line ending with > # ] $ %
	Timeout time.Duration  // per command (default 60 s)
	Enable  string         // answered to "Password:" (enable mode)
	Answers []Answer       // confirmations ([confirm], [y/n]…)
}

// Answer replies to a question the device asks.
type Answer struct {
	Re    *regexp.Regexp
	Reply string
}

// Answers builds Answer from pattern → reply pairs (case-insensitive).
func Answers(pairs ...string) []Answer {
	var out []Answer
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, Answer{regexp.MustCompile("(?i)" + pairs[i]), pairs[i+1]})
	}
	return out
}

// Shell runs commands in an interactive CLI session for network OSes that do
// not run commands on an exec channel: it waits for the prompt after each
// command, answers pagers and questions, and returns one output per command
// (without the echoed command and the prompt). The connection is closed
// afterwards: network OSes drop it when the CLI session ends.
func (s *SSH) Shell(ctx context.Context, commands []string, o ShellOptions) ([]string, error) {
	client, err := s.Connect(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	sess, err := client.NewSession()
	if err != nil {
		return nil, Errorf("%s: %v", s.t.Host, err)
	}
	defer sess.Close()
	if err := sess.RequestPty("vt100", 1000, 250, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		return nil, Errorf("%s: %v", s.t.Host, err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := sess.Shell(); err != nil {
		return nil, Errorf("%s: %v", s.t.Host, err)
	}
	prompt := o.Prompt
	if prompt == nil {
		prompt = defaultPrompt
	}
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	chunks := make(chan string, 64)
	go func() {
		defer close(chunks)
		buf := make([]byte, 65536)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				chunks <- string(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	write := func(v string) { _, _ = io.WriteString(stdin, v) }
	matchPrompt := func(tail string) bool {
		return prompt.MatchString(strings.TrimRight(tail, " ")) || prompt.MatchString(tail)
	}
	readUntilPrompt := func(limit time.Duration) (string, error) {
		var buf strings.Builder
		deadline := time.Now().Add(limit)
		for {
			left := time.Until(deadline)
			if left <= 0 {
				return "", Errorf("%s: no CLI prompt (timed out)", s.t.Host)
			}
			wait := min(left, 1500*time.Millisecond)
			var chunk string
			var ok, timedOut bool
			select {
			case chunk, ok = <-chunks:
				if !ok {
					return Clean(buf.String()), nil
				}
			case <-time.After(wait):
				timedOut = true
			case <-ctx.Done():
				return "", ctx.Err()
			}
			full := buf.String()
			if timedOut {
				if matchPrompt(tail(Clean(full), 300)) {
					return Clean(full), nil
				}
				continue
			}
			buf.WriteString(chunk)
			full = buf.String()
			t := Clean(tail(full, 300))
			lines := strings.Split(t, "\n")
			if pagerRe.MatchString(lines[len(lines)-1]) {
				write(" ")
				cleaned := pagerRe.ReplaceAllString(full, "")
				buf.Reset()
				buf.WriteString(cleaned)
				continue
			}
			answered := false
			for _, a := range o.Answers {
				if a.Re.MatchString(t) {
					write(a.Reply + "\n")
					// drop the question so it is not matched again
					cut := strings.LastIndex(full, "\n")
					buf.Reset()
					if cut >= 0 {
						buf.WriteString(full[:cut+1])
					}
					answered = true
					break
				}
			}
			if answered {
				continue
			}
			if o.Enable != "" && enablePwRe.MatchString(t) {
				write(o.Enable + "\n")
				cut := strings.LastIndex(full, "\n")
				buf.Reset()
				if cut >= 0 {
					buf.WriteString(full[:cut+1])
				}
				continue
			}
			if matchPrompt(t) {
				return Clean(buf.String()), nil
			}
		}
	}
	if _, err := readUntilPrompt(20 * time.Second); err != nil {
		return nil, err
	}
	outputs := make([]string, 0, len(commands))
	for _, cmd := range commands {
		write(cmd + "\n")
		out, err := readUntilPrompt(o.Timeout)
		if err != nil {
			return outputs, err
		}
		lines := strings.Split(out, "\n")
		for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
			lines = lines[1:]
		}
		c := strings.TrimSpace(cmd)
		if len(c) > 20 {
			c = c[:20]
		}
		if len(lines) > 0 && c != "" && strings.Contains(lines[0], c) {
			lines = lines[1:]
		}
		if len(lines) > 0 && prompt.MatchString(lines[len(lines)-1]) {
			lines = lines[:len(lines)-1]
		}
		outputs = append(outputs, strings.Join(lines, "\n"))
	}
	write("exit\n")
	return outputs, nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// Close closes the connection.
func (s *SSH) Close() {
	s.mu.Lock()
	c := s.client
	s.client = nil
	s.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// Banner reads the SSH identification line of a server (discovery).
func Banner(ctx context.Context, host string, port int, timeout time.Duration) (string, bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	line, _, _ := strings.Cut(string(buf[:n]), "\n")
	return strings.TrimSpace(line), true
}

// KeyFingerprint is the SHA-256 fingerprint of a key in authorized_keys
// format ("" when it cannot be parsed).
func KeyFingerprint(key string) string {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		f := strings.Fields(key)
		if len(f) >= 2 {
			if b, err := base64.StdEncoding.DecodeString(f[1]); err == nil {
				if pk, err = ssh.ParsePublicKey(b); err == nil {
					return ssh.FingerprintSHA256(pk)
				}
			}
		}
		return ""
	}
	return ssh.FingerprintSHA256(pk)
}
