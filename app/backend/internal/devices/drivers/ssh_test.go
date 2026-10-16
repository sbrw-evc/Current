package drivers

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var iosOutput = map[string]string{"show version": iosVersion, "show interfaces": iosInterfaces, "show lldp neighbors detail": lldpDetail,
	"show cdp neighbors detail": cdpDetail, "show ip arp": arpIOS, "show mac address-table": macIOS,
	"show running-config": "hostname core-sw\n!\nend"}

// fakeDevice is an SSH server that behaves like Cisco IOS in an interactive
// shell and like a Linux host on an exec channel.
type fakeDevice struct {
	addr    string
	hostKey string
	mu      sync.Mutex
	log     []string // "shell <cmd>" / "exec <cmd>"
}

func (f *fakeDevice) record(s string) {
	f.mu.Lock()
	f.log = append(f.log, s)
	f.mu.Unlock()
}

func (f *fakeDevice) shellCommands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, l := range f.log {
		if c, ok := strings.CutPrefix(l, "shell "); ok {
			out = append(out, c)
		}
	}
	return out
}

func startFakeDevice(t *testing.T) *fakeDevice {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "admin" && string(pw) == "secret" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeDevice{addr: ln.Addr().String(), hostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c, cfg)
		}
	}()
	return f
}

func (f *fakeDevice) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, in, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for req := range in {
				switch req.Type {
				case "pty-req", "env":
					_ = req.Reply(true, nil)
				case "exec":
					var p struct{ Command string }
					_ = ssh.Unmarshal(req.Payload, &p)
					_ = req.Reply(true, nil)
					f.record("exec " + p.Command)
					if strings.Contains(p.Command, "#HOST") {
						_, _ = io.WriteString(ch, linuxOutput)
					} else {
						_, _ = io.WriteString(ch, "ok\n")
					}
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				case "shell":
					_ = req.Reply(true, nil)
					f.ios(ch)
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				default:
					_ = req.Reply(false, nil)
				}
			}
		}()
	}
}

func (f *fakeDevice) ios(ch ssh.Channel) {
	mode := ""
	w := func(s string) { _, _ = io.WriteString(ch, s) }
	w("\r\ncore-sw#")
	rd := bufio.NewReader(ch)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		f.record("shell " + cmd)
		w(cmd + "\r\n") // terminal echo
		switch {
		case cmd == "exit":
			if mode == "" {
				return
			}
			mode = ""
		case cmd == "configure terminal":
			mode = "(config)"
		case strings.HasPrefix(cmd, "interface "):
			mode = "(config-if)"
		case cmd == "end":
			mode = ""
		case cmd == "write memory":
			w("Building configuration...\r\n[OK]\r\n")
		case cmd == "reload":
			w("Proceed with reload? [confirm]")
			continue
		case iosOutput[cmd] != "":
			for _, l := range strings.Split(iosOutput[cmd], "\n") {
				w(l + "\r\n")
			}
		case cmd != "" && !hasPrefix(cmd, "terminal", "hostname", "ip name-server", "ntp", "no shutdown", "shutdown", "description"):
			w("% Invalid input detected at '^' marker.\r\n")
		}
		w(fmt.Sprintf("core-sw%s#", mode))
	}
}

func hasPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (f *fakeDevice) target(key string) Target {
	host, port, _ := net.SplitHostPort(f.addr)
	var n int
	_, _ = fmt.Sscan(port, &n)
	return Target{Host: host, Port: n, Transport: "ssh", SSHHostKey: key, Timeout: 10 * time.Second}
}

func TestCiscoIOSOverSSH(t *testing.T) {
	f := startFakeDevice(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, _ := Lookup("cisco_ios")
	creds := Credentials{Username: "admin", Password: "secret"}
	d, err := p.Driver(f.target(""), creds)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := d.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	learned := d.HostKey()
	d.Close()
	if !SameKey(learned, f.hostKey) {
		t.Fatalf("learned key %q, server %q", learned, f.hostKey)
	}
	if snap.Facts.Hostname != "core-sw" || snap.Facts.Model != "WS-C2960X-48TS-L" || len(snap.Interfaces) != 3 || *snap.Interfaces[0].RxBytes != 567890 {
		t.Fatalf("snapshot %+v", snap)
	}
	protos := map[string]bool{}
	for _, n := range snap.Neighbors {
		protos[n.Protocol] = true
	}
	if !protos["lldp"] || !protos["cdp"] || len(protos) != 2 {
		t.Fatalf("neighbors %+v", snap.Neighbors)
	}
	arp := map[string]bool{}
	for _, e := range snap.Endpoints {
		// Gi1/0/5 has a CDP neighbour (an AP): MACs learned there belong to the AP, not to the switch port.
		if e.Source == SourceBridge {
			t.Fatalf("bridge endpoint behind a neighbour: %+v", e)
		}
		if e.Source == SourceARP {
			arp[e.IP] = true
		}
	}
	if len(arp) != 2 || !arp["192.168.0.1"] || !arp["192.168.0.50"] {
		t.Fatalf("arp %v", arp)
	}

	d, _ = p.Driver(f.target(learned), creds)
	defer d.Close()
	ip, _ := ValidateAction(ActionInterface, Params{Name: "Gi1/0/2", Enabled: P(false), Description: P("spare")})
	out, err := d.Apply(ctx, ActionInterface, ip)
	if err != nil || out != "Done" {
		t.Fatalf("interface: %q %v", out, err)
	}
	cmds := f.shellCommands()
	i := slices.Index(cmds, "configure terminal")
	if i < 0 || !slices.Equal(cmds[i:i+6], []string{"configure terminal", "interface Gi1/0/2", "shutdown", "description spare", "exit", "end"}) ||
		!slices.Contains(cmds, "write memory") {
		t.Fatalf("commands %v", cmds)
	}
	if out, err := d.Apply(ctx, ActionCommand, Params{Command: "write memory"}); err != nil || !strings.Contains(out, "Building configuration") {
		t.Fatalf("command: %q %v", out, err)
	}
	if b, err := d.Backup(ctx); err != nil || !strings.HasPrefix(strings.TrimSpace(b), "hostname core-sw") {
		t.Fatalf("backup: %q %v", b, err)
	}
	if out, _ := d.Apply(ctx, ActionReboot, Params{}); out != "Reboot started" || !slices.Contains(f.shellCommands(), "reload") {
		t.Fatalf("reboot: %q", out)
	}
	if _, err := d.Apply(ctx, ActionFlowExport, Params{Collector: "10.0.0.1", Port: 2055, Protocol: "sflow"}); err == nil {
		t.Fatal("sFlow on IOS accepted")
	}

	// A changed host key is refused before any credential is sent.
	bad, _ := p.Driver(f.target("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGSKXBJ0rEZzAWS1thVXw7Jv8JpDh1Bx0+r8wnxOobpK"), creds)
	defer bad.Close()
	if _, err := bad.Collect(ctx); err == nil || !strings.Contains(err.Error(), "host key has changed") {
		t.Fatalf("host key mismatch: %v", err)
	}
}

func TestLinuxAndWrongPasswordOverSSH(t *testing.T) {
	f := startFakeDevice(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, _ := Lookup("linux")
	d, _ := p.Driver(f.target(""), Credentials{Username: "admin", Password: "secret"})
	snap, err := d.Collect(ctx)
	d.Close()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Facts.Hostname != "openwrt" || snap.Facts.Vendor != "Linux" {
		t.Fatalf("facts %+v", snap.Facts)
	}
	d, _ = p.Driver(f.target(""), Credentials{Username: "admin", Password: "nope"})
	defer d.Close()
	if _, err := d.Collect(ctx); err == nil || !strings.Contains(err.Error(), "wrong login") {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestSSHBanner(t *testing.T) {
	f := startFakeDevice(t)
	host, port, _ := net.SplitHostPort(f.addr)
	var n int
	_, _ = fmt.Sscan(port, &n)
	b, ok := Banner(context.Background(), host, n, 2*time.Second)
	if !ok || !strings.HasPrefix(b, "SSH-2.0-") {
		t.Fatalf("banner %q %v", b, ok)
	}
	if fp := KeyFingerprint(f.hostKey); !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("fingerprint %q", fp)
	}
}
