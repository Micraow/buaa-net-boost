// SPDX-License-Identifier: CC-BY-NC-4.0
//go:build linux

// spray-helper: privileged helper for same-5-tuple TCP SYN duplication.
//
// The helper owns only the AF_PACKET capture socket and the raw IPv6 send
// socket. It never accepts or owns the application's TCP connection: the
// proxy's own kernel socket connects, the helper only replays the captured
// SYN. Requests are accepted over a 0600 UNIX socket.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ethPAll    = 0x0003
	ethPIPv6   = 0x86dd
	ipProtoTCP = 6
	snapshot   = 262144
	maxPending = 8192
	maxCopies  = 32
)

type key struct {
	lport uint16
	dport uint16
	dst   [16]byte
}

type request struct {
	key      key
	copies   int
	interval time.Duration
	deadline time.Time
}

type helper struct {
	iface   string
	pf      int
	raw     int
	verbose bool
	mu      sync.Mutex
	pending map[key]*request
	sem     chan struct{}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func main() {
	var sockPath, iface string
	var concurrency int
	var verbose bool
	flag.StringVar(&sockPath, "socket", "/tmp/buaa-net-boost-spray.sock", "UNIX socket path")
	flag.StringVar(&iface, "iface", "wlan0", "capture and send interface")
	flag.IntVar(&concurrency, "concurrency", 256, "max concurrent sprays")
	flag.BoolVar(&verbose, "verbose", false, "log each sprayed flow")
	flag.Parse()

	if len(iface) == 0 || len(iface) >= unix.IFNAMSIZ {
		log.Fatalf("bad iface %q", iface)
	}
	if concurrency < 1 {
		concurrency = 1
	}
	h, err := newHelper(iface, concurrency)
	if err != nil {
		log.Fatal(err)
	}
	h.verbose = verbose
	go h.captureLoop()
	go h.reaper()
	if err := h.serve(sockPath); err != nil {
		log.Fatal(err)
	}
}

func newHelper(iface string, concurrency int) (*helper, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}
	pf, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET (需要 CAP_NET_RAW): %w", err)
	}
	if err := unix.Bind(pf, &unix.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  ifi.Index,
	}); err != nil {
		unix.Close(pf)
		return nil, fmt.Errorf("bind AF_PACKET %s: %w", iface, err)
	}
	_ = unix.SetsockoptInt(pf, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	if err := attachSYNFilter(pf); err != nil {
		unix.Close(pf)
		return nil, fmt.Errorf("attach SYN filter: %w", err)
	}

	raw, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		unix.Close(pf)
		return nil, fmt.Errorf("raw IPv6 (需要 CAP_NET_RAW): %w", err)
	}
	if err := unix.SetsockoptString(raw, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface); err != nil {
		unix.Close(pf)
		unix.Close(raw)
		return nil, fmt.Errorf("SO_BINDTODEVICE(%s): %w", iface, err)
	}
	_ = unix.SetsockoptInt(raw, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)

	return &helper{
		iface:   iface,
		pf:      pf,
		raw:     raw,
		pending: make(map[key]*request),
		sem:     make(chan struct{}, concurrency),
	}, nil
}

// attachSYNFilter keeps only IPv6/TCP/SYN packets. The offsets assume a
// 14-byte Ethernet header and no IPv6 extension headers, matching the
// capture/send path used by synspray.
func attachSYNFilter(fd int) error {
	prog := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 12},                        // ethertype
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 6, K: ethPIPv6},   // -> reject
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 20},                        // IPv6 next header
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 4, K: ipProtoTCP}, // -> reject
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 67},                        // TCP flags
		{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: 0x02},                     // SYN
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: 0x02},       // -> reject
		{Code: unix.BPF_RET | unix.BPF_K, K: snapshot},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
	fprog := &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, fprog)
}

func (h *helper) captureLoop() {
	buf := make([]byte, 65536)
	for {
		n, _, err := unix.Recvfrom(h.pf, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			log.Printf("recvfrom: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if n < 54+20 {
			continue
		}
		if buf[12] != 0x86 || buf[13] != 0xdd {
			continue
		}
		ip6 := buf[14:n]
		if len(ip6) < 40 || ip6[0]>>4 != 6 || ip6[6] != ipProtoTCP {
			continue
		}
		iplen := 40 + int(binary.BigEndian.Uint16(ip6[4:6]))
		if iplen > len(ip6) {
			iplen = len(ip6)
		}
		if iplen < 60 {
			continue
		}
		tcp := ip6[40:iplen]
		if len(tcp) < 20 || tcp[13]&0x02 == 0 {
			continue
		}
		srcPort := binary.BigEndian.Uint16(tcp[0:2])
		dstPort := binary.BigEndian.Uint16(tcp[2:4])
		var dst [16]byte
		copy(dst[:], ip6[24:40])
		k := key{lport: srcPort, dport: dstPort, dst: dst}

		h.mu.Lock()
		req := h.pending[k]
		if req != nil && time.Now().After(req.deadline) {
			delete(h.pending, k)
			req = nil
		}
		if req != nil {
			delete(h.pending, k)
		}
		h.mu.Unlock()
		if req == nil {
			continue
		}

		pkt := append([]byte(nil), ip6[:iplen]...)
		fixTCPChecksum(pkt)
		select {
		case h.sem <- struct{}{}:
			go func() {
				defer func() { <-h.sem }()
				h.sendCopies(pkt, req)
			}()
		default:
			log.Printf("spray drop: concurrency full")
		}
	}
}

func (h *helper) sendCopies(pkt []byte, req *request) {
	dst := &unix.SockaddrInet6{Port: 0}
	copy(dst.Addr[:], pkt[24:40])
	if h.verbose {
		log.Printf("spray %s:%d lport=%d copies=%d", net.IP(req.key.dst[:]), req.key.dport, req.key.lport, req.copies)
	}
	for i := 0; i < req.copies; i++ {
		if err := unix.Sendto(h.raw, pkt, 0, dst); err != nil {
			log.Printf("sendto: %v", err)
			return
		}
		if i+1 < req.copies {
			time.Sleep(req.interval)
		}
	}
}

func (h *helper) reaper() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		h.mu.Lock()
		for k, r := range h.pending {
			if now.After(r.deadline) {
				delete(h.pending, k)
			}
		}
		h.mu.Unlock()
	}
}

func (h *helper) serve(path string) error {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	log.Printf("spray-helper listening on %s iface=%s", path, h.iface)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go h.handleConn(c)
	}
}

func (h *helper) handleConn(c net.Conn) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 4096), 64*1024)
	w := bufio.NewWriter(c)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if line == "PING" {
			fmt.Fprintln(w, "OK")
			_ = w.Flush()
			continue
		}
		if line == "QUIT" {
			fmt.Fprintln(w, "OK")
			_ = w.Flush()
			return
		}
		parts := strings.Fields(line)
		if len(parts) != 7 || parts[0] != "SPRAY" {
			fmt.Fprintln(w, "ERR usage: SPRAY <target> <port> <lport> <copies> <interval_ms> <iface>")
			_ = w.Flush()
			continue
		}
		req, err := h.parseRequest(parts[1:])
		if err != nil {
			fmt.Fprintf(w, "ERR %v\n", err)
			_ = w.Flush()
			continue
		}
		if err := h.register(req); err != nil {
			fmt.Fprintf(w, "ERR %v\n", err)
			_ = w.Flush()
			continue
		}
		fmt.Fprintln(w, "OK")
		_ = w.Flush()
	}
}

func (h *helper) parseRequest(p []string) (*request, error) {
	if len(p) != 6 {
		return nil, fmt.Errorf("需要 6 个参数")
	}
	ip := net.ParseIP(p[0])
	if ip == nil || ip.To4() != nil || ip.To16() == nil {
		return nil, fmt.Errorf("目标必须是 IPv6 单播")
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return nil, fmt.Errorf("目标不是全局 IPv6 单播")
	}
	port, err := parsePort(p[1])
	if err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}
	lport, err := parsePort(p[2])
	if err != nil {
		return nil, fmt.Errorf("lport: %w", err)
	}
	copies, err := strconv.Atoi(p[3])
	if err != nil || copies < 1 || copies > maxCopies {
		return nil, fmt.Errorf("copies 必须在 1..%d", maxCopies)
	}
	interval, err := strconv.Atoi(p[4])
	if err != nil || interval < 5 || interval > 100 {
		return nil, fmt.Errorf("interval_ms 必须在 5..100")
	}
	if p[5] != h.iface {
		return nil, fmt.Errorf("iface %q 不是 helper 的 %q", p[5], h.iface)
	}
	var dst [16]byte
	copy(dst[:], ip.To16())
	return &request{
		key:      key{lport: uint16(lport), dport: uint16(port), dst: dst},
		copies:   copies,
		interval: time.Duration(interval) * time.Millisecond,
		deadline: time.Now().Add(2 * time.Second),
	}, nil
}

func (h *helper) register(req *request) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.pending) >= maxPending {
		return fmt.Errorf("pending full")
	}
	h.pending[req.key] = req
	return nil
}

func parsePort(s string) (int, error) {
	v, err := strconv.Atoi(s)
	if err != nil || v < 1 || v > 65535 {
		return 0, fmt.Errorf("必须在 1..65535")
	}
	return v, nil
}

func fixTCPChecksum(pkt []byte) {
	if len(pkt) < 60 {
		return
	}
	tcp := pkt[40:]
	tcpLen := len(tcp)
	tcp[16], tcp[17] = 0, 0

	var sum uint32
	sum = add16(pkt[8:40], sum) // IPv6 src + dst
	sum += uint32(tcpLen >> 16)
	sum += uint32(tcpLen & 0xffff)
	sum += ipProtoTCP
	sum = add16(tcp, sum)
	c := fold16(sum)
	tcp[16] = byte(c >> 8)
	tcp[17] = byte(c)
}

func add16(b []byte, sum uint32) uint32 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func fold16(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
