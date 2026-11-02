// SPDX-License-Identifier: CC-BY-NC-4.0

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// SOCKS5 UDP ASSOCIATE. The TCP connection carries only the association
// lifetime; datagrams carry a SOCKS5 UDP header. The first datagram of a new
// flow is sent udpCopies times on the same upstream 5-tuple; later datagrams
// are sent once. Responses are de-duplicated by payload hash.
func (p *proxy) handleUDPAssociate(client *net.TCPConn, br *bufio.Reader) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Printf("[udp] listen: %v", err)
		return
	}
	defer relay.Close()
	addr := relay.LocalAddr().(*net.UDPAddr)
	if _, err := client.Write([]byte{
		5, 0, 0, 1, 127, 0, 0, 1, byte(addr.Port >> 8), byte(addr.Port),
	}); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(io.Discard, br)
	}()
	go func() {
		<-done
		_ = relay.Close()
	}()

	var mu sync.Mutex
	flows := make(map[string]*udpFlow)
	defer func() {
		mu.Lock()
		for _, f := range flows {
			f.close()
		}
		mu.Unlock()
	}()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				now := time.Now()
				mu.Lock()
				for k, f := range flows {
					if now.Sub(f.lastTime()) > 60*time.Second {
						f.close()
						delete(flows, k)
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, src, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 4 || buf[2] != 0 {
			continue
		}
		if !sameClientIP(src, client.RemoteAddr()) {
			continue
		}
		host, port, off, err := parseSocksUDPAddr(buf[:n])
		if err != nil || off >= n {
			continue
		}
		ip, err := p.resolve(host)
		if err != nil {
			log.Printf("[udp] resolve %s: %v", host, err)
			continue
		}
		key := src.String() + "|" + ip + ":" + strconv.Itoa(port)
		mu.Lock()
		f := flows[key]
		if f == nil {
			if len(flows) >= p.udpFlows {
				mu.Unlock()
				continue
			}
			f, err = newUDPFlow(relay, ip, port, src)
			if err != nil {
				mu.Unlock()
				log.Printf("[udp] flow %s:%d: %v", ip, port, err)
				continue
			}
			flows[key] = f
			if p.verbose {
				log.Printf("[udp] flow %s -> %s:%d", src, ip, port)
			}
		}
		mu.Unlock()

		data := append([]byte(nil), buf[off:n]...)
		copies := p.udpCopies
		if isLocalIP(ip) {
			copies = 1
		}
		f.send(data, copies, p.udpInterval)
	}
}

type udpFlow struct {
	relay  *net.UDPConn
	conn   *net.UDPConn
	client *net.UDPAddr
	target *net.UDPAddr
	mu     sync.Mutex
	first  bool
	last   time.Time
	seen   map[uint64]time.Time
}

func newUDPFlow(relay *net.UDPConn, ip string, port int, client *net.UDPAddr) (*udpFlow, error) {
	network := "udp6"
	if stringsHasDot(ip) {
		network = "udp4"
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	target, err := net.ResolveUDPAddr(network, net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	f := &udpFlow{
		relay:  relay,
		conn:   conn,
		client: client,
		target: target,
		first:  true,
		last:   time.Now(),
		seen:   make(map[uint64]time.Time),
	}
	go f.readLoop()
	return f, nil
}

func (f *udpFlow) send(data []byte, copies int, interval time.Duration) {
	f.mu.Lock()
	first := f.first
	f.first = false
	f.last = time.Now()
	f.mu.Unlock()

	if !first || copies <= 1 {
		_, _ = f.conn.WriteToUDP(data, f.target)
		return
	}
	go func() {
		for i := 0; i < copies; i++ {
			if _, err := f.conn.WriteToUDP(data, f.target); err != nil {
				return
			}
			if i+1 < copies {
				time.Sleep(interval)
			}
		}
	}()
}

func (f *udpFlow) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, _, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.last = time.Now()
		dup := f.dupLocked(buf[:n])
		f.mu.Unlock()
		if dup {
			continue
		}
		hdr := socksUDPHeader(f.target)
		out := make([]byte, 0, len(hdr)+n)
		out = append(out, hdr...)
		out = append(out, buf[:n]...)
		_, _ = f.relay.WriteToUDP(out, f.client)
	}
}

func (f *udpFlow) dupLocked(b []byte) bool {
	h := fnv.New64a()
	_, _ = h.Write(b)
	k := h.Sum64()
	now := time.Now()
	if t, ok := f.seen[k]; ok && now.Sub(t) < time.Second {
		return true
	}
	f.seen[k] = now
	if len(f.seen) > 1024 {
		for k, t := range f.seen {
			if now.Sub(t) > time.Second {
				delete(f.seen, k)
			}
		}
	}
	return false
}

func (f *udpFlow) lastTime() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

func (f *udpFlow) close() {
	_ = f.conn.Close()
}

func parseSocksUDPAddr(b []byte) (string, int, int, error) {
	if len(b) < 4 {
		return "", 0, 0, fmt.Errorf("short header")
	}
	if b[0] != 0 || b[1] != 0 {
		return "", 0, 0, fmt.Errorf("reserved")
	}
	if b[2] != 0 {
		return "", 0, 0, fmt.Errorf("fragmentation not supported")
	}
	switch b[3] {
	case 1:
		if len(b) < 10 {
			return "", 0, 0, fmt.Errorf("short IPv4")
		}
		return net.IP(b[4:8]).String(), int(binary.BigEndian.Uint16(b[8:10])), 10, nil
	case 4:
		if len(b) < 22 {
			return "", 0, 0, fmt.Errorf("short IPv6")
		}
		return net.IP(b[4:20]).String(), int(binary.BigEndian.Uint16(b[20:22])), 22, nil
	case 3:
		if len(b) < 5 {
			return "", 0, 0, fmt.Errorf("short domain")
		}
		l := int(b[4])
		if len(b) < 5+l+2 {
			return "", 0, 0, fmt.Errorf("short domain body")
		}
		return string(b[5 : 5+l]), int(binary.BigEndian.Uint16(b[5+l : 5+l+2])), 5 + l + 2, nil
	}
	return "", 0, 0, fmt.Errorf("unknown ATYP")
}

func socksUDPHeader(addr *net.UDPAddr) []byte {
	if ip4 := addr.IP.To4(); ip4 != nil {
		return []byte{0, 0, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], byte(addr.Port >> 8), byte(addr.Port)}
	}
	ip16 := addr.IP.To16()
	h := make([]byte, 0, 22)
	h = append(h, 0, 0, 0, 4)
	h = append(h, ip16...)
	h = append(h, byte(addr.Port>>8), byte(addr.Port))
	return h
}

func sameClientIP(src *net.UDPAddr, remote net.Addr) bool {
	ta, ok := remote.(*net.TCPAddr)
	if !ok {
		return false
	}
	return src.IP.Equal(ta.IP)
}

func stringsHasDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}
