// SPDX-License-Identifier: CC-BY-NC-4.0

package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// unixSprayer is a thin client for the privileged spray-helper. It keeps one
// persistent UNIX-socket connection; the helper arms a capture for the source
// port before the proxy calls DialContext, so the kernel's SYN is not missed.
type unixSprayer struct {
	mu       sync.Mutex
	conn     net.Conn
	br       *bufio.Reader
	path     string
	iface    string
	copies   int
	interval time.Duration
}

func newUnixSprayer(path, iface string, copies int, interval time.Duration) (*unixSprayer, error) {
	s := &unixSprayer{
		path:     path,
		iface:    iface,
		copies:   copies,
		interval: interval,
	}
	if err := s.connect(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *unixSprayer) connect() error {
	c, err := net.DialTimeout("unix", s.path, time.Second)
	if err != nil {
		return err
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(c)
	if _, err := fmt.Fprintln(c, "PING"); err != nil {
		_ = c.Close()
		return err
	}
	line, err := br.ReadString('\n')
	if err != nil {
		_ = c.Close()
		return err
	}
	if strings.TrimSpace(line) != "OK" {
		_ = c.Close()
		return fmt.Errorf("helper PING: %s", strings.TrimSpace(line))
	}
	s.conn, s.br = c, br
	return nil
}

func (s *unixSprayer) close() {
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.conn, s.br = nil, nil
}

// Register implements race.Sprayer.
func (s *unixSprayer) Register(ip string, port, lport int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		if s.conn == nil {
			if err := s.connect(); err != nil {
				return err
			}
		}
		_ = s.conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err := fmt.Fprintf(s.conn,
			"SPRAY %s %d %d %d %d %s\n",
			ip, port, lport, s.copies, int(s.interval/time.Millisecond), s.iface)
		if err != nil {
			s.close()
			continue
		}
		line, err := s.br.ReadString('\n')
		if err != nil {
			s.close()
			continue
		}
		line = strings.TrimSpace(line)
		if line != "OK" {
			return fmt.Errorf("helper: %s", line)
		}
		_ = s.conn.SetDeadline(time.Time{})
		return nil
	}
	return fmt.Errorf("helper connection lost")
}
