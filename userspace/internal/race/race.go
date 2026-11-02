// SPDX-License-Identifier: CC-BY-NC-4.0
// Package race implements source-port-windowed TCP handshake racing.
package race

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const soBindToDevice = 25

// Sprayer registers a flow so a privileged helper can capture its SYN and
// replay it on the same 5-tuple. It must return after the helper has armed
// the capture, but before the caller starts DialContext.
type Sprayer interface {
	Register(ip string, port, lport int) error
}

// Config controls the racer.
type Config struct {
	N             int
	Family        int
	Rounds        int
	Base          int
	End           int
	Step          int
	Timeout       time.Duration
	Iface         string
	Verbose       bool
	Sprayer       Sprayer
	SprayCopies   int
	SprayInterval time.Duration
	Logf          func(format string, args ...any)
}

// PortWindow hands out non-overlapping source-port windows.
type PortWindow struct {
	start, end, step, n int
	cur                 int
	used                map[int]bool
	mu                  sync.Mutex
}

func NewPortWindow(start, end, step, n int) (*PortWindow, error) {
	if !(1024 <= start && start < end && end <= 65535) {
		return nil, fmt.Errorf("需要 1024 <= base < end <= 65535")
	}
	if step <= 0 {
		return nil, fmt.Errorf("step 必须 > 0")
	}
	if n <= 0 || n > step {
		return nil, fmt.Errorf("必须满足 0 < n <= step")
	}
	if start+n > end {
		return nil, fmt.Errorf("base + n 超过 end")
	}
	return &PortWindow{start: start, end: end, step: step, n: n, cur: start, used: map[int]bool{}}, nil
}

// Take 返回一个所有端口都未被占用的窗口；调用方必须对每个端口 ReleasePort。
func (w *PortWindow) Take() (int, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	span := w.end - w.start
	if span < w.n {
		return 0, false
	}
	for tries := 0; tries < span; tries++ {
		base := w.cur
		w.cur += w.step
		if w.cur+w.n > w.end {
			w.cur = w.start
		}
		if base+w.n > w.end {
			continue
		}
		free := true
		for i := 0; i < w.n; i++ {
			if w.used[base+i] {
				free = false
				break
			}
		}
		if !free {
			continue
		}
		for i := 0; i < w.n; i++ {
			w.used[base+i] = true
		}
		return base, true
	}
	return 0, false
}

func (w *PortWindow) ReleasePort(port int) {
	w.mu.Lock()
	delete(w.used, port)
	w.mu.Unlock()
}

// BindControl returns a Dialer.Control that binds the socket to iface.
func BindControl(iface string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if iface != "" {
				serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, soBindToDevice, iface)
			}
		}); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("SO_BINDTODEVICE(%s): %w (旧内核需要 CAP_NET_RAW；可用 --no-bind)", iface, serr)
		}
		return nil
	}
}

// DefaultIface6 finds the interface of the IPv6 default route.
func DefaultIface6() string {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return DefaultIface()
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 10 {
			continue
		}
		if p[0] != "00000000000000000000000000000000" || p[1] != "00" {
			continue
		}
		if p[9] != "" && p[9] != "lo" {
			return p[9]
		}
	}
	return DefaultIface()
}

// DefaultIface finds the interface of the IPv4 default route.
func DefaultIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		p := strings.Fields(sc.Text())
		if len(p) < 4 || p[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(p[3], 16, 32)
		if err == nil && flags&0x1 != 0 {
			return p[0]
		}
	}
	return ""
}

// ResolveIPv4 resolves host via the system resolver and returns an IPv4 string.
func ResolveIPv4(host string) (string, error) {
	return ResolveIP(host, 4)
}

// ResolveIP resolves host and picks an address of the requested family (4 or 6).
func ResolveIP(host string, family int) (string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if family == 6 {
			if ip.To4() == nil && ip.To16() != nil {
				return ip.String(), nil
			}
		} else if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("%s 没有 IPv%d 地址", host, family)
}

// Racer races N source ports per round.
type Racer struct {
	cfg Config
	win *PortWindow
	log func(format string, args ...any)
}

func New(cfg Config) (*Racer, error) {
	if cfg.Family == 0 {
		cfg.Family = 4
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2500 * time.Millisecond
	}
	if cfg.Rounds <= 0 {
		cfg.Rounds = 2
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	win, err := NewPortWindow(cfg.Base, cfg.End, cfg.Step, cfg.N)
	if err != nil {
		return nil, err
	}
	return &Racer{cfg: cfg, win: win, log: cfg.Logf}, nil
}

type attemptResult struct {
	conn  *net.TCPConn
	lport int
	err   error
}

func (r *Racer) attempt(ctx context.Context, ip string, port, base int) (*net.TCPConn, int, time.Duration, error) {
	start := time.Now()
	actx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	ch := make(chan attemptResult, r.cfg.N)
	var wg sync.WaitGroup
	for i := 0; i < r.cfg.N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lport := base + i
			defer func() {
				if r := recover(); r != nil {
					ch <- attemptResult{lport: lport, err: fmt.Errorf("panic: %v", r)}
				}
			}()
			isV6 := net.ParseIP(ip).To4() == nil
			network := "tcp4"
			if isV6 {
				network = "tcp6"
			}
			if isV6 && r.cfg.Sprayer != nil && r.cfg.SprayCopies > 0 {
				if err := r.cfg.Sprayer.Register(ip, port, lport); err != nil {
					r.log("[spray] port %d: %v", lport, err)
				}
			}
			d := net.Dialer{
				LocalAddr: &net.TCPAddr{Port: lport},
				Timeout:   r.cfg.Timeout,
				Control:   BindControl(r.cfg.Iface),
			}
			c, err := d.DialContext(actx, network, net.JoinHostPort(ip, strconv.Itoa(port)))
			if err != nil {
				ch <- attemptResult{lport: lport, err: err}
				return
			}
			tc := c.(*net.TCPConn)
			_ = tc.SetNoDelay(true)
			ch <- attemptResult{conn: tc, lport: lport}
		}(i)
	}

	if r.cfg.Verbose {
		r.log("[syn] window %d-%d (%d sockets)", base, base+r.cfg.N-1, r.cfg.N)
	}

	var winner *net.TCPConn
	var wport int
	var lastErr error
	for i := 0; i < r.cfg.N; i++ {
		res := <-ch
		if res.err != nil {
			lastErr = res.err
			if winner == nil && r.cfg.Verbose {
				r.log("[syn] port %d failed: %v", res.lport, res.err)
			}
			continue
		}
		if winner == nil {
			winner, wport = res.conn, res.lport
			cancel()
			if r.cfg.Verbose {
				r.log("[syn] port %d SYN-ACK at %s", wport, time.Since(start).Round(time.Millisecond))
			}
		} else {
			if r.cfg.Verbose {
				r.log("[syn] port %d also established, closing", res.lport)
			}
			CloseRST(res.conn)
		}
	}
	wg.Wait()

	for i := 0; i < r.cfg.N; i++ {
		p := base + i
		if p != wport {
			r.win.ReleasePort(p)
		}
	}

	if winner != nil {
		return winner, wport, time.Since(start), nil
	}
	if lastErr == nil {
		lastErr = context.DeadlineExceeded
	}
	return nil, 0, time.Since(start), lastErr
}

// Race tries up to Rounds windows and returns the first established connection.
func (r *Racer) Race(ctx context.Context, ip string, port int) (*net.TCPConn, int, time.Duration, int, error) {
	var total time.Duration
	var lastErr error
	for round := 1; round <= r.cfg.Rounds; round++ {
		var c *net.TCPConn
		var lport int
		var dt time.Duration
		var err error
		var base int
		for bindTry := 0; bindTry < 3; bindTry++ {
			var ok bool
			base, ok = r.win.Take()
			if !ok {
				lastErr = fmt.Errorf("没有空闲源端口")
				break
			}
			c, lport, dt, err = r.attempt(ctx, ip, port, base)
			total += dt
			if c != nil || !errors.Is(err, syscall.EADDRINUSE) {
				break
			}
			r.log("[race] base=%d 端口被占用，换窗口重试", base)
		}
		if r.cfg.Verbose {
			r.log("[race] round %d base=%d total=%s", round, base, total.Round(time.Millisecond))
		}
		if c != nil {
			return c, lport, total, round, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("竞速失败")
	}
	return nil, 0, total, r.cfg.Rounds, lastErr
}

// ReleasePort releases a winner port once its connection is closed.
func (r *Racer) ReleasePort(port int) {
	if port > 0 {
		r.win.ReleasePort(port)
	}
}

// CloseRST closes with RST instead of FIN.
func CloseRST(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}

// ResolveFast prefers a real IPv6 address but does not let a broken AAAA
// query block IPv4. A and AAAA are queried concurrently; AAAA gets a short
// budget and a short grace period before falling back to A.
func ResolveFast(ctx context.Context, host string, family int) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if family == 6 && ip.To4() == nil {
			return ip.String(), nil
		}
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
		return "", fmt.Errorf("%s 没有 IPv%d 地址", host, family)
	}
	if family == 4 {
		c, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		ips, err := net.DefaultResolver.LookupNetIP(c, "ip4", host)
		if err != nil || len(ips) == 0 {
			if err == nil {
				err = fmt.Errorf("%s 没有 IPv4 地址", host)
			}
			return "", err
		}
		return ips[0].String(), nil
	}

	type result struct {
		ip  string
		v6  bool
		err error
	}
	ch := make(chan result, 2)
	go func() {
		c, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		ips, err := net.DefaultResolver.LookupNetIP(c, "ip6", host)
		for _, ip := range ips {
			if ip.Is6() && !ip.Is4In6() {
				ch <- result{ip: ip.String(), v6: true}
				return
			}
		}
		ch <- result{v6: true, err: err}
	}()
	go func() {
		c, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		ips, err := net.DefaultResolver.LookupNetIP(c, "ip4", host)
		if len(ips) > 0 {
			ch <- result{ip: ips[0].String()}
			return
		}
		ch <- result{err: err}
	}()

	var v4 *result
	var lastErr error
	grace := time.NewTimer(25 * time.Millisecond)
	defer grace.Stop()
	for i := 0; i < 2; i++ {
		select {
		case r := <-ch:
			if r.err == nil && r.ip != "" {
				if r.v6 {
					return r.ip, nil
				}
				rr := r
				v4 = &rr
				continue
			}
			if r.err != nil {
				lastErr = r.err
			}
		case <-grace.C:
			if v4 != nil {
				return v4.ip, nil
			}
		}
	}
	if v4 != nil {
		return v4.ip, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%s 没有地址", host)
	}
	return "", lastErr
}
