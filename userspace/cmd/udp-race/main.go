// SPDX-License-Identifier: CC-BY-NC-4.0
// udp-race: UDP source-port first-packet racing relay.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"buaa-net-boost/internal/race"
)

type flow struct {
	mu      sync.Mutex
	conn    *net.UDPConn
	ready   bool
	pending [][]byte
	closed  bool
}

type relay struct {
	listener *net.UDPConn
	target   *net.UDPAddr
	racer    *race.Racer
	n        int
	rounds   int
	timeout  time.Duration
	idle     time.Duration
	family   int
	iface    string
	verbose  bool
	window   *race.PortWindow
	sem      chan struct{}

	mu    sync.Mutex
	flows map[string]*flow
}

func main() {
	var (
		listen     int
		targetHost string
		targetPort int
		family     int
		n, rounds  int
		base, end  int
		step       int
		timeout    time.Duration
		idle       time.Duration
		iface      string
		noBind     bool
		verbose    bool
		flowsMax   int
	)
	flag.IntVar(&listen, "listen", 18081, "本地监听端口")
	flag.StringVar(&targetHost, "target", "", "目标 IP")
	flag.IntVar(&targetPort, "target-port", 0, "目标端口")
	flag.IntVar(&n, "n", 5, "每轮并行源端口数")
	flag.IntVar(&family, "family", 4, "IP family: 4 或 6")
	flag.IntVar(&rounds, "rounds", 1, "窗口轮数")
	flag.IntVar(&base, "base", 20000, "源端口起始")
	flag.IntVar(&end, "end", 32000, "源端口结束（不含）")
	flag.IntVar(&step, "step", 8, "窗口滚动步长")
	flag.DurationVar(&timeout, "timeout", 1200*time.Millisecond, "单轮竞速超时")
	flag.DurationVar(&idle, "idle", 60*time.Second, "流空闲回收")
	flag.StringVar(&iface, "iface", "", "绑定网卡（默认自动探测）")
	flag.BoolVar(&noBind, "no-bind", false, "不绑定网卡")
	flag.BoolVar(&verbose, "verbose", false, "打印竞速过程")
	flag.IntVar(&flowsMax, "flows", 512, "最大并发流数")
	flag.Parse()

	if targetHost == "" || targetPort < 1 || targetPort > 65535 {
		log.Fatalf("需要 --target 和 --target-port")
	}
	if family != 4 && family != 6 {
		log.Fatalf("--family 只能是 4 或 6")
	}
	ip, err := race.ResolveIP(targetHost, family)
	if err != nil {
		log.Fatalf("解析 %s: %v", targetHost, err)
	}
	target, err := net.ResolveUDPAddr(fmt.Sprintf("udp%d", family), net.JoinHostPort(ip, strconv.Itoa(targetPort)))
	if err != nil {
		log.Fatalf("目标: %v", err)
	}
	if noBind {
		iface = ""
	} else if iface == "" {
		iface = race.DefaultIface()
	}

	win, err := race.NewPortWindow(base, end, step, n)
	if err != nil {
		log.Fatalf("参数错误: %v", err)
	}
	// racer 仅用于统一的参数校验/日志接口；UDP 竞速在下面单独实现。
	racer, err := race.New(race.Config{
		N: n, Family: family, Rounds: rounds, Base: base, End: end, Step: step,
		Timeout: timeout, Iface: iface, Verbose: verbose, Logf: log.Printf,
	})
	if err != nil {
		log.Fatalf("参数错误: %v", err)
	}

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listen}
	ln, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	r := &relay{
		listener: ln,
		target:   target,
		racer:    racer,
		n:        n,
		rounds:   rounds,
		timeout:  timeout,
		idle:     idle,
		family:   family,
		iface:    iface,
		verbose:  verbose,
		window:   win,
		sem:      make(chan struct{}, max(1, flowsMax)),
		flows:    make(map[string]*flow),
	}
	log.Printf("listen 127.0.0.1:%d -> %s n=%d rounds=%d ports=[%d,%d) step=%d iface=%q",
		listen, target, n, rounds, base, end, step, iface)

	buf := make([]byte, 65535)
	for {
		nread, client, err := ln.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}
		data := append([]byte(nil), buf[:nread]...)
		r.dispatch(client, data)
	}
}

func (r *relay) dispatch(client *net.UDPAddr, data []byte) {
	key := client.String()
	r.mu.Lock()
	f := r.flows[key]
	if f != nil {
		f.mu.Lock()
		if f.ready && f.conn != nil {
			_, _ = f.conn.WriteToUDP(data, r.target)
		} else if len(f.pending) < 32 {
			f.pending = append(f.pending, data)
		}
		f.mu.Unlock()
		r.mu.Unlock()
		return
	}
	select {
	case r.sem <- struct{}{}:
	default:
		r.mu.Unlock()
		return
	}
	f = &flow{}
	r.flows[key] = f
	r.mu.Unlock()

	go r.startFlow(key, client, data, f)
}

func (r *relay) startFlow(key string, client *net.UDPAddr, first []byte, f *flow) {
	winner, reply, winPort := r.doRace(first)
	if winner == nil {
		log.Printf("FAIL %s -> %s", client, r.target)
		r.removeFlow(key, f)
		return
	}
	log.Printf("OK   %s -> %s", client, r.target)
	_, _ = r.listener.WriteToUDP(reply, client)
	_ = winner.SetReadDeadline(time.Now().Add(r.idle))

	f.mu.Lock()
	f.conn = winner
	f.ready = true
	pending := f.pending
	f.pending = nil
	f.mu.Unlock()

	for _, d := range pending {
		_, _ = winner.WriteToUDP(d, r.target)
	}

	buf := make([]byte, 65535)
	for {
		_ = winner.SetReadDeadline(time.Now().Add(r.idle))
		n, err := winner.Read(buf)
		if err != nil {
			break
		}
		_, _ = r.listener.WriteToUDP(buf[:n], client)
	}
	_ = winner.Close()
	if winPort > 0 {
		r.window.ReleasePort(winPort)
	}
	r.removeFlow(key, f)
}

func (r *relay) doRace(first []byte) (*net.UDPConn, []byte, int) {
	for round := 1; round <= r.rounds; round++ {
		base, ok := r.window.Take()
		if !ok {
			break
		}
		if r.verbose {
			log.Printf("[udp] window %d-%d (%d sockets)", base, base+r.n-1, r.n)
		}
		conns := make([]*net.UDPConn, 0, r.n)
		ports := make(map[*net.UDPConn]int)
		for i := 0; i < r.n; i++ {
			d := net.Dialer{
				LocalAddr: &net.UDPAddr{Port: base + i},
				Timeout:   r.timeout,
				Control:   race.BindControl(r.iface),
			}
			c, err := d.Dial(fmt.Sprintf("udp%d", r.family), r.target.String())
			if err != nil {
				continue
			}
			uc := c.(*net.UDPConn)
			if _, err := uc.Write(first); err != nil {
				_ = uc.Close()
				continue
			}
			conns = append(conns, uc)
			ports[uc] = base + i
		}

		type ures struct {
			conn *net.UDPConn
			data []byte
			err  error
		}
		ch := make(chan ures, len(conns))
		for _, c := range conns {
			go func(c *net.UDPConn) {
				buf := make([]byte, 65535)
				_ = c.SetReadDeadline(time.Now().Add(r.timeout))
				n, err := c.Read(buf)
				ch <- ures{conn: c, data: append([]byte(nil), buf[:n]...), err: err}
			}(c)
		}

		var winner *net.UDPConn
		var reply []byte
		winPort := 0
		for i := 0; i < len(conns); i++ {
			res := <-ch
			if res.err == nil && winner == nil {
				winner, reply = res.conn, res.data
				winPort = ports[winner]
				for _, c := range conns {
					if c != winner {
						_ = c.Close()
					}
				}
			} else if res.conn != winner {
				_ = res.conn.Close()
			}
		}
		if winner != nil {
			for c, p := range ports {
				if c != winner {
					r.window.ReleasePort(p)
				}
			}
			if r.verbose {
				log.Printf("[udp] round %d base=%d winner=%d", round, base, winPort)
			}
			return winner, reply, winPort
		}
		for _, p := range ports {
			r.window.ReleasePort(p)
		}
	}
	return nil, nil, 0
}

func (r *relay) removeFlow(key string, f *flow) {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	r.mu.Lock()
	if r.flows[key] == f {
		delete(r.flows, key)
	}
	r.mu.Unlock()
	<-r.sem
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
