// SPDX-License-Identifier: CC-BY-NC-4.0
// tcp-race: TCP source-port handshake racing proxy.
//
// Supports HTTP CONNECT, SOCKS5 CONNECT, and transparent mode.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"buaa-net-boost/internal/race"
)

type proxy struct {
	racer       *race.Racer
	family      int
	timeout     time.Duration
	sem         chan struct{}
	transparent bool
	n, rounds   int
	targetIP    string
	targetPort  int
	verbose     bool
	udpCopies   int
	udpInterval time.Duration
	udpFlows    int
}

func main() {
	var (
		listen        int
		n, rounds     int
		family        int
		base, end     int
		step          int
		threads       int
		timeout       time.Duration
		iface         string
		noBind        bool
		transparent   bool
		target        string
		verbose       bool
		spray         int
		sprayInterval time.Duration
		sprayHelper   string
		udpCopies     int
		udpInterval   time.Duration
		udpFlows      int
	)
	flag.IntVar(&listen, "listen", 18080, "本地监听端口")
	flag.IntVar(&n, "n", 5, "每轮并行源端口数")
	flag.IntVar(&family, "family", 4, "IP family: 4 或 6")
	flag.IntVar(&rounds, "rounds", 1, "窗口轮数")
	flag.IntVar(&base, "base", 20000, "源端口起始")
	flag.IntVar(&end, "end", 32000, "源端口结束（不含）")
	flag.IntVar(&step, "step", 8, "窗口滚动步长")
	flag.IntVar(&threads, "threads", 256, "最大并发连接数")
	flag.DurationVar(&timeout, "timeout", 1500*time.Millisecond, "单轮竞速超时")
	flag.StringVar(&iface, "iface", "", "绑定网卡（默认自动探测默认路由网卡）")
	flag.BoolVar(&noBind, "no-bind", false, "不绑定网卡")
	flag.BoolVar(&transparent, "transparent", false, "透明模式：不解析协议，直接转发到 --target")
	flag.StringVar(&target, "target", "", "透明模式目标 ip:port")
	flag.BoolVar(&verbose, "verbose", false, "打印每个源端口的 SYN 结果")
	flag.IntVar(&spray, "spray", 0, "每路径 SYN 复读份数（0 关闭，仅 IPv6）")
	flag.DurationVar(&sprayInterval, "spray-interval", 20*time.Millisecond, "SYN 复读间隔")
	flag.StringVar(&sprayHelper, "spray-helper", "/tmp/buaa-net-boost-spray.sock", "spray-helper UNIX socket")
	flag.IntVar(&udpCopies, "udp-copies", 16, "UDP 首包复读份数")
	flag.DurationVar(&udpInterval, "udp-interval", 20*time.Millisecond, "UDP 复读间隔")
	flag.IntVar(&udpFlows, "udp-flows", 512, "每个 UDP ASSOCIATE 的最大流数")
	flag.Parse()

	if family != 4 && family != 6 {
		log.Fatalf("--family 只能是 4 或 6")
	}
	if iface == "" {
		if family == 6 {
			iface = race.DefaultIface6()
		} else {
			iface = race.DefaultIface()
		}
	}
	helperIface := iface
	bindIface := helperIface
	if noBind {
		bindIface = ""
	}
	if bindIface == "" && !noBind {
		log.Printf("[warn] 未找到默认路由网卡，将不绑定网卡")
	}

	var sprayer race.Sprayer
	if spray > 0 {
		if family != 6 {
			log.Fatalf("--spray 只支持 --family 6")
		}
		if sprayInterval < 5*time.Millisecond || sprayInterval > 100*time.Millisecond {
			log.Fatalf("--spray-interval 必须在 5ms..100ms")
		}
		s, err := newUnixSprayer(sprayHelper, helperIface, spray, sprayInterval)
		if err != nil {
			log.Fatalf("spray helper: %v（先启动 spray-helper，或去掉 --spray）", err)
		}
		sprayer = s
		log.Printf("[spray] helper=%s iface=%s copies=%d interval=%s", sprayHelper, helperIface, spray, sprayInterval)
	}
	if udpCopies < 1 || udpCopies > 32 {
		log.Fatalf("--udp-copies 必须在 1..32")
	}
	if udpInterval < 5*time.Millisecond || udpInterval > 100*time.Millisecond {
		log.Fatalf("--udp-interval 必须在 5ms..100ms")
	}

	logf := log.Printf
	r, err := race.New(race.Config{
		N: n, Family: family, Rounds: rounds, Base: base, End: end, Step: step,
		Timeout: timeout, Iface: bindIface, Verbose: verbose, Logf: logf,
		Sprayer: sprayer, SprayCopies: spray, SprayInterval: sprayInterval,
	})
	if err != nil {
		log.Fatalf("参数错误: %v", err)
	}

	p := &proxy{
		racer:       r,
		family:      family,
		timeout:     timeout,
		sem:         make(chan struct{}, max(1, threads)),
		transparent: transparent,
		n:           n,
		rounds:      rounds,
		verbose:     verbose,
		udpCopies:   udpCopies,
		udpInterval: udpInterval,
		udpFlows:    max(1, udpFlows),
	}
	if transparent {
		ip, port, err := parseTarget(target, family)
		if err != nil {
			log.Fatalf("--target: %v", err)
		}
		p.targetIP, p.targetPort = ip, port
	}

	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", listen))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("listen 127.0.0.1:%d n=%d rounds=%d ports=[%d,%d) step=%d iface=%q transparent=%v target=%s:%d spray=%d udp=%d",
		listen, n, rounds, base, end, step, bindIface, transparent, p.targetIP, p.targetPort, spray, udpCopies)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go p.handle(c)
	}
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func (p *proxy) connect(ip string, port int) (*net.TCPConn, int, time.Duration, int, error) {
	network := "tcp4"
	if p.family == 6 {
		network = "tcp6"
	}
	// 回环/私网/链路本地不走校园出口，竞速没有意义，直接连。
	if isLocalIP(ip) {
		d := net.Dialer{Timeout: time.Second}
		c, err := d.Dial(network, net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			return nil, 0, 0, 0, err
		}
		return c.(*net.TCPConn), 0, 0, 0, nil
	}
	return p.racer.Race(context.Background(), ip, port)
}

func parseTarget(spec string, family int) (string, int, error) {
	host, portStr, err := net.SplitHostPort(spec)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("端口必须在 1..65535")
	}
	ip, err := race.ResolveIP(host, family)
	if err != nil {
		return "", 0, err
	}
	return ip, port, nil
}

func (p *proxy) handle(c net.Conn) {
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-time.After(time.Second):
		_ = c.Close()
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[panic] %v", r)
		}
	}()

	client, ok := c.(*net.TCPConn)
	if !ok {
		_ = c.Close()
		return
	}
	_ = client.SetNoDelay(true)
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(client, 4096)
	var upstream *net.TCPConn
	defer func() {
		if upstream != nil {
			race.CloseRST(upstream)
		}
		_ = client.Close()
	}()

	if p.transparent {
		up, lport, dt, round, err := p.connect(p.targetIP, p.targetPort)
		if err != nil {
			log.Printf("[transparent] FAIL -> %s:%d: %v", p.targetIP, p.targetPort, err)
			return
		}
		if lport > 0 {
			defer p.racer.ReleasePort(lport)
		}
		log.Printf("[transparent] OK -> %s:%d winner=%d round=%d t=%s",
			p.targetIP, p.targetPort, lport, round, dt.Round(time.Millisecond))
		upstream = up
		tunnel(client, br, upstream)
		return
	}

	first, err := br.Peek(1)
	if err != nil {
		return
	}
	socks := first[0] == 5

	var host string
	var port int
	var cmd byte = 1
	if socks {
		host, port, cmd, err = readSocks5(br, client)
		if err != nil {
			log.Printf("[socks5] parse: %v", err)
			return
		}
		if cmd == 3 {
			p.handleUDPAssociate(client, br)
			return
		}
	} else {
		host, port, err = readHTTPConnect(br)
		if err != nil {
			log.Printf("[http] parse: %v", err)
			_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
	}

	ip, err := race.ResolveIP(host, p.family)
	if err != nil {
		log.Printf("[resolve] %s: %v", host, err)
		if socks {
			socksReply(client, 0x04)
		} else {
			_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		}
		return
	}

	up, lport, dt, round, err := p.connect(ip, port)
	if err != nil {
		log.Printf("FAIL %s->%s:%d n=%d rounds=%d t=%s: %v",
			host, ip, port, p.n, p.rounds, dt.Round(time.Millisecond), err)
		if socks {
			socksReply(client, 0x05)
		} else {
			_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		}
		return
	}
	upstream = up
	if lport > 0 {
		defer p.racer.ReleasePort(lport)
	}

	log.Printf("OK   %s->%s:%d winner=%d round=%d t=%s", host, ip, port, lport, round, dt.Round(time.Millisecond))
	if socks {
		socksReply(client, 0x00)
	} else {
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	}
	tunnel(client, br, upstream)
}

func readHTTPConnect(br *bufio.Reader) (string, int, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", 0, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "CONNECT ") {
		return "", 0, fmt.Errorf("不是 CONNECT 请求")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", 0, fmt.Errorf("请求行不完整")
	}
	host, portStr, err := net.SplitHostPort(fields[1])
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("端口非法")
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return "", 0, err
		}
		if l == "\r\n" || l == "\n" {
			break
		}
		if len(l) > 8192 {
			return "", 0, fmt.Errorf("头部过大")
		}
	}
	return host, port, nil
}

func readSocks5(br *bufio.Reader, client *net.TCPConn) (string, int, byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return "", 0, 0, err
	}
	if hdr[0] != 5 {
		return "", 0, 0, fmt.Errorf("不是 SOCKS5")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return "", 0, 0, err
	}
	ok := false
	for _, m := range methods {
		if m == 0 {
			ok = true
			break
		}
	}
	if !ok {
		_, _ = client.Write([]byte{5, 0xff})
		return "", 0, 0, fmt.Errorf("没有可接受的认证方法")
	}
	_, _ = client.Write([]byte{5, 0})

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return "", 0, 0, err
	}
	if req[0] != 5 {
		return "", 0, 0, fmt.Errorf("版本错误")
	}
	cmd := req[1]
	if cmd != 1 && cmd != 3 {
		_, _ = client.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", 0, 0, fmt.Errorf("不支持的命令")
	}

	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", 0, 0, err
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return "", 0, 0, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return "", 0, 0, err
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", 0, 0, err
		}
		host = net.IP(b).String()
	default:
		return "", 0, 0, fmt.Errorf("未知 ATYP")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return "", 0, 0, err
	}
	return host, int(pb[0])<<8 | int(pb[1]), cmd, nil
}

func socksReply(c *net.TCPConn, rep byte) {
	_, _ = c.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
}

func tunnel(client *net.TCPConn, br *bufio.Reader, upstream *net.TCPConn) {
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	_ = client.SetNoDelay(true)
	_ = upstream.SetNoDelay(true)

	// 把 CONNECT/SOCKS5 之后已缓冲的应用字节先送出去，再走 splice 快路径。
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		if _, err := upstream.Write(b); err == nil {
			_, _ = br.Discard(n)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[panic] pipe: %v", r)
			}
		}()
		_, _ = io.Copy(upstream, client)
		_ = upstream.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[panic] pipe: %v", r)
			}
		}()
		_, _ = io.Copy(client, upstream)
		_ = client.CloseWrite()
	}()
	wg.Wait()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var _ = os.Exit
