// probe: benchmark source-port handshake racing.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"time"

	"buaa-net-boost/internal/race"
)

func main() {
	var (
		n, trials int
		family    int
		base, end int
		step      int
		timeout   time.Duration
		iface     string
		noBind    bool
	)
	flag.IntVar(&n, "n", 5, "每轮并行源端口数")
	flag.IntVar(&family, "family", 4, "IP family: 4 或 6")
	flag.IntVar(&trials, "trials", 10, "试验次数")
	flag.IntVar(&base, "base", 20000, "源端口起始")
	flag.IntVar(&end, "end", 32000, "源端口结束（不含）")
	flag.IntVar(&step, "step", 8, "窗口滚动步长")
	flag.DurationVar(&timeout, "timeout", 2*time.Second, "单轮竞速超时")
	flag.StringVar(&iface, "iface", "", "绑定网卡（默认自动探测）")
	flag.BoolVar(&noBind, "no-bind", false, "不绑定网卡")
	flag.Parse()

	if flag.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "用法: %s [flags] <host> <port>\n", os.Args[0])
		os.Exit(2)
	}
	host := flag.Arg(0)
	port, err := strconv.Atoi(flag.Arg(1))
	if err != nil || port < 1 || port > 65535 {
		log.Fatalf("端口非法")
	}
	ip, err := race.ResolveIP(host, family)
	if err != nil {
		log.Fatalf("解析 %s: %v", host, err)
	}
	if family != 4 && family != 6 {
		log.Fatalf("--family 只能是 4 或 6")
	}
	if noBind {
		iface = ""
	} else if iface == "" {
		iface = race.DefaultIface()
	}

	r, err := race.New(race.Config{
		N: n, Family: family, Rounds: 1, Base: base, End: end, Step: step,
		Timeout: timeout, Iface: iface, Verbose: true, Logf: log.Printf,
	})
	if err != nil {
		log.Fatalf("参数错误: %v", err)
	}

	var (
		ok      int
		times   []time.Duration
		winners []int
	)
	for i := 0; i < trials; i++ {
		c, lport, dt, _, err := r.Race(context.Background(), ip, port)
		if err != nil {
			log.Printf("trial %d FAIL: %v", i+1, err)
			continue
		}
		ok++
		times = append(times, dt)
		winners = append(winners, lport)
		race.CloseRST(c)
		r.ReleasePort(lport)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	median := time.Duration(0)
	if len(times) > 0 {
		median = times[len(times)/2]
	}
	fmt.Printf("target=%s:%d N=%d ok=%d/%d median=%s winners=%v\n",
		ip, port, n, ok, trials, median.Round(time.Millisecond), winners)
	_ = net.IPv4len
}
