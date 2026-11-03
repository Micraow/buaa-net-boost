# 不开 TUN 的客户端研究：协议层还能改什么

日期：2026-11-03。目标：在不开 mihomo TUN 时，用独立的本地代理/协议栈获得收益；
同时评估 KCP、用户态 TCP、QUIC、QoS/DSCP、协议伪装、连接池等方案是否值得做。

## 1. 当前路径与瓶颈

链路本身已经很好：

- Wi-Fi `BUAA-Mobile`，5745MHz，400Mbps VHT-MCS9 40MHz，信号 -55dBm；
  `tx retries / tx failed / beacon loss` 全 0；连接约 22 小时。
- IPv4 `223.5.5.5`：0% 丢包，5.4–6.7ms；校园 DNS 2.3–4.0ms。
- IPv6 TUNA `2402:f000:1:400::2`：0% 丢包，3.2–4.3ms；阿里 v6 3.1–4.5ms。
- MTU 1500；`ping -M do -s 1472/1452` 都通；`power_save` 已 off；qdisc noqueue。
- 当前 TCP 连接 `rtt 5.7ms、cwnd 10、0 retrans`。
- 系统累计 `TcpExtTCPSynRetrans=29156`、`TCPLostRetransmit=30376`、
  `TCPTimeouts=32622`（22 小时），说明历史上的主要问题是 **新流 SYN/首包**，
  不是链路稳态。
- `tcp_available_congestion_control` 现在含 `bbr`，默认仍是 `cubic`。
- 还有一条挂住的旧 proxy 连接 `rtt 97ms、cwnd 2、923 次重传`；keep-alive
  槽位需要 idle timeout/清理。

结论：**物理层/MTU/Wi-Fi 没有可挖的；剩余收益集中在 DNS、新连接建立/复用、
协议栈行为和并发流。**

## 2. TUN 开/关时的路径差异

### TUN 开

```text
App -> mihomo TUN (mixed stack) -> SOCKS5 outbound (校内 IPv4 中转)
    -> 中转 -> 目标
```

- App 的 TCP 在 mihomo 用户态栈终止；mihomo 对每个 app 连接新建到校内
  SOCKS5 的 TCP；中转再新建到目标的 TCP。
- 我们那个本地 `tcp-race` 代理**不在路径里**，所以它的连接池/预热没有用。
- mihomo 已经开了 `tcp-concurrent: true`、`unified-delay: true`、`sniffer`；
  TUN `stack: mixed`（当前配置 `tun.enable` 实际是 false，开启时才生效）。
- 能改的是 mihomo：DNS/DoH、`tcp-concurrent`、sniffer、TUN stack、MTU/GSO、
  keep-alive；以及中转侧（用户不一定控制）。

### TUN 关

```text
App/Browser -> 127.0.0.1:18080 (tcp-race HTTP CONNECT/SOCKS5)
            -> TCP SYN 复读/双路径 -> 目标
```

- 这时本地代理**在路径里**，连接池/预热、DNS、spray、UDP ASSOCIATE、
  socket buffer、DSCP 都可以由我们控制。
- 应用需要显式配代理（浏览器 HTTP/SOCKS5、curl `-x`）；这是不开 TUN 的代价。

## 3. 协议层方案矩阵

| 方案 | 现在值得做？ | 原因 | 公平性/风险 |
|---|---|---|---|
| **DNS/DoH + A/AAAA 快速回退** | **是** | DeepSeek LCP 1700→516ms；UDP 53 的 AAAA 被过滤，DoH 53ms 正常 | 无，绕开过滤 |
| **TUN 关时的预热连接池** | **是，但有限** | 只能预热“空闲未用”的 TCP；TCP 不能把已传数据的连接复用给新流；对二次访问/热门目标有效 | 低，占少量服务器连接 |
| **SYN 复读/双路径（已有）** | **是** | 新流前 K 包丢失；2×8 实测 50/50 | 中，增加 SYN；你已接受 |
| **TCP 参数**（`tcp_slow_start_after_idle=0`、`tcp_notsent_lowat`、`tcp_mtu_probing`、`tcp_fastopen`） | **可试** | keep-alive 后不慢启动、MTU 探测、握手；收益小到中 | 低 |
| **BBR** | **否（当前链路）** | 0% 丢包、3–6ms；BBR 不会比 cubic 快，可能更激进/更差 | 高，挤占 cubic |
| **并行连接/多流** | **按站点** | 多 5 元组/ECMP；对坏路径/单流限速有效 | **高，抢份额**；只在坏站点短时开 |
| **KCP** | **否** | 可靠 UDP ARQ，适合高丢包/高 RTT；当前 0% 丢包、3–6ms；需要服务端；会增带宽 | 高，且对好链路是倒退 |
| **用户态 TCP（gVisor/smoltcp）** | **只在端点可控时** | mihomo TUN 已用 mixed 栈；它改的是 app↔mihomo 的本地 TCP，不改校内中转/目标那两段 | 中；CPU 更高，收益不确定 |
| **QUIC/HTTP3** | **协议层可行，客户端受限** | 需要 SOCKS5 UDP ASSOCIATE/TUN；Chrome SOCKS5 不代理 UDP；需要支持 UDP 的客户端 | 中；UDP 逐包用户态，CPU 高 |
| **DSCP/QoS 标记** | **先测** | 校园/AP 很可能不认 EF/AF；标记可能只在本地队列生效 | 若被识别，会不公平；先 A/B |
| **协议伪装（fake TLS/QUIC、域前置）** | **不建议** | 没有证据表明校园按协议/端口限速；伪装可能违反校园政策，且增加复杂度 | 高；不做规避审计/计费 |
| **Wi-Fi/MTU/qdisc** | **已经最优** | 400Mbps、0 retries、MTU 1500、noqueue、power_save off | 无 |

## 4. 不开 TUN 的落地方案

```bash
# helper（只 TCP SYN）
sudo setcap cap_net_raw+ep userspace/bin/spray-helper
userspace/bin/spray-helper --socket /tmp/buaa-net-boost-spray.sock --iface wlan0 &

# 代理
userspace/bin/tcp-race \
  --listen 18080 --family 6 --n 2 --rounds 1 --timeout 3s \
  --spray 8 --spray-interval 20ms \
  --spray-helper /tmp/buaa-net-boost-spray.sock \
  --iface wlan0 --no-bind

# 应用/浏览器代理填 127.0.0.1:18080
curl -x http://127.0.0.1:18080 https://目标/
```

不开 TUN 时建议加的开关（研究中）：

- `--dns-doh=https://doh.pub/dns-query`：绕开 UDP 53 的 AAAA 过滤；
- `--prewarm N`：对热门目标保持 N 条空闲上游 TCP（仅 TUN 关时有效）；
- `--dscp EF|AF41`：A/B 校园是否认；
- `--parallel N`：按站点短时并行流（不公平，慎用）。

## 5. 研究矩阵与指标

变体：

1. 直连（无代理）
2. 本地代理（kernel TCP + 2×8 spray）
3. + DoH（A/AAAA 走 443）
4. + 预热连接池
5. + DSCP（EF/AF41）
6. + 并行 N=2/4/8
7. + BBR（仅在上游 socket）
8. + 用户态 TCP（gVisor）——只有端点可控时
9. KCP/QUIC 隧道——需要服务端，当前不做

指标：

- 新流成功率、TTFB、LCP、DOM/load；
- 100MB 上传/下载吞吐、CPU/RSS；
- `TcpExtTCPSynRetrans`/`TcpExtTCPLostRetransmit`/`TCPTimeouts` 的每轮增量；
- 额外 SYN/首包数、服务器连接数、公平性（同链路其他流的吞吐变化）。

目标：TUNA、Cloudflare Speed、DeepSeek、Comate、Baidu，IPv4/IPv6 分开。

## 6. 已有数据（TUN 关，本地代理）

- 浏览器：DeepSeek LCP 1700→516ms，Comate 582→340ms；USTC/百度/Bing 持平；
  Cloudflare Speed 因 challenge 轻微变慢。
- 100MB 3 轮：下载直连 17.61 vs 代理 17.52 MB/s（0.5%）；上传直连 15.86 vs
  代理 14.90 MB/s（6%，一次代理 16.37 高于直连）。
- UDP DNS：单包 15/50，16 连发 50/50，中位 65.7ms；代理 CPU 2%。
- DeepSeek AAAA：UDP 53 被 Tencent/阿里/校园/114/Google 过滤；DoH 53ms 正常；
  域名 AAAA 目标本身没有 AAAA。

## 7. 推荐

**先做（不开 TUN 也有效）：**

1. DoH + A/AAAA 快速回退（已做 200ms+25ms 缓存；可加 DoH 开关）；
2. 热门目标预热连接池（TUN 关时才有意义）；
3. 现有 2×8 SYN 复读 + 16 UDP 首包；
4. `tcp_slow_start_after_idle=0`、`tcp_mtu_probing=1`、`tcp_notsent_lowat`。

**按站点/时段试，不全局开：**

5. 并行 N>2、DSCP 标记；
6. 上游 BBR（仅在有丢包/高 RTT 的路径）。

**不做：**

7. 当前链路 KCP（0% 丢包，纯增开销）；
8. 协议伪装/域前置（无证据、政策风险）；
9. 用客户端做 DoS、绕过计费、对第三方批量探测。

“不公平”的边界：BBR、并行流、更多 SYN 会抢份额，这在你自己的网络里可以 A/B；
但不要把它们变成对校园出口/目标服务器的攻击，也不要用来规避计费和审计。
