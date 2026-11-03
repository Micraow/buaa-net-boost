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

## 8. 150Mbps AC 限速实验（NIC 按请求设置）

目标：判断限速是 per-flow 还是 per-client/AC，以及 DSCP/并行/协议能否超过。

| 测试 | 结果 |
|---|---|
| 单流 TCP 100MB 下载 | **18.5 MB/s ≈ 148 Mbps** |
| 2 流并发 | 17.5 MB/s |
| 4 流并发 | 17.3 MB/s |
| 8 流并发 | 17.6 MB/s |
| DSCP EF | 16.7 MB/s |
| DSCP 默认 | 18.2 MB/s |
| 单流上传 | 约 15.9 MB/s |
| 4 流上传并发 | 12.46 MB/s |
| QUIC/HTTP3（Cloudflare `__down`） | HTTP 403，样本无效 |

结论：

- 限速是 **per-client 聚合**，不是 per-flow。单流已经贴着 150Mbps；2/4/8 并发都没有
  超过单流，反而略低。并行流不能把总带宽乘上去。
- DSCP EF 没有收益（16.7 vs 18.2，且是单次；至少没有正向效果），AC 很可能不认
  DSCP 或不做优先队列。
- 上传方向同样没有聚合增益（4 流 12.46 MB/s）。
- 正确测 QUIC 需要一个返回大文件且支持 HTTP/3 的目标；Cloudflare `__down` 返回 403，
  不能拿它下结论。但限速发生在 AC/STA 聚合层时，QUIC 也大概率同样受限。
- 要通过客户端协议“超过 per-station 聚合限速”，只能换 station/账号/AC 策略，或者
  伪造 MAC/IP；后者是规避/滥用，不做。合法路径是让 NIC 调整 AC 限速策略。
- 客户端软件仍能改善 **延迟/连接成功率/体验**（DNS、SYN 复读、预热、TCP 参数），
  但不能提高这条 150Mbps 的聚合上限；单流 18.5 MB/s 已经接近该上限。

### 双 vif / 真实 MAC 实验（已还原）

- Intel Wi-Fi 支持 `managed <= 2`；在 `wlan0` 之外创建 `wlan0b`，用本机有线网卡的
  真实 MAC（具体地址不记录），克隆同一 `BUAA-Mobile` PEAP 配置；两个接口各自拿到
  独立 IPv4/IPv6。
- 认证 MAC 是两个不同的 MAC；EAP 用户名/密码相同。AC 看到的是“不同 MAC、同一账号”；
  如果按用户限速，两个会话共享；如果按 MAC 限速，第二个 station 有自己的桶。
- 测速：`wlan0` 单流 16.27 MB/s；`wlan0b` 单流 11.66 MB/s；两个 vif 同时跑
  100MB 聚合 **8.93 MB/s**。没有叠加，反而互相拖慢——同一射频/同一信道共享空口，
  两个 managed vif 不是一个独立射频。
- 结论：在这块单射频硬件上，MAC/vif 不能突破 150Mbps 的 per-client 限速；如果 AC
  是 per-MAC，第二个 station 的桶也被同一空口/AP 调度限制。要验证是否 per-MAC，需要
  第二个物理射频/有线口/另一个账号，而不是同一个射频上的第二个 vif。
- 实验后已删除 `wlan0b` 和临时连接，`wlan0`/`BUAA-Mobile` 恢复；TUNA 访问 200。

### 跨 SSID / 跨信道 vif 实验（已还原）

- `wlan0`: BUAA-WiFi，5GHz 5745MHz（BSSID ...92）。
- `wlan0b`: BUAA-Mobile，先同 5GHz 5745（BSSID ...93），后切 2.4GHz 2437（BSSID ...83）。
- 认证 MAC 不同，EAP 账号相同；两个接口各自独立 IPv4/IPv6。
- 同 5GHz/同 AP：wlan0 16.27、wlan0b 11.66、并发 8.93 MB/s。
- 5GHz WiFi + 2.4GHz Mobile：wlan0 12.08、wlan0b 4.38、并发 10.31 MB/s。
- 结论：两个 managed vif 共享同一射频/天线/空口；`#channels <=2` 是分时切信道，
  不是 2 倍空口。跨 SSID/跨信道也没有叠加，反而拖慢 5GHz。per-MAC 桶即使存在，
  也被单射频的 airtime 限制；要叠加需要第二个物理射频（USB Wi-Fi/有线）或另一台设备，
  不是同一个射频上的 vif。
- vif 的用途：在一个物理 WLAN 设备上同时提供多个逻辑接口/角色（STA+AP 热点、
  STA+P2P、两个 STA、mesh/monitor、网络命名空间/测试），每个 vif 有独立 MAC；
  它不是第二个射频，不保证带宽叠加。
- 实验后已删除 `wlan0b` 和临时连接，BUAA-WiFi 恢复，TUNA 200。

### 空闲 vif 对主链路的影响

- `wlan0b` 不存在：5GHz 中位 17.49 MB/s（18.68/17.49/17.63）。
- `wlan0b` 关联同 5GHz、完全空闲：5GHz 中位 17.49 MB/s（18.08/17.49/14.40）。
- `wlan0b` 关联 2.4GHz、完全空闲：5GHz 中位 16.04 MB/s（14.29/16.04/17.41）。
- 结论：vif 存在/关联本身没有明显拖慢；之前 12.08 是 `wlan0b` 有实际流量时的
  射频分时/空口竞争，不是“配置漏了 MAC”。2.4GHz 那路 PHY 只有 104/52Mbps，
  单流 4.38 MB/s 接近 2.4GHz PHY 上限；5GHz 主链路的 150Mbps 上限不变。
- 要真正叠加，需要第二个物理射频（USB Wi-Fi）或另一个 AP/频段，而不是同一个
  Intel 射频上的 vif；vif 的设计是并发角色（STA+AP/P2P/两个 STA），不是多射频。

### 两个不同 5GHz AP 的实验（已还原）

- `wlan0`: BUAA-WiFi，5745MHz（AP BSSID ...92）；`wlan0b`: BUAA-Mobile，5765MHz
  （另一个 AP，BSSID ...53）。
- 关联后 `wlan0` 的 TX 384/108Mbps、`wlan0b` 216/26Mbps；单射频为两个 vif
  分时切信道，两个 vif 的 PHY 速率都被压低。
- 测速：`wlan0` 14.35 MB/s，`wlan0b` 11.54 MB/s，两个并发 **11.98 MB/s**；
  没有叠加，反而低于单独 `wlan0`。
- 结论：即使连两个不同的 5GHz AP/信道，一个射频还是不能同时跑满两个 400Mbps
  PHY；`#channels <= 2` 是分时，不是双射频。400Mbps 是单信道 PHY 速率，不是
  两个 vif 的合计可用带宽。要叠加必须第二个物理射频（USB Wi-Fi）或第二台设备。
- 实验后已删除 `wlan0b` 和临时连接，BUAA-WiFi 恢复，TUNA 200。

### 限速器画像：token bucket / 多源 IPv6 / v4-v6

- 短窗口（每次空闲 5s）：0.5s 8.81 MB/s，2s 17.37 MB/s，5s 7.52 MB/s；
  1s 样本失败；没有看到 >150Mbps 的 burst。短窗口受 TCP 慢启动/连接建立影响，
  不能证明 token bucket 无 burst，但至少没有稳定的“秒级超发”。
- 手工在 `wlan0` 前缀内加 `2001:250:20f:1:aaaa::1` / `bbbb::1` 后，
  `curl --interface <addr>` 失败；校园没有路由这些任意后缀，不能用这种方法测
  per-IP 桶。需要 AC 侧确认 key 是 MAC/IP/用户名。
- 同一 TUNA 目标：v4 单流 19.66 MB/s（约 157Mbps，略高于 150），v6 17.21 MB/s；
  v4+v6 并发 19.26 MB/s，不是两者相加。v4 略高于 150 更像限速的计量/开销差异，
  不是第二个独立桶；双栈仍共享同一个 per-client 聚合桶。
- 结论：并行流、DSCP、vif、双 AP、双栈、多源地址都没有稳定的 2×150。剩余可试的
  是 WMM/802.1p 分类、分片/扩展头漏计、以及第二个物理射频；前两个是找实现 bug，
  不是标准协议能给的稳定增益。

### 异形包实验与限速方向性（Scapy / hping3，已还原）

工具：scapy 2.8.0、hping3 3.0.0-alpha-1、tcpdump。构造包只发往 TEST-NET
（192.0.2.1 / 2001:db8::1）、公开 DNS 和镜像；单次 1–10s，结束后无残留
vif/路由/后台进程。

**IPv4 选项**

- 本地网关 10.136.0.1:80 对 NOP、Timestamp、RecordRoute、RouterAlert 四种
  SYN 全部回 RST（3–12ms）：AC/Wi-Fi 正常转发带 IP 选项的 TCP。
- 公网 TUNA 101.6.15.130:80：无选项 78ms 建连；NOP/TS/RR 均 3s 超时；
  RouterAlert 4ms 内收到 RST（可能是校园出口或中间盒，未定位）。
  Cloudflare 1.1.1.1:443 接受 NOP/TS，4–5ms 建连。
- 结论：IP 选项不是通用 bypass，部分上游会静默丢弃；RouterAlert 还会被立即
  拒绝。能通过的路径上，选项也不改变下行合约。

**IPv4 分片**

- 1200B ICMP echo 拆成 4 个 400B 分片，连发 3 轮收到 3 个回复：分片可端到端
  通过校园路径和 AC。
- 3000B UDP 被拆成 2×1500B + 1 个小分片；只增加开销，没有看到限速器漏计。

**IPv6 扩展头**

- HBH、Destination Options、Fragment、HBH+DO+Frag 串联，对链路本地网关和
  网关全局地址各发 5 份：全部 5/5 回复。本地 AP/网关完整转发扩展头。
- 同样构造对 2001:4860:4860::8888 发 5 份：全部 0/5；对 Cloudflare 的普通
  ping 本身 100% 丢包，Ali DNS 90% 丢包。扩展头是在 CERNET 之外的上游被过滤，
  不是 AC 丢的，不能用于公网大流量。
- Linux 不允许在 TCP socket 上设置 IPV6_DSTOPTS/IPV6_HOPOPTS（EINVAL），
  只能用于 UDP/raw；UDP 构造的 HBH/DO/Fragment 在 tcpdump 中结构正确。

**限速方向性（关键）**

- 单流 TUNA v6：18.2 MB/s（约 146Mbps）。
- TUNA + BFSU 两个不同 CERNET 站点并发：总下行 18.08/18.06 MB/s，两流分别
  8.3+9.8、5.1+13.0；总下行仍停在 145Mbps 左右。
- TUNA+BFSU+NJU 三站并发：17.51 MB/s（140Mbps）。
- 窗口 2s/5s/10s/20s：160/148/146/141Mbps。2s 有约 5–10% 的小突发，
  没有可持续的超发。
- 上行 100Mbps UDP（1400B，驱动 tx 104–106Mbps）与下行并发：下行仍
  15.8–17.7 MB/s（126–142Mbps），总吞吐约 240Mbps。
- 上行 30Mbps（200B 小包，驱动 tx 38–40Mbps）：下行 16.7–17.7 MB/s，
  与基线 17.6–18.1 几乎相同。
- 真实 Cloudflare 双上传（合计 9.2–9.4 MB/s）与 TUNA 下行并发：下行
  14.4–16.1 + 上行 9.2–9.4 = 23.6–25.5 MB/s（189–204Mbps）。
- 结论：150Mbps 是 **每 station、仅下行** 的合约/整形，不是上下行共享桶，
  也不是纯 PHY 上限（400Mbps PHY 下 100Mbps 上行 + 145Mbps 下行可同时存在）。
  多流、多目标、多 IP、双栈都共享同一个下行 150Mbps；上行有独立额度。

**为什么 WMM/DSCP 实验不适用**

- 之前 `SO_PRIORITY=6` 只作用于客户端发出的上行包；下行包的 DSCP 由服务器
  决定，客户端无法设置。因此 WMM/802.1p/DSCP 无法影响下行合约。
- 合约在 AP/AC 的 station 层生效，客户端构造的上行 IP 选项/扩展头/分片
  不会改变下行计量；要触发“异形下行包漏计”必须有一个可控的高速下行源，
  当前没有。

**QUIC / 公共 iperf3**

- `curl --http3-only https://cloudflare-quic.com/` 返回 HTTP/3 200，
  校园没有封 UDP/443；但 Cloudflare 到校园约 12MB/s，低于合约，无法判断
  UDP/QUIC 是否被合约豁免。
- 公共 iperf3：HE 反向 TCP 仅 524kbps、UDP 被拒；Scaleway 忙；国内
  iperf3 端口均未开放。没有找到 >150Mbps 的公共 UDP/QUIC 下行源。

**附带确认：IPv6 新流首包丢失仍在**

- 8 次 `curl -6` 到 TUNA，6 次 connect 约 1.0s（首 SYN 丢失后 1s 重传），
  2 次立即建连；一次抓包看到 SYN 在 1s、2s 各重传一次，2.05s 才收到 SYN-ACK。
- 与之前的结论一致：这是真实的链路行为，tcp-race 的复读/竞速仍有价值；
  它与 150Mbps 下行合约是两回事。

**结论**

- 本地 AC 对 IP 选项、IPv4 分片、IPv6 扩展头都照常转发；过滤发生在上游。
- 150Mbps 是真实存在的每 station 下行合约，不是 per-flow/per-IP/共享桶。
- 单个物理射频上，客户端没有找到能稳定超过 150Mbps 下行的协议/包形态漏洞；
  要超过只能换 station 身份（第二个物理射频/第二台设备/不同 role 的 SSID），
  这不是包构造能解决的。

### Aruba 合约语义与 IPv4 异常构造（补充）

**Aruba 公开配置语义**

- ArubaOS 的命名合约：`aaa bandwidth-contract <name> kbits <kbps>`；
  在 `user-role` 下绑定：`bw-contract <name> per-user downstream|upstream`，
  也支持 `per-apgroup`。
- 还支持按应用/类别：`bandwidth-contract app <app> <name> downstream|upstream
  [exclude]`、`bandwidth-contract appcategory <cat> <name> ... [exclude]`；
  Aruba Central 的 API 有 app-bandwidth-contracts、web-category 等对象。
- 这与实测吻合：`per-user downstream` 的 150Mbps 是每 station 下行合约，
  上行是另一条独立合约/额度；不是 per-flow、per-IP，也不是上下行共享桶。
- 公开资料里没有找到“绕过 Aruba bandwidth contract”的研究或漏洞；搜索引擎
  被验证码挡住，能查到的只有配置语法、MIB（WLSX-USER-MIB）、Central API
  schema 和固件里的 CLI 语法文件。
- NIC 已确认没有配置应用排除（app/category exclude），因此“某个应用不受
  合约约束”这条线不成立；实测 B 站直播也只有 137KB/s（直播码率本身低），
  无法用于验证 150Mbps 档位。

**IPv4 选项 / 源路由**

- 本地网关 10.136.0.1 对 NOP、Timestamp、RecordRoute、RouterAlert、
  实验选项 0x1E、40 字节最大选项、保留标志位 0x8000 的 ICMP echo 都正常
  回复；带同样选项的 TCP SYN 也回 RST。AC/Wi-Fi 不因选项丢包。
- LSRR（no-op，路由表就是目的地址）可以端到端到 1.1.1.1 并收到回复；
  SSRR（type 137）被拒；把 LSRR 路由表设成网关自身、目的仍是 1.1.1.1 时，
  网关返回 ICMP 3/0（net unreachable）。也就是说源路由不能用来改路。
- 到公网 TUNA 的 TCP SYN：NOP/TS/RR 3s 超时，RouterAlert 4ms 内 RST；
  Cloudflare 接受 NOP/TS。IP 选项不是通用 bypass。

**IPv4 分片（修正构造后）**

- 手工分片必须显式设置 `proto=1`，否则 `IP()/Raw()` 会当成 protocol 0，
  目标不会按 ICMP 处理（这是本轮踩到的构造坑）。
- 合法 608+600 拆分、8 字节/16 字节首片、乱序（第二片先到）都能被网关
  重组并回复；32 字节重叠分片被丢弃。即：常规分片可用，重叠分片被防
  teardrop/重叠攻击的策略挡住。
- DF+2000B 的 ICMP echo 在抓包里被本机内核拆成 1500+548 两片（raw socket
  下 DF 没有阻止本机分片），不是路径支持 2000B。

**客户端可控的下行字段**

- ECN：把 `net.ipv4.tcp_ecn` 设为 1 后，TUNA 并未协商 ECN，下行 IPv6
  Traffic Class 全为 0；没有 ECN 标记可用。
- MSS：1440→18.18、536→16.47、256→14.32、88→6.90 MB/s。小包只会更慢，
  说明合约按字节计量，没有“包数/小包”漏洞。
- 这些字段都不能改变下行 150Mbps 合约；要构造“异形下行包”，需要一个
  可控的高速下行源（自己的 VPS/第二台校园主机），当前没有。
