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
