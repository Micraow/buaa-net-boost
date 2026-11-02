# userspace：Go 代理 + TCP SYN 复读 + UDP 首包复读

方案一实现：本地 SOCKS5/HTTP CONNECT 代理负责承载应用数据，特权小助手
`spray-helper` 只负责抓取 TCP SYN 并原样复读；UDP 的首包复读由代理自己的
上游 socket 完成，不需要 root。

## 构建

```bash
make -C userspace
# 产物：userspace/bin/{tcp-race,udp-race,probe,spray-helper}
```

需要 Go ≥ 1.24；仅 Linux（`AF_PACKET`、raw IPv6、`SO_BINDTODEVICE`）。
`golang.org/x/sys` 只用于 `SO_ATTACH_FILTER`。

## 方案一：SOCKS5/HTTP CONNECT + spray-helper

### 1. 启动 helper（只做 TCP SYN 抓取/复读）

helper 只需要 `CAP_NET_RAW`，不需要 root 跑代理：

```bash
sudo setcap cap_net_raw+ep userspace/bin/spray-helper
userspace/bin/spray-helper \
  --socket /tmp/buaa-net-boost-spray.sock \
  --iface wlan0
```

- `--socket` 是 0600 UNIX socket，只接受本机请求；
- `--iface` 必须和代理的出口网卡一致；
- helper 只接受全局 IPv6 单播目标，校验端口/份数/间隔，`pending` 和并发都有上限；
- 它抓的是代理自己内核 socket 发出的 SYN，不接管连接、不回传 fd。

### 2. 启动代理

```bash
userspace/bin/tcp-race \
  --listen 18080 --family 6 \
  --n 2 --rounds 1 --timeout 3s \
  --spray 8 --spray-interval 20ms \
  --spray-helper /tmp/buaa-net-boost-spray.sock \
  --iface wlan0 --no-bind
```

- `--n 2`：两条候选 5 元组（不同源端口）并发；
- `--spray 8`：每条路径 8 份 SYN，20ms 间隔；总共 16 个 SYN，第一条 SYN-ACK 胜出，另一条 RST 关闭；
- `--timeout 3s`：如果 16 份都没赶上，留给内核 1s/2s 重传兜底；
- `--family 6`：优先 IPv6；没有 AAAA 或 IPv6 连接失败时回退 IPv4。A/AAAA 并发查询，AAAA 只等 200ms + 25ms 宽限；DNS 结果缓存 30 秒，避免 DeepSeek 这类 AAAA 超时把页面卡 6 秒；
- `--no-bind`：代理本身不绑网卡；如果代理有 `CAP_NET_RAW`，可以去掉，让 TCP socket 也绑 `wlan0`；
- UDP 默认 `--udp-copies 16 --udp-interval 20ms`，只在每条新流的第一个数据报上连发。

### 3. 客户端

```bash
# HTTP CONNECT
curl -x http://127.0.0.1:18080 https://目标/

# SOCKS5 TCP
curl --socks5-hostname 127.0.0.1:18080 https://目标/

# 浏览器：HTTP/SOCKS5 代理填 127.0.0.1:18080
```

SOCKS5 的 `UDP ASSOCIATE` 也支持：客户端把 UDP 发到代理返回的
`127.0.0.1:port`，代理按目标建立上游 UDP flow，首包 16 连发，后续包只发一次，
重复响应按 5 元组 + payload 哈希去重。DNS 走 UDP 53、QUIC 走 UDP 443 都可以。

## 一批探测的参数

| 协议 | 参数 | 说明 |
|---|---|---|
| TCP | 2 路径 × 8 份，20ms | 16 个 SYN；第一条成功即停；另一条 RST |
| UDP | 1 路径 × 16 份，20ms | 16 个首包；第一份响应即停；后续单发 |

TCP 的“双路径”是**两个源端口/5 元组**，不是两个物理网卡；当前环境只有
`wlan0` 有全局 IPv6。UDP 实测双路径 8+8 不如单路径 16，所以默认只加深、不加宽。

## UDP 固定目标中继（旧工具）

```bash
userspace/bin/udp-race --listen 18081 --target 203.107.6.88 --target-port 123 \
  --n 5 --base 20000 --step 8 --verbose
```

适合先验证 UDP 竞速；通用 SOCKS5 UDP 用上面的 `tcp-race`。

## 实测

2026-11-02，`wlan0`，目标 TUNA `2402:f000:1:400::2` / Cloudflare DNS
`2606:4700:4700::1111`：

| 项目 | 结果 |
|---|---|
| TCP 小请求，代理 | 20/20，中位 89ms，最慢 178ms |
| TCP 小请求，直连 | 19/20，中位总 1.08s，中位 connect 1.035s，1 次 12s 超时 |
| 100MB 下载，代理（3 轮中位） | 17.52 MB/s |
| 100MB 下载，直连同 IP（3 轮中位） | 17.61 MB/s（损失 0.5%） |
| 代理 CPU / RSS | 100MB 用 0.15–0.18s（1–2%），RSS +28–48KB |
| helper CPU / RSS | 0.00–0.01s，10.9MB RSS，基本不变 |
| 单条 TCP 流额外包 | 16 个 SYN，约 1.5KB |
| UDP DNS，代理 | 50/50，中位 65.7ms，最慢 353ms |
| UDP 代理 CPU / RSS | 50 个新流 0.10s（2%），RSS +8.6MB；每流一个上游 socket |
| 100MB 上传，代理（3 轮中位） | 14.90 MB/s |
| 100MB 上传，直连同 IP（3 轮中位） | 15.86 MB/s（损失 6%） |

直连和代理使用同一个目标 IP（`--resolve`）做对比；校园链路本身波动很大，
吞吐数字只代表这一时段，不代表代理上限。表中 MB/s 是 `size/time_total`，
**包含 connect**：直连每轮卡 5.23s，代理上游 connect 只有几十毫秒。扣掉
connect 后直连约 7.0/11.0 MB/s，代理约 6.1/13.9 MB/s，两组有重叠；代理的
稳定收益在 connect 长尾，不是物理带宽。代理的 `io.Copy` 在 Linux 上走
`splice`，CPU 开销主要来自每连接的 TLS/HTTP 端到端（不在代理里）。
详细方法和原始输出见 [`../docs/benchmark.md`](../docs/benchmark.md)。

### 浏览器 / 上传 / DeepSeek

Chrome（Playwright headless）每站直连/代理各 2 轮：

| 站点 | 直连 LCP | 代理 LCP | 直连 TTFB | 代理 TTFB |
|---|---:|---:|---:|---:|
| USTC 镜像 | 348ms | 368ms | 89ms | 86ms |
| 百度 | 212ms | 204ms | 75ms | 78ms |
| Comate | 582ms | **340ms** | 27ms | 33ms |
| DeepSeek | **1700ms** | **516ms** | **1404ms** | **195ms** |
| Bing | 364ms | 386ms | 134ms | 158ms |

DeepSeek 的卡顿来自 AAAA：UDP 53 对 `chat.deepseek.com` 的 AAAA 被
Tencent/阿里/校园/114/Google 返回 SERVFAIL 或超时，DoH 走 443 却 53ms 返回
NODATA；域名本身 AAAA CNAME 目标也没有 AAAA。代理的并发 A/AAAA + 缓存把
这条长尾消掉；修短后 DeepSeek `curl` 总时间约 190ms。100MB 3 轮中位：下载
直连 17.61、代理 17.52 MB/s（0.5%）；上传直连 15.86、代理 14.90 MB/s（6%，
一次代理 16.37 高于直连）。QUIC/Hysteria2、IPv4 多路径和源端口/运营商关系见
[`../docs/browser-benchmark.md`](../docs/browser-benchmark.md)。

## IPv6 结论

- 新流前 K 个包会被连续丢弃/限速，K 随时段/流变化（实测 1–16）；
- 同 5 元组复读到第 K 份就能穿过去，TCP 双路径 8×8 实测 50/50；
- UDP 单包 DNS 只有 15/50，8 份 45/50，16 份 50/50；
- 8 份时的“按流黑洞”不是永久黑洞：4 条失败流隔 2 秒用同一源端口重试全部成功；
- 因此 TCP 用 2×8，UDP 用 1×16；失败再回退 IPv4/隧道。

## 已修复的原型缺陷

- **假胜者**：Go 的 `DialContext` 直接返回成功/失败，不使用 `SO_ERROR` 猜。
- **SOCKS5 语义**：先竞速、成功后才回 `REP=0`；失败回 `REP=5/4`。
- **CONNECT 余量**：`bufio.Reader` 保留头部之后的应用字节，隧道建立后先转发。
- **半关闭**：单侧 EOF 时对另一侧 `CloseWrite()`。
- **DNS**：使用系统解析器；需要完全避开系统 DNS 时外部用 DoH 传 IP。
- **网卡**：`--iface` / `--no-bind`，IPv6 默认读 `/proc/net/ipv6_route`。
- **UDP 主机名**：启动时解析；后续数据报按 flow 转发。
- **参数校验**：端口窗口、份数、间隔、目标类型都有校验。
- **连接上限**：`--threads`、`--udp-flows`，避免慢客户端无限占资源。

## 注意

- `spray-helper` 用 raw socket，务必只在本机、自有/授权网络运行；UNIX socket 0600，目标校验为全局 IPv6 单播。
- TCP 复读只对新建连接有效；已建立连接路径失效不会自动迁移。
- UDP 复读只对可重复的协议安全（DNS 同 ID、QUIC Initial）；任意 UDP 可能重复触发副作用，需协议识别或改用隧道。
- 每条新 TCP 流 16 个 SYN、每条新 UDP 流 16 个首包；高连接率场景要加令牌桶/限速。
- UDP 每个新 flow 一个上游 socket；真实 DNS 复用源端口时会少很多，短连接 DNS 可能累积内存（`--udp-flows` 上限兜底）。
- QUIC/HTTP3 需要客户端支持 SOCKS5 UDP ASSOCIATE；Chrome 的 SOCKS5 不代理 UDP。Hysteria2 是 QUIC/UDP 协议，TCP CONNECT 代理不能承载，需要 TUN/透明重定向或支持 UDP detour 的客户端。
- 仅限自有/授权网络使用；不要用于绕过计费或第三方探测。

## License

CC BY-NC 4.0：禁止商用，必须署名；不是 OSI 开源许可证。见
[`../LICENSE`](../LICENSE) 和 [`../NOTICE`](../NOTICE)。
