# 方案一实测：延迟、带宽与开销

日期：2026-11-02。环境：`wlan0`，全局 IPv6，代理
`--family 6 --n 2 --spray 8 --spray-interval 20ms --timeout 3s`，helper
`CAP_NET_RAW`。目标：TUNA `2402:f000:1:400::2:443`（Ubuntu 24.04.4 ISO，
100MB Range）和 Cloudflare DNS `2606:4700:4700::1111:53`。仅代表这一时段，
校园链路波动很大。

## TCP 小请求（20 次，每次新连接）

代理和直连都访问同一个 TUNA IP；直连用 `--resolve` 固定，避免 anycast 差异。

```bash
U='https://mirrors.tuna.tsinghua.edu.cn/ubuntu-releases/24.04.4/ubuntu-24.04.4-desktop-amd64.iso'
IP='2402:f000:1:400::2'

# 代理
curl -x http://127.0.0.1:18080 -sS -r 0-1023 -o /dev/null \
  -w '%{http_code} %{time_total}\n' "$U"

# 直连
curl -6 -sS --resolve "mirrors.tuna.tsinghua.edu.cn:443:[$IP]" \
  -r 0-1023 -o /dev/null \
  -w '%{http_code} %{time_connect} %{time_total}\n' "$U"
```

| 方式 | 成功 | 中位总延迟 | 中位 connect | 最慢 |
|---|---|---|---|---|
| 代理 | 20/20 | 89ms | —（代理内部竞速 8–32ms） | 178ms |
| 直连同 IP | 19/20 | 1.08s | 1.035s | 1 次 12s 超时 |

直连的 1s 级别延迟是首包/重传造成的；代理的 16 个 SYN（2 路径 × 8 份）
在几十毫秒内完成握手，不需要等内核 1s/2s RTO。

## 100MB 下载

同样的 ISO 前 100MB（`-r 0-104857599`），直连和代理固定同一 IP；交替跑两轮：

| 轮次 | 方式 | 吞吐 | 总耗时 | connect |
|---|---|---|---|---|
| 1 | 直连 | 5.2 MB/s | 20.1s | 5.23s |
| 1 | 代理 | 6.1 MB/s | 17.2s | 代理内部竞速 |
| 2 | 直连 | 7.1 MB/s | 14.8s | 5.23s |
| 2 | 代理 | 13.8 MB/s | 7.6s | 代理内部竞速 |

校园链路本身在变化（第二轮整体更快），所以不能把吞吐差异归因于代理；
可以确定的是代理没有把吞吐压下去。直连的 `connect` 固定卡 5.2s，是首包
丢失后 TCP 重传退避的结果；代理把这一段消掉了。

### 为什么代理的 MB/s 看起来更高

`curl` 的 `speed_download` 是 `字节数 / time_total`，**包含 connect**。
直连每轮都卡了 5.23s 的 TCP 重传退避，代理的上游 connect 只有几十毫秒。
扣掉 connect 后（代理按约 0.03s 估）：

| 轮次 | 方式 | 传输时间 | 传输吞吐 |
|---|---|---|---|
| 1 | 直连 | 20.1 - 5.23 = 14.9s | 7.0 MB/s |
| 1 | 代理 | 17.2 - 0.03 = 17.2s | 6.1 MB/s |
| 2 | 直连 | 14.8 - 5.23 = 9.6s | 11.0 MB/s |
| 2 | 代理 | 7.6 - 0.03 = 7.6s | 13.9 MB/s |

两组有重叠，第一轮代理的实际传输甚至略慢；第二轮代理更高更像链路波动/两条
5 元组选到了不同的 ECMP 路径，而不是代理增加了物理带宽。代理的稳定收益在
**connect 的长尾**（直连 5.23s → 代理几十毫秒），不是吞吐。要比较吞吐，应该
看“扣掉 connect 的传输速率”，并做多轮配对；否则 `speed_download` 会把
connect 的差距算进 MB/s。

### CPU / RSS

用 `/proc/<pid>/stat` 的 utime+stime 和 `ps -o rss` 在每次传输前后采样：

| 进程 | 100MB CPU | 占墙钟 | RSS 变化 |
|---|---|---|---|
| `tcp-race` 代理 | 0.15–0.18s | 1–2% | +28–48KB |
| `spray-helper` | 0.00–0.01s | ≈0 | 基本不变（约 10.9MB） |

代理的 TCP tunnel 用 `io.Copy`，Linux 上走 `splice`；CPU 主要花在每连接的
TLS/HTTP（端到端，不在代理里）。helper 的 `AF_PACKET` 只通过 BPF 过滤
IPv6/TCP/SYN，不解析数据包，所以传输期间几乎不占 CPU。

## UDP（SOCKS5 UDP ASSOCIATE，DNS 查询）

客户端每次用新的 UDP 源端口，因此每次都是一个新 flow；代理首包发 16 份，
后续包单发。50 次查询：

| 指标 | 结果 |
|---|---|
| 成功 | 50/50 |
| 中位延迟 | 65.7ms |
| 最慢 | 353ms |
| 代理 CPU | 0.10s（2% 墙钟） |
| 代理 RSS | 9.0MB → 17.7MB（+8.6MB） |

RSS 增长来自每个新 flow 一个上游 UDP socket 和缓冲区；50 个短查询 flow
约 170KB/flow。真实 DNS 解析器通常复用 UDP 源端口，flow 数会少很多；
`--udp-flows` 默认 512 是兜底上限，TCP 断开时 flow 也会关闭。

## 额外包量

| 协议 | 每新 flow 额外包 | 估算字节 |
|---|---|---|
| TCP | 2 路径 × 8 份 = 16 个 SYN | 约 16 × 94B ≈ 1.5KB |
| UDP | 16 个首包 | DNS 查询约 16 × 60B ≈ 1KB；QUIC Initial 约 16 × 1.2KB ≈ 19KB |

高连接率场景（例如每个请求都新建 TCP）要加令牌桶；本项目目前用
`--threads`、`--udp-flows`、helper 的 `pending`/并发上限做兜底，没有做全局
SYN 速率限制。

## 复现注意事项

- helper 需要 `CAP_NET_RAW`：`sudo setcap cap_net_raw+ep userspace/bin/spray-helper`；
- 代理若没有 `CAP_NET_RAW`，用 `--no-bind`，让 helper 绑网卡；
- 直连和代理必须固定同一个目标 IP，否则 CDN/anycast 会污染对比；
- 100MB Range 的吞吐受校园出口、目标服务器和时段影响，建议同一时段交替跑；
- 只在自己/授权网络测试，不要对第三方发起批量 SYN 或 UDP 探测。
