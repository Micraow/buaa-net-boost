# buaa-net-boost

校园网出口按流哈希导致新连接高失败率的**实测调查**与**客户端规避原型**。

## 背景

某校园网 IPv4 出口出现“新建连接约 40%–60% 失败、已建立连接正常”的现象。实测发现：

- 失败按 5 元组粘住，同一源端口重试无效；
- 按源端口扫描得到**周期为 8 的确定性位图**，4 个好、4 个坏；
- 不同目的地分组对应不同的好坏桶分布，并与走联通/电信/CERNET 上联相关；
- 判断为出口侧 ECMP/LAG 成员失效，按流哈希把约一半新流送进黑洞。

## 目录

| 路径 | 内容 |
|---|---|
| `report/ecmp-new-flow-report.md` | 完整调查报告：现象、数据、分析、复现命令 |
| `ebpf/` | `cgroup/connect4` 透明重定向 + 加载器（需 root） |
| `userspace/` | Go 版 TCP 竞速代理、UDP 竞速中继、握手基准（`make -C userspace`） |
| `docs/tcp-race.md` | TCP 竞速代理用法与实测 |
| `docs/udp-race.md` | UDP 竞速中继用法与实测 |
| `docs/ebpf-vs-tun.md` | eBPF / TUN / LD_PRELOAD 方案对比 |
| `docs/benchmark.md` | 方案一实测：延迟、100MB 带宽、CPU/RSS、额外包量 |
| `docs/browser-benchmark.md` | 浏览器 LCP/TTFB、上传、DNS AAAA、QUIC/Hysteria2、IPv4 多路径 |
| `synspray/` | 同 5 元组 SYN 复读的独立验证工具与测量数据 |

## 快速开始

### 1. 用户态 TCP 竞速代理（Go）

```bash
make -C userspace
userspace/bin/tcp-race --listen 18080 --n 5 --rounds 1 --base 20000 --step 8
# 可选：--iface wlp8s0 / --no-bind / --timeout 2.5s / --verbose

curl -x http://127.0.0.1:18080 -k https://目标/
curl --socks5-hostname 127.0.0.1:18080 -k https://目标/
```

### 2. UDP 竞速中继（Go）

```bash
userspace/bin/udp-race --listen 18081 \
  --target 203.107.6.88 --target-port 123 --n 5 --base 20000 --step 8
```

### 3. eBPF 透明重定向（需 root，脚本以普通用户运行）

```bash
cd ebpf && make
./run_test.sh 104.16.132.229:443
```

日志：`ebpf/race-loader.log`、`ebpf/race-trace.log`、`ebpf/race-proxy.log`。

`userspace/README.md` 列出了 Go 实现修复的原型缺陷（假胜者、SOCKS5 提前回成功、CONNECT 余量、半关闭、DNS、网卡硬编码、UDP 缓冲等）。

## 方案一：SOCKS5/HTTP CONNECT + 特权 SYN helper（IPv6 推荐）

本地代理承载应用数据，特权小助手只抓 SYN 并原样复读；UDP 的首包复读由代理
自己的上游 socket 完成，不需要 root。

```bash
make -C userspace
sudo setcap cap_net_raw+ep userspace/bin/spray-helper
userspace/bin/spray-helper --socket /tmp/buaa-net-boost-spray.sock --iface wlan0 &

userspace/bin/tcp-race \
  --listen 18080 --family 6 --n 2 --rounds 1 --timeout 3s \
  --spray 8 --spray-interval 20ms \
  --spray-helper /tmp/buaa-net-boost-spray.sock \
  --iface wlan0 --no-bind

curl -x http://127.0.0.1:18080 https://目标/
# 浏览器 HTTP/SOCKS5 代理填 127.0.0.1:18080；SOCKS5 也支持 UDP ASSOCIATE
```

一批探测：TCP 2 条 5 元组 × 8 份 SYN（16 个），UDP 单 5 元组 × 16 个首包；
第一条 SYN-ACK / 第一份响应胜出，其余 RST/丢弃。实测（TUNA / Cloudflare DNS）：

| 项目 | 代理 | 直连 |
|---|---|---|
| TCP 小请求 | 20/20，中位 89ms | 19/20，中位 1.08s，1 次 12s 超时 |
| 100MB 下载（3 轮） | 17.52 MB/s；CPU ~2% | 17.61 MB/s |
| 100MB 上传（3 轮） | 14.90 MB/s；CPU ~0.1% | 15.86 MB/s |
| UDP DNS | 50/50，中位 65.7ms | 单包 15/50 |

代理 CPU 在 100MB 传输中 0.15–0.18s，helper 0.00–0.01s；额外包量约 16 个
SYN/新 TCP 流、16 个首包/新 UDP 流。表中的 MB/s 是 `size/time_total`，包含
connect：直连每轮卡 5.23s，代理上游 connect 只有几十毫秒。扣掉 connect 后
直连约 7.0/11.0 MB/s、代理约 6.1/13.9 MB/s，两组有重叠；代理的稳定收益在
connect 长尾，不是物理带宽。完整方法和开销见
[`docs/benchmark.md`](docs/benchmark.md)。

浏览器实测（Chrome，2 轮）：DeepSeek LCP 1700→516ms，Comate 582→340ms，
USTC/百度/Bing 基本持平；100MB 3 轮下载 17.61→17.52 MB/s（0.5%），上传
15.86→14.90 MB/s（6%，一次代理 16.37 高于直连）。DeepSeek 的卡顿根因是
AAAA 在 UDP 53 被过滤（DoH 正常），代理的并发 A/AAAA + 缓存把它消掉；
QUIC/Hysteria2、上传、IPv4 多路径的结论见
[`docs/browser-benchmark.md`](docs/browser-benchmark.md)。

## 核心结论

- 坏桶最长连续 4 个，所以 **5 个连续源端口必然至少 1 个落在好桶**；实测 N=5 时 TCP 12/12、UDP 20/20。
- 竞速只冗余握手/首包，不重复应用数据；正常延迟仍约 1 个 RTT。
- eBPF 只负责把流量透明地送到竞速器；竞速必须在用户态完成。
- IPv6 新流的前 K 个包会被连续丢弃/限速（K 随时段/流变化，实测 1–16）；同 5 元组复读可把建连从 1s 级降到几十毫秒。TCP 2×8、UDP 1×16 是当前实测最稳的一批参数。

## 合规

仅在自有或授权网络中使用。不要用于绕过计费、对第三方发起探测或规避审计。报告中的 IP、端口、路径来自特定测试环境，换环境需要调整参数。


## License

This repository is **source-available under CC BY-NC 4.0**:
noncommercial use only, attribution required, commercial use requires a
separate written license. See `LICENSE` and `NOTICE`.

CC BY-NC 4.0 is **not an OSI-approved open-source license**, because OSI
licenses cannot restrict commercial use. If you need an OSI license, no OSI
license can provide the "no commercial use" restriction requested here.

The `char _license[] SEC("license") = "GPL";` string in `ebpf/*.bpf.c` is a
kernel verifier ABI declaration for GPL-only helpers; it does not change the
source license above.
