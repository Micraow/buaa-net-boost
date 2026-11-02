# userspace：Go 版 TCP / UDP 竞速工具

Python 原型已替换为 Go 实现。Go 的 `net` 栈 + `io.Copy`（Linux 上走 `splice`）在 20 MB 下载上已接近直连速度（实测 10.8–12.5 MB/s，直连 5.8–10.0 MB/s，受网络波动影响）。

## 构建

```bash
make -C userspace
# 产物：userspace/bin/{tcp-race,udp-race,probe}
```

需要 Go ≥ 1.22；仅 Linux（使用了 `SO_BINDTODEVICE`）。

## TCP 竞速代理

```bash
userspace/bin/tcp-race --listen 18080 --n 5 --rounds 1 --base 20000 --step 8
# 可选：--iface wlp8s0 / --no-bind / --timeout 1.5s / --threads 256 / --verbose

curl -x http://127.0.0.1:18080 -k https://目标/
curl --socks5-hostname 127.0.0.1:18080 -k https://目标/
```

透明模式（配合 eBPF / nftables）：

```bash
userspace/bin/tcp-race --listen 18080 --transparent --target 104.16.132.229:443 --verbose
```

## UDP 竞速中继

```bash
userspace/bin/udp-race --listen 18081 --target 203.107.6.88 --target-port 123 \
  --n 5 --base 20000 --step 8 --verbose
```

## 握手竞速基准

```bash
userspace/bin/probe --n 5 --trials 10 --base 20003 223.5.5.5 443
```

## 已修复的原型缺陷

- **假胜者**：Go 的 `DialContext` 直接返回成功/失败，不再依赖 `SO_ERROR`；失败连接不会被计入胜者。
- **SOCKS5 语义**：先竞速、成功后才回 `REP=0`；失败回 `REP=5/4`，不会把 HTTP 文本写进 SOCKS 流。
- **CONNECT 余量**：用 `bufio.Reader` 保留头部之后的应用字节，隧道建立后先转发。
- **半关闭**：单侧 EOF 时对另一侧 `CloseWrite()`，另一方向继续转发。
- **DNS**：使用系统解析器 `getaddrinfo`，不再硬编码被接管的 UDP DNS；如需完全避开系统 DNS，可在外部用 DoH 解析后传 IP。
- **网卡**：`--iface` / `--no-bind`，默认自动探测默认路由网卡；不再硬编码 `wlan0`。
- **UDP 主机名**：启动时解析一次；竞速期间的后续数据报会缓冲，胜者确定后按序发出。
- **参数校验**：端口窗口要求 `1024 <= base < end <= 65535`、`0 < n <= step`。
- **连接上限**：`--threads` / `--flows` 信号量，避免慢客户端无限占线程。
- **错误码**：HTTP 400/502、SOCKS5 REP 按协议分开。

## 注意

- `SO_BINDTODEVICE` 在旧内核上需要 `CAP_NET_RAW`；失败时用 `--no-bind` 或换 `--iface`。
- TCP 竞速只对新建连接有效；已建立连接路径失效不会自动迁移。
- UDP 只对“有请求-响应”的协议可靠；单向 UDP 无法判定胜者。
- 每条新连接会多产生 N−1 个 SYN/首包；N 建议 5–6，不要无限加大。
- 仅限自有/授权网络使用。
