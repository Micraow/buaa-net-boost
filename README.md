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

## 核心结论

- 坏桶最长连续 4 个，所以 **5 个连续源端口必然至少 1 个落在好桶**；实测 N=5 时 TCP 12/12、UDP 20/20。
- 竞速只冗余握手/首包，不重复应用数据；正常延迟仍约 1 个 RTT。
- eBPF 只负责把流量透明地送到竞速器；竞速必须在用户态完成。

## 合规

仅在自有或授权网络中使用。不要用于绕过计费、对第三方发起探测或规避审计。报告中的 IP、端口、路径来自特定测试环境，换环境需要调整参数。
