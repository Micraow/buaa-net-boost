# eBPF vs TUN：把“多源端口握手竞速”放在哪一层

## 结论

- **竞速本身必须在用户态**（或内核模块）。eBPF 和 TUN 只能负责把流量**透明地送到竞速器**，不能替应用完成“多条候选连接里选一个”的语义。
- 系统级最佳：**eBPF 重定向 + 本地竞速代理**。开销小、无 TUN 设备、可按 cgroup/进程/namespace 精确控制。
- 没有 eBPF 时：**nftables/iptables REDIRECT 到本地代理**，比 TUN 简单。
- TUN 是最后选择：UDP 很自然，但 TCP 需要用户态 TCP 栈或再转给代理，开销和复杂度最高。
- 单应用场景：**LD_PRELOAD 拦截 `connect()`** 做 TCP 竞速最简单；UDP 仍建议本地代理。

## eBPF 能做什么

- `cgroup/connect4`：把应用的目标地址改写到 `127.0.0.1:proxy`，让代理接管；可按进程/cgroup 精准生效。
- `sock_ops`：观察连接建立/失败/重传，做统计或触发重连。
- tc/XDP：统计、限速、按桶观察；可以作为“学习好端口”的数据来源。
- 可以用 eBPF 维护每个目的组的“好桶”表，给代理提供选端口提示。

## eBPF 不能做什么

- 不能为一个已经 `connect()` 的应用 socket 透明地换源端口重试——`connect()` 只接受一个 5 元组。
- 不能替应用保留多条候选连接、选一条返回给应用；这需要用户态代理或 LD_PRELOAD 的 `dup2` 技巧。
- 因此 eBPF 只解决“怎么把流量送到竞速器”，不解决“怎么竞速”。

## TUN 能做什么

- 在 IP 层截获所有 TCP/UDP，交给用户态处理；UDP 只需一张流表，比较自然。
- TCP 有两种做法：
  1. 用户态 TCP 栈：完全接管，重、性能差、要处理窗口/选项/重传/MTU；
  2. TUN 只做搬运，把流量再重定向到本地代理：等价于 nftables REDIRECT + 代理，TUN 是多余的一层。
- 优点：不需要 eBPF 支持，兼容性好；对 UDP 很合适。
- 缺点：需要 root/CAP_NET_ADMIN；MTU、分片、校验和、路由、性能开销；TCP 终止复杂。

## 推荐架构

1. 用户态竞速器：TCP `proxy.py`（HTTP CONNECT + SOCKS5），UDP `udp_race.py`。
2. 透明接入，按优先级：
   - **eBPF** `cgroup/connect4` 把 TCP/UDP 改写到本地代理；
   - **nftables/iptables REDIRECT**（OUTPUT 链）到本地代理；
   - **TUN/TPROXY** 兜底。
3. 竞速器内部：端口窗口、胜者保留、失败换窗口重试、流表与空闲回收。

## 性能对比

| 方案 | 额外开销 | 复杂度 | 适用 |
|---|---|---|---|
| LD_PRELOAD（单应用 TCP） | 最低 | 低 | 自有程序 |
| eBPF + 本地代理 | 低 | 中高 | 系统级/按进程 |
| nftables REDIRECT + 代理 | 中 | 中 | 系统级，无 eBPF |
| TUN + 代理/用户态栈 | 高 | 高 | 兜底、UDP |

竞速本身只增加 N−1 个 SYN/首包，不复制应用数据；正常延迟仍约 1 个 RTT。

## 安全与合规

仅在自有或授权网络使用；不要用于绕过计费、对第三方发起探测或规避审计。
