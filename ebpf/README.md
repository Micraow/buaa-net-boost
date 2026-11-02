# eBPF 透明重定向 + 用户态竞速

把指定目标 `IP:port` 的 `connect()` 在 cgroup 层改写到本地竞速代理；代理做多源端口 SYN 竞速，胜者承载应用数据。

**范围**：本目录的 eBPF 程序只处理 IPv4；IPv6 请用 userspace 的 （不需要 eBPF）。

**为什么竞速不放在 eBPF**：`connect()` 只接受一个 5 元组，eBPF 无法替应用保留多个候选连接并选一个返回。eBPF 只负责“把流量送到竞速器”，竞速必须在用户态。

## 文件

| 文件 | 作用 |
|---|---|
| `connect_redirect.bpf.c` | `cgroup/connect4` 程序：匹配目标 IP:port，改写为 `127.0.0.1:18080`，并 `bpf_printk` 记录 |
| `loader.c` | 加载 BPF、写入 target/redirect map、挂到指定 cgroup |
| `Makefile` | 编译 |
| `run_test.sh` | 建 cgroup、起代理、挂 BPF、跑一次 curl、收集日志 |

## 依赖

- 内核 ≥ 5.16（`bpf_trace_vprintk`）且支持 cgroup v2 + `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`；
- `clang`、`libbpf-dev`（≥ 0.6）、`libelf-dev`、`zlib1g-dev`、`gcc`；
- Go ≥ 1.22（构建用户态竞速代理）；
- root（加载 BPF、挂 cgroup），但脚本本身应以普通用户运行。

Debian/Ubuntu 安装：

```bash
sudo apt install clang libbpf-dev libelf-dev zlib1g-dev gcc golang-go
```

## 编译

```bash
cd ebpf
make
make -C ../userspace        # 构建 Go 竞速代理
```

产物：`connect_redirect.bpf.o`、`loader`、`../userspace/bin/tcp-race`。

## 运行

```bash
./run_test.sh 104.16.132.229:443
```

脚本做的事：

1. 在当前用户 cgroup 下建 `zcode-race` 子 cgroup；
2. 以普通用户启动透明竞速代理；只把测试客户端放进被挂载的 cgroup，避免代理/mihomo 自己的 connect 被重定向成环；
3. 用 `sudo` 加载 BPF 并挂到该 cgroup，等待 loader 输出 `ready:`；失败则中止；
4. 把 curl 进程放进 cgroup，访问 `https://cloudflare.com/`（`--resolve` 到 `104.16.132.229`）；
5. `trap` 清理代理/loader/cgroup，并收集 `race-loader.log`、`race-trace.log`、`race-proxy.log`。

## 预期日志

eBPF `trace_pipe`：

```
race redirect 104.16.132.229:443 -> 127.0.0.1:18080
```

代理（多 SYN 过程）：

```
[syn] window 20000-20004 (5 sockets)
[syn] port 20004 SYN-ACK at 194ms
[syn] port 20000 no reply, closing at 2500ms
[syn] port 20001 no reply, closing at 2500ms
[syn] port 20002 no reply, closing at 2500ms
[syn] port 20003 no reply, closing at 2500ms
[transparent] OK -> 104.16.132.229:443 winner=20004 round=1 t=195ms
```

## 验证（无 eBPF 部分）

在拿到 root 之前，已用透明代理单独验证“重定向后的目标”这一半：

```bash
../userspace/bin/tcp-race --listen 18080 --transparent --target 104.16.132.229:443 \
  --n 5 --rounds 1 --verbose --base 20000

# 另一个终端：TLS 客户端直连 127.0.0.1:18080，SNI=cloudflare.com
python3 - <<'PY'
import socket, ssl
ctx = ssl.create_default_context()
s = socket.create_connection(("127.0.0.1", 18080), timeout=8)
ss = ctx.wrap_socket(s, server_hostname="cloudflare.com")
ss.sendall(b"GET / HTTP/1.0\r\nHost: cloudflare.com\r\n\r\n")
print(ss.recv(200).split(b"\r\n")[0].decode())
PY
```

三次结果均为 `HTTP/1.1 301 Moved Permanently`，日志显示每轮 5 个端口中恰有一个在约 160–195 ms 完成 SYN-ACK，其余无回音。

## 注意

- BPF 程序只匹配一个目标（map 只有 1 项）；多目标改成 `HASH` map 即可。
- 只挂测试客户端的 cgroup；代理和 loader 不要放进同一个 cgroup，否则代理自己的 connect 会被重定向成环。
- 当前只支持 IPv4；IPv6 需要 `cgroup/connect6` 和 `user_ip6`。
- 结束后可删除 cgroup：`sudo rmdir /sys/fs/cgroup/zcode-race`（确保里面没有进程）。

## 实测（2026-11-02）

- 问题仍在：64 个源端口扫描 32/64 成功；坏桶起点 N=1、N=4 均为 0/8，N=5 为 8/8。
- eBPF 重定向生效：`connect=0.0001s`；直连对照组 1–4/5，经 eBPF 竞速 5/5、3/3。
- 竞速日志：每轮 5 个端口中一个在 160–190 ms 完成，其余无回音；健康目标（Apple）首端口 4–6 ms 即胜出。
- 端到端总时间：Cloudflare 直连成功约 0.55 s，经代理约 0.59–0.80 s；直连失败一次要等 8 s。

## 与 TUN / fake-ip 的关系

- eBPF 的 connect 钩子在 TUN 之前运行；代理的上游绑定 wlan0，绕过 TUN。两者可以共存。
- **fake-ip 会让钩子看到 198.18.x 的假地址**，匹配不到真实目标；此时要么把 DNS 改成 redir-host，要么改用应用层代理。
- 只把客户端应用放进被挂载的 cgroup；把 mihomo/代理自己放进去，会把它们到目标的 connect 也重定向成环。
- `bpf_printk` 参数超过 3 个会触发 helper 限制，实测会导致重定向不生效；保持 4 个参数以内。
