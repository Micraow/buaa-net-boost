# eBPF 透明重定向 + 用户态竞速

把指定目标 `IP:port` 的 `connect()` 在 cgroup 层改写到本地竞速代理；代理做多源端口 SYN 竞速，胜者承载应用数据。

**为什么竞速不放在 eBPF**：`connect()` 只接受一个 5 元组，eBPF 无法替应用保留多个候选连接并选一个返回。eBPF 只负责“把流量送到竞速器”，竞速必须在用户态。

## 文件

| 文件 | 作用 |
|---|---|
| `connect_redirect.bpf.c` | `cgroup/connect4` 程序：匹配目标 IP:port，改写为 `127.0.0.1:18080`，并 `bpf_printk` 记录 |
| `loader.c` | 加载 BPF、写入 target/redirect map、挂到指定 cgroup |
| `Makefile` | 编译 |
| `run_test.sh` | 建 cgroup、起代理、挂 BPF、跑一次 curl、收集日志 |

## 依赖

- 内核支持 cgroup v2 + `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`；
- `clang`、`bpftool`、`libbpf` 头文件与库；
- root（加载 BPF、挂 cgroup）。

## 编译

```bash
cd ebpf
make
```

产物：`connect_redirect.bpf.o`、`loader`。

## 运行

```bash
sudo ./run_test.sh 104.16.132.229:443
```

脚本做的事：

1. 建 `/sys/fs/cgroup/zcode-race`；
2. 在 root cgroup 里启动透明竞速代理（避免它自己的 connect 被重定向成环）；
3. 加载 BPF 并挂到 `zcode-race`；
4. 把 curl 进程放进 `zcode-race`，访问 `https://cloudflare.com/`（`--resolve` 到 `104.16.132.229`）；
5. 收集 `race-loader.log`、`race-trace.log`、`race-proxy.log`。

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
python3 ../userspace/proxy.py --listen 18080 --transparent --target 104.16.132.229:443 \
  --n 5 --rounds 2 --verbose --base 20000

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
