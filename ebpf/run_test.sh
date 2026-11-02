#!/bin/bash
# 在指定 cgroup 内把到 TARGET 的 connect() 重定向到本地竞速代理，然后跑一次 curl。
# 需要 root（加载 eBPF、挂 cgroup）。
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
CG=/sys/fs/cgroup/zcode-race
TARGET="${1:-104.16.132.229:443}"
LISTEN="${2:-18080}"
TRACE=/sys/kernel/tracing/trace_pipe
[ -e "$TRACE" ] || TRACE=/sys/kernel/debug/tracing/trace_pipe

sudo mkdir -p "$CG"

# 代理和 loader 都在 root cgroup 里，避免它们自己的 connect 被重定向成环
python3 "$HERE/../userspace/proxy.py" --listen "$LISTEN" --transparent --target "$TARGET" \
    --n 5 --rounds 2 --verbose --base 20000 > "$HERE/race-proxy.log" 2>&1 &
PP=$!

sudo "$HERE/loader" "$HERE/connect_redirect.bpf.o" "$CG" "$TARGET" "127.0.0.1:$LISTEN" \
    > "$HERE/race-loader.log" 2>&1 &
LP=$!
sleep 1

sudo timeout 12 cat "$TRACE" > "$HERE/race-trace.log" 2>&1 &
TP=$!
sleep 1

echo "=== curl（在 $CG 内，目标 $TARGET）==="
sudo bash -c "echo \$\$ > $CG/cgroup.procs; exec curl --noproxy '*' \
    --resolve cloudflare.com:443:104.16.132.229 \
    -s -o /dev/null -w 'http=%{http_code} time=%{time_total}s\n' \
    https://cloudflare.com/"

sleep 2
kill "$PP" "$LP" "$TP" 2>/dev/null || true

echo "=== loader ==="
cat "$HERE/race-loader.log"
echo "=== eBPF trace ==="
grep -a "race redirect" "$HERE/race-trace.log" | tail -10 || true
echo "=== proxy（多 SYN 过程）==="
tail -30 "$HERE/race-proxy.log"
