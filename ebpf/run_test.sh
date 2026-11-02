#!/bin/bash
# 在指定 cgroup 内把到 TARGET 的 connect() 重定向到本地竞速代理，然后跑一次 curl。
# 需要 root（加载 eBPF、挂 cgroup），但脚本本身应以普通用户运行；内部会对 loader 使用 sudo。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-104.16.132.229:443}"
LISTEN="${2:-18080}"
N="${3:-5}"
ROUNDS="${4:-1}"

if [[ ! "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$ ]]; then
	echo "target 必须是 IPv4:port，收到: $TARGET" >&2
	exit 2
fi

if [ "$(id -u)" -eq 0 ] && [ -z "${SUDO_USER:-}" ]; then
	echo "请以普通用户运行本脚本（脚本内部会对 loader 使用 sudo）" >&2
	exit 2
fi
RUN_AS="${SUDO_USER:-$(id -un)}"

BIN="$HERE/../userspace/bin/tcp-race"
if [ ! -x "$BIN" ]; then
	(cd "$HERE/../userspace" && go build -o bin/tcp-race ./cmd/tcp-race)
fi

CG="/sys/fs/cgroup$(awk -F: '{print $3}' /proc/self/cgroup)/zcode-race"
mkdir -p "$CG"
if [ ! -f "$CG/cgroup.procs" ]; then
	echo "$CG 不是 cgroup v2 目录" >&2
	exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
	chown "$RUN_AS" "$CG" 2>/dev/null || true
fi

LOG_PROXY="$HERE/race-proxy.log"
LOG_LOADER="$HERE/race-loader.log"
LOG_TRACE="$HERE/race-trace.log"
rm -f "$LOG_PROXY" "$LOG_LOADER" "$LOG_TRACE"

PP=""
LP=""
TP=""
cleanup() {
	[ -n "$PP" ] && kill "$PP" 2>/dev/null || true
	[ -n "$LP" ] && kill "$LP" 2>/dev/null || true
	[ -n "$TP" ] && kill "$TP" 2>/dev/null || true
	wait 2>/dev/null || true
	rmdir "$CG" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# 代理以普通用户运行，不解析不可信网络数据为 root
if [ "$(id -u)" -eq 0 ]; then
	sudo -u "$RUN_AS" -- "$BIN" --listen "$LISTEN" --transparent --target "$TARGET" \
		--n "$N" --rounds "$ROUNDS" --verbose --base 20000 > "$LOG_PROXY" 2>&1 &
else
	"$BIN" --listen "$LISTEN" --transparent --target "$TARGET" \
		--n "$N" --rounds "$ROUNDS" --verbose --base 20000 > "$LOG_PROXY" 2>&1 &
fi
PP=$!

sudo "$HERE/loader" "$HERE/connect_redirect.bpf.o" "$CG" "$TARGET" "127.0.0.1:$LISTEN" 30 \
	> "$LOG_LOADER" 2>&1 &
LP=$!

# 等 loader 真正 ready，而不是 sleep 1
for _ in $(seq 1 50); do
	if grep -q '^ready:' "$LOG_LOADER" 2>/dev/null; then
		break
	fi
	if ! kill -0 "$LP" 2>/dev/null; then
		break
	fi
	sleep 0.1
done
if ! grep -q '^ready:' "$LOG_LOADER" 2>/dev/null; then
	echo "loader 未就绪：" >&2
	cat "$LOG_LOADER" >&2
	exit 1
fi

TRACE=/sys/kernel/tracing/trace_pipe
[ -e "$TRACE" ] || TRACE=/sys/kernel/debug/tracing/trace_pipe
if sudo test -r "$TRACE" 2>/dev/null; then
	sudo timeout 15 cat "$TRACE" > "$LOG_TRACE" 2>&1 &
	TP=$!
else
	echo "trace_pipe 不可读，跳过 trace" >&2
fi

echo "=== curl（在 $CG 内，目标 $TARGET）==="
bash -c "echo \$\$ > '$CG/cgroup.procs'; exec curl --noproxy '*' -k \
	--max-time 20 --connect-timeout 8 \
	--resolve cloudflare.com:443:${TARGET%:*} \
	-s -o /dev/null -w 'http=%{http_code} time=%{time_total}s\n' \
	https://cloudflare.com/"

sleep 1
echo "=== loader ==="
cat "$LOG_LOADER"
echo "=== trace ==="
grep -a 'race redirect' "$LOG_TRACE" 2>/dev/null | tail -10 || echo "(no trace)"
echo "=== proxy ==="
tail -30 "$LOG_PROXY"
