#!/bin/bash
# 对比：正常 connect vs 同 5 元组复读 SYN。
# 用法：sudo ./test.sh <v6-target> <port> [trials] [copies] [interval_ms] [timeout_ms]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-2402:f000:1:400::2}"
PORT="${2:-443}"
TRIALS="${3:-10}"
COPIES="${4:-4}"
INTERVAL="${5:-20}"
TIMEOUT="${6:-3000}"

if [ ! -x "$HERE/synspray" ]; then
	(cd "$HERE" && gcc -O2 -Wall -o synspray synspray.c)
fi

echo "=== normal connect ==="
python3 - "$TARGET" "$PORT" "$TRIALS" <<'PY'
import select, socket, statistics, sys, time
target, port, trials = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
ok = 0; ts = []
for _ in range(trials):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, 25, b"wlan0")
    s.setblocking(False)
    t = time.perf_counter()
    try:
        s.connect((target, port))
    except BlockingIOError:
        pass
    except Exception:
        s.close(); continue
    _, w, _ = select.select([], [s], [], 3.0)
    if w and s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
        ok += 1; ts.append((time.perf_counter() - t) * 1000)
    s.close()
print(f"normal {ok}/{trials} median={statistics.median(ts) if ts else 0:.0f}ms")
PY

echo "=== synspray (需要 root) ==="
sudo "$HERE/spray_loop.sh" "$TARGET" "$PORT" "$TRIALS" "$COPIES" "$INTERVAL" "$TIMEOUT"
