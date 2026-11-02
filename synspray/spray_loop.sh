#!/bin/bash
# 以 root 运行（由 test.sh 通过 sudo 调用）
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="$1"; PORT="$2"; TRIALS="$3"; COPIES="$4"; INTERVAL="$5"; TIMEOUT="$6"
for _ in $(seq 1 "$TRIALS"); do
	"$HERE/synspray" "$TARGET" "$PORT" 0 "$COPIES" "$INTERVAL" "$TIMEOUT" wlan0 || true
done
