#!/usr/bin/env python3
"""
UDP 多源端口首包竞速中继。

对每个新的客户端流，用 N 个连续源端口同时把首个数据报发往目标；
第一个收到目标回复的 socket 胜出，其余关闭；后续数据报只走胜者。

用法:
  python3 udp_race.py --listen 18081 --target 203.107.6.88 --target-port 123 \
      --n 5 --base 20000 --step 8
"""

import argparse
import select
import socket
import threading
import time

SO_BINDTODEVICE = 25
IFACE = b"wlan0"


class PortWindow:
    def __init__(self, start, end, step):
        self.start, self.end, self.step = start, end, step
        self.cur = start
        self.lock = threading.Lock()

    def take(self):
        with self.lock:
            base = self.cur
            self.cur += self.step
            if self.cur + 8 > self.end:
                self.cur = self.start
            return base


class Flow:
    def __init__(self, sock, target):
        self.sock = sock
        self.target = target
        self.last = time.time()


def race_udp(target, data, n, base, timeout=1.2):
    socks = []
    ports = {}
    for i in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, IFACE)
        try:
            s.bind(("", base + i))
            s.sendto(data, target)
        except OSError:
            s.close()
            continue
        s.setblocking(False)
        socks.append(s)
        ports[s] = base + i

    t0 = time.time()
    winner = reply = winport = None
    while socks and time.time() - t0 < timeout:
        r, _, _ = select.select(socks, [], [], 0.05)
        for s in r:
            try:
                d, a = s.recvfrom(65535)
            except OSError:
                continue
            if a[0] == target[0] and a[1] == target[1]:
                winner, reply, winport = s, d, ports.get(s)
                break
        if winner is not None:
            break

    for s in socks:
        if s is not winner:
            s.close()
    if winner is not None:
        winner.setblocking(True)
    return winner, reply, winport, (time.time() - t0) * 1000


def start_flow(listener, client, data, target, n, window, rounds, flows, lock, starting):
    try:
        winner = reply = winport = None
        for _ in range(rounds):
            base = window.take()
            winner, reply, winport, dt = race_udp(target, data, n, base)
            if winner is not None:
                break
        if winner is None:
            print(f"FAIL {client} -> {target}", flush=True)
            return
        listener.sendto(reply, client)
        flow = Flow(winner, target)
        with lock:
            flows[client] = flow
            starting.discard(client)
        print(f"OK   {client} -> {target} winner={winport} t={dt:.0f}ms", flush=True)

        while True:
            r, _, _ = select.select([winner], [], [], 5)
            if not r:
                if time.time() - flow.last > 60:
                    break
                continue
            d, a = winner.recvfrom(65535)
            if a[0] != target[0] or a[1] != target[1]:
                continue
            listener.sendto(d, client)
            flow.last = time.time()
    except Exception as exc:
        print("ERR", exc, flush=True)
    finally:
        with lock:
            flows.pop(client, None)
            starting.discard(client)
        try:
            if winner is not None:
                winner.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, default=18081)
    ap.add_argument("--target", required=True)
    ap.add_argument("--target-port", type=int, required=True)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--base", type=int, default=20000)
    ap.add_argument("--end", type=int, default=32000)
    ap.add_argument("--step", type=int, default=8)
    args = ap.parse_args()

    target = (args.target, args.target_port)
    window = PortWindow(args.base, args.end, args.step)
    flows = {}
    starting = set()
    lock = threading.Lock()

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.listen))
    print(f"listen 127.0.0.1:{args.listen} -> {target} n={args.n} "
          f"ports=[{args.base},{args.end}) step={args.step}", flush=True)

    while True:
        data, client = listener.recvfrom(65535)
        with lock:
            flow = flows.get(client)
            if flow is not None:
                try:
                    flow.sock.sendto(data, target)
                    flow.last = time.time()
                except OSError:
                    pass
                continue
            if client in starting:
                continue
            starting.add(client)
        threading.Thread(
            target=start_flow,
            args=(listener, client, data, target, args.n, window, args.rounds, flows, lock, starting),
            daemon=True,
        ).start()


if __name__ == "__main__":
    main()
