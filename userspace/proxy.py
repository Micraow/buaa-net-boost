#!/usr/bin/env python3
"""
TCP 多源端口握手竞速代理。

支持 HTTP CONNECT 和 SOCKS5 CONNECT；对每个新连接用 N 个连续源端口
并行发 SYN，第一个完成握手的连接胜出，其余 RST 关闭；应用数据只走胜者。

用法:
  python3 proxy.py --listen 18080 --n 5 --rounds 2 --base 20000 --step 8
  curl -x http://127.0.0.1:18080 -k https://目标/
  curl --socks5-hostname 127.0.0.1:18080 https://目标/
"""

import argparse
import socket
import select
import struct
import threading
import time

SO_BINDTODEVICE = 25
IFACE = b"wlan0"


# ---------------------------------------------------------------- ports

class PortWindow:
    """在 [start, end) 内按 step 取窗口，避免复用刚用过的 5 元组。"""

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


# ---------------------------------------------------------------- race

def bind_connect(ip, port, lport):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, IFACE)
    s.setblocking(False)
    try:
        s.bind(("", lport))
    except OSError:
        s.close()
        return None
    try:
        s.connect((ip, port))
    except BlockingIOError:
        pass
    except OSError:
        s.close()
        return None
    return s


def close_rst(s):
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


def race_once(ip, port, n, base, timeout, verbose=False):
    socks = {}
    for i in range(n):
        s = bind_connect(ip, port, base + i)
        if s is not None:
            socks[s] = base + i
    if verbose:
        print(f"[syn] window {base}-{base + n - 1} ({len(socks)} sockets)", flush=True)

    t0 = time.perf_counter()
    winner = winport = None
    established = set()
    while socks and time.perf_counter() - t0 < timeout:
        _, w, x = select.select([], list(socks), list(socks), 0.01)
        for s in w:
            if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                p = socks[s]
                established.add(p)
                if verbose:
                    print(f"[syn] port {p} SYN-ACK at {(time.perf_counter()-t0)*1000:.0f}ms", flush=True)
                winner, winport = s, p
                break
        if winner is not None:
            break
        for s in x:
            p = socks.pop(s, None)
            if verbose and p is not None:
                print(f"[syn] port {p} failed at {(time.perf_counter()-t0)*1000:.0f}ms", flush=True)
            s.close()

    for s in list(socks):
        if s is winner:
            continue
        p = socks[s]
        if verbose:
            if p in established:
                print(f"[syn] port {p} also established, closing", flush=True)
            else:
                print(f"[syn] port {p} no reply, closing at {timeout*1000:.0f}ms", flush=True)
        close_rst(s)

    if winner is not None:
        winner.setblocking(True)
        winner.settimeout(None)
    return winner, winport, (time.perf_counter() - t0) * 1000


def race(ip, port, n, window, rounds, timeout=2.5, verbose=False):
    """多轮竞速；每轮换一个端口窗口，覆盖缺陷位。"""
    for r in range(rounds):
        base = window.take()
        s, p, dt = race_once(ip, port, n, base, timeout, verbose)
        if s is not None:
            return s, p, dt, r + 1
    return None, None, timeout * 1000, rounds


# ---------------------------------------------------------------- dns

def resolve(host):
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass

    pkt = struct.pack("!HHHHHH", 0x7777, 0x0100, 1, 0, 0, 0)
    for part in host.split("."):
        pkt += bytes([len(part)]) + part.encode()
    pkt += b"\x00" + struct.pack("!HH", 1, 1)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, IFACE)
    s.settimeout(3)
    try:
        s.sendto(pkt, ("223.5.5.5", 53))
        data, _ = s.recvfrom(2048)
    except OSError:
        s.close()
        return None
    s.close()

    ancount = struct.unpack("!H", data[6:8])[0]

    def skip_name(d, o):
        while True:
            l = d[o]
            if l == 0:
                return o + 1
            if l & 0xC0 == 0xC0:
                return o + 2
            o += l + 1

    off = skip_name(data, 12) + 4
    for _ in range(ancount):
        off = skip_name(data, off)
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            return socket.inet_ntoa(data[off:off + 4])
        off += rdlen
    return None


# ---------------------------------------------------------------- tunnel

def pipe(a, b, idle_timeout=600.0):
    last = time.time()
    while True:
        r, _, x = select.select([a, b], [], [a, b], 30)
        if x:
            return
        if not r:
            if time.time() - last > idle_timeout:
                return
            continue
        for s in r:
            try:
                data = s.recv(65536)
            except OSError:
                return
            if not data:
                return
            last = time.time()
            other = b if s is a else a
            try:
                other.sendall(data)
            except OSError:
                return


# ---------------------------------------------------------------- protocol

def recv_exact(c, n):
    buf = b""
    while len(buf) < n:
        d = c.recv(n - len(buf))
        if not d:
            return None
        buf += d
    return buf


def read_http_connect(c):
    req = b""
    while b"\r\n\r\n" not in req:
        d = c.recv(4096)
        if not d:
            return None
        req += d
        if len(req) > 65536:
            return None
    line = req.split(b"\r\n", 1)[0].decode(errors="replace")
    if not line.startswith("CONNECT "):
        return None
    host, port = line.split()[1].rsplit(":", 1)
    return host, int(port)


def read_socks5_connect(c):
    hdr = recv_exact(c, 2)
    if not hdr or hdr[0] != 5:
        return None
    methods = recv_exact(c, hdr[1])
    if methods is None:
        return None
    c.sendall(b"\x05\x00")

    req = recv_exact(c, 4)
    if not req or req[0] != 5 or req[1] != 1:
        return None
    atyp = req[3]
    if atyp == 1:
        host = socket.inet_ntoa(recv_exact(c, 4))
    elif atyp == 3:
        ln = recv_exact(c, 1)[0]
        host = recv_exact(c, ln).decode()
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(c, 16))
    else:
        return None
    port = struct.unpack("!H", recv_exact(c, 2))[0]
    c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
    return host, port


def handle(client, window, n, rounds, transparent=False, target=None, verbose=False):
    try:
        if transparent:
            ip, port = target
            winner, winport, dt, round_used = race(ip, port, n, window, rounds, verbose=verbose)
            if winner is None:
                print(f"[transparent] FAIL -> {ip}:{port}", flush=True)
                client.close()
                return
            print(f"[transparent] OK -> {ip}:{port} winner={winport} round={round_used} t={dt:.0f}ms", flush=True)
            pipe(client, winner)
            return

        first = client.recv(1, socket.MSG_PEEK)
        if not first:
            client.close()
            return
        if first == b"\x05":
            target = read_socks5_connect(client)
        else:
            target = read_http_connect(client)
        if not target:
            client.close()
            return

        host, port = target
        ip = resolve(host)
        if ip is None:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client.close()
            return

        winner, winport, dt, round_used = race(ip, port, n, window, rounds, verbose=verbose)
        if winner is None:
            print(f"FAIL {host}->{ip}:{port} n={n} rounds={rounds} t={dt:.0f}ms", flush=True)
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client.close()
            return

        print(f"OK   {host}->{ip}:{port} winner={winport} round={round_used} t={dt:.0f}ms", flush=True)
        if first != b"\x05":
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        pipe(client, winner)
    except Exception as exc:
        print("ERR", exc, flush=True)
    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, default=18080)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--base", type=int, default=20000)
    ap.add_argument("--end", type=int, default=32000)
    ap.add_argument("--step", type=int, default=8)
    ap.add_argument("--transparent", action="store_true",
                    help="不解析 CONNECT/SOCKS5，直接把字节转发到 --target")
    ap.add_argument("--target", help="transparent 模式的目标 ip:port")
    ap.add_argument("--verbose", action="store_true", help="打印每个源端口的 SYN 结果")
    args = ap.parse_args()

    target = None
    if args.transparent:
        if not args.target:
            ap.error("--transparent 需要 --target ip:port")
        host, port = args.target.rsplit(":", 1)
        ip = resolve(host)
        if ip is None:
            ap.error(f"无法解析 {host}")
        target = (ip, int(port))

    window = PortWindow(args.base, args.end, args.step)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.listen))
    srv.listen(64)
    print(f"listen 127.0.0.1:{args.listen} n={args.n} rounds={args.rounds} "
          f"ports=[{args.base},{args.end}) step={args.step} "
          f"transparent={args.transparent} target={target}", flush=True)

    while True:
        c, _ = srv.accept()
        threading.Thread(
            target=handle,
            args=(c, window, args.n, args.rounds, args.transparent, target, args.verbose),
            daemon=True,
        ).start()


if __name__ == "__main__":
    main()
