import socket, select, struct, time, sys

def mk(ip, port, lport):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, 25, b"wlan0")
    s.setblocking(False)
    try:
        s.bind(("", lport))
    except Exception:
        s.close(); return None
    try:
        s.connect((ip, port))
    except BlockingIOError:
        pass
    except Exception:
        s.close(); return None
    return s

def race(ip, port, n=5, base=55000, timeout=2.0):
    socks = {}
    for i in range(n):
        s = mk(ip, port, base + i)
        if s: socks[s] = base + i
    t0 = time.perf_counter()
    winner = None; winport = None
    deadline = t0 + timeout
    while socks and time.perf_counter() < deadline:
        wl = list(socks.keys())
        try:
            _, w, x = select.select([], wl, wl, 0.01)
        except Exception:
            break
        for s in w:
            err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                winner = s; winport = socks[s]
                break
        if winner: break
        for s in x:
            if s in socks: del socks[s]
            s.close()
    # 关闭其余
    for s, p in list(socks.items()):
        if s is winner: continue
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii",1,0))
        s.close()
    if winner:
        winner.setblocking(True)
        winner.settimeout(5)
        return winner, winport, (time.perf_counter()-t0)*1000
    return None, None, (time.perf_counter()-t0)*1000

if __name__ == "__main__":
    ip, port = sys.argv[1], int(sys.argv[2])
    n = int(sys.argv[3]) if len(sys.argv)>3 else 5
    trials = int(sys.argv[4]) if len(sys.argv)>4 else 10
    base = int(sys.argv[5]) if len(sys.argv)>5 else 55000
    ok=0; ts=[]; wps=[]
    for _ in range(trials):
        s, wp, dt = race(ip, port, n, base=base)
        if s:
            ok+=1; ts.append(dt); wps.append(wp)
            try:
                s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
                s.recv(16)
            except Exception: pass
            s.close()
    import statistics
    print(f"target={ip}:{port} N={n} ok={ok}/{trials} median={statistics.median(ts) if ts else 0:.0f}ms winners_ports={wps[:10]}")
