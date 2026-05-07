"""
server.py — Simple IPv6 TCP server for h0
Self-assigns h0's IPv6 if p4-utils didn't. Listens on port 80.
Automatically starts tcpdump on h0-eth0 and saves capture.pcap to
/home/ayush/my/ when Ctrl+C is pressed.

Run on h0 xterm BEFORE firing any traffic:
    python3 /home/ayush/my/server.py
"""

import socket, threading, re, subprocess, time

subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'], capture_output=True)

HOST      = "::"
PORT      = 80
H0_IPV6   = "2001:1:1::10"
PCAP_PATH_A = "/home/ayush/my/capture_path_a.pcap"  # eth0 — path_a_sw (SYNs)
PCAP_PATH_B = "/home/ayush/my/capture_path_b.pcap"  # eth1 — path_b_sw (ACKs)

CLIENT_NEIGHBORS = {
    '2001:1:1::1': 'aa:00:00:00:00:01',
    '2001:1:1::2': 'aa:00:00:00:00:02',
    '2001:1:1::3': 'aa:00:00:00:00:03',
    '2001:1:1::4': 'aa:00:00:00:00:04',
    '2001:1:1::5': 'aa:00:00:00:00:05',
}

stats = {'connections': 0}

def get_iface():
    result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        m = re.search(r'\d+:\s+([\w-]+eth\d+)', line)
        if m:
            return m.group(1)
    return None

def get_all_ifaces():
    result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
    ifaces = []
    for line in result.stdout.split('\n'):
        m = re.search(r'\d+:\s+([\w-]+eth\d+)', line)
        if m:
            ifaces.append(m.group(1))
    return ifaces

def setup(iface):
    result = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True)
    if H0_IPV6 not in result.stdout:
        subprocess.run(['ip', '-6', 'addr', 'add', 'nodad', H0_IPV6 + '/64', 'dev', iface],
                       capture_output=True)
        print(f"[server] Assigned {H0_IPV6}/64 to {iface} (nodad)")
    for ip, mac in CLIENT_NEIGHBORS.items():
        subprocess.run(['ip', '-6', 'neigh', 'replace', ip,
                        'lladdr', mac, 'dev', iface, 'nud', 'permanent'],
                       capture_output=True)
    print(f"[server] Static neighbor entries installed for all clients on {iface}")

def _monitor_synrecv():
    prev = 0
    while True:
        try:
            r = subprocess.run(['ss', '-6', '-n', 'state', 'syn-recv'],
                               capture_output=True, text=True)
            lines = [l for l in r.stdout.strip().split('\n')
                     if l and 'Recv-Q' not in l]
            count = len(lines)
            if count != prev:
                if count > 0:
                    print(f"[server] *** ATTACK TRAFFIC: {count} half-open SYNs hitting h0 ***")
                elif prev > 0:
                    print(f"[server] Attack stopped — half-open connections cleared (block rule working)")
                prev = count
        except Exception:
            pass
        time.sleep(0.3)

def handle(conn, addr):
    stats['connections'] += 1
    n = stats['connections']
    print(f"[server] Connection #{n} from {addr[0]}")
    try:
        conn.recv(1024)
        conn.send(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        conn.close()
    except Exception as e:
        print(f"[server] Connection #{n} error: {e}")

def start():
    iface = get_iface()
    if iface:
        setup(iface)

    # Start tcpdump on every interface before listening so no packets are missed
    pcap_paths = [PCAP_PATH_A, PCAP_PATH_B]
    all_ifaces = get_all_ifaces()
    tcpdump_procs = []
    for i, ifc in enumerate(all_ifaces[:2]):
        path = pcap_paths[i]
        p = subprocess.Popen(
            ['tcpdump', '-i', ifc, '-w', path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        tcpdump_procs.append((ifc, path, p))
        print(f"[server] tcpdump capturing on {ifc} -> {path}")
    if not tcpdump_procs:
        print("[server] WARNING: no interfaces detected — tcpdump not started")
    else:
        time.sleep(0.3)   # let tcpdump open and start capturing

    threading.Thread(target=_monitor_synrecv, daemon=True).start()

    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1000)
    print(f"[server] Listening on [::]:{PORT} (IPv6)")
    print(f"[server] Ctrl+C to stop")
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print(f"\n[server] Done. Total connections served: {stats['connections']}")
        s.close()
        for ifc, path, p in tcpdump_procs:
            p.terminate()
            p.wait()
            print(f"[server] Capture saved: {ifc} -> {path}")

if __name__ == '__main__':
    start()
