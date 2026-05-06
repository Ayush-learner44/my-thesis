"""
server.py — Simple IPv6 TCP server for h0
Self-assigns h0's IPv6 if p4-utils didn't. Listens on port 80.
Run on h0 xterm BEFORE firing any traffic:
    python3 /home/ayush/my/server.py
"""

import socket, threading, re, subprocess

# Enable IPv6 in this namespace (WSL2 disables it on new veth interfaces)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'], capture_output=True)

HOST  = "::"   # listen on all IPv6 interfaces
PORT  = 80
H0_IPV6 = "2001:1:1::10"   # h0 IPv6 — matches network.py

# Client MACs and IPv6s for static neighbor entries
# (h0 needs these to send SYN-ACK without NDP)
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

def setup(iface):
    # Self-assign h0's IPv6 if p4-utils didn't
    result = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True)
    if H0_IPV6 not in result.stdout:
        subprocess.run(['ip', '-6', 'addr', 'add', H0_IPV6 + '/64', 'dev', iface],
                       capture_output=True)
        print(f"[server] Assigned {H0_IPV6}/64 to {iface}")

    # Static neighbor entries for all clients — bypasses NDP
    for ip, mac in CLIENT_NEIGHBORS.items():
        subprocess.run(['ip', '-6', 'neigh', 'replace', ip,
                        'lladdr', mac, 'dev', iface, 'nud', 'permanent'],
                       capture_output=True)
    print(f"[server] Static neighbor entries installed for all clients on {iface}")

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

    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1000)
    print(f"[server] Listening on [::]:{PORT} (IPv6)")
    print(f"[server] Ctrl+C to stop")
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print(f"\n[server] Done. Total connections served: {stats['connections']}")
        s.close()

if __name__ == '__main__':
    start()
