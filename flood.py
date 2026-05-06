"""
flood.py — Flash crowd simulation
Self-assigns IPv6 if p4-utils didn't. Fires simultaneous TCP connections.
Run from any legit host xterm:
    python3 /home/ayush/my/flood.py
"""

import socket, re, subprocess, threading

subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'], capture_output=True)

VICTIM_IP  = "2001:1:1::10"      # h0 IPv6 — matches network.py
VICTIM_MAC = "aa:00:00:00:00:00" # h0 MAC  — matches network.py
DST_PORT   = 80
BURST_SIZE = 100

IPV6_MAP = {
    'h0': '2001:1:1::10',
    'h1': '2001:1:1::1',
    'h2': '2001:1:1::2',
    'h3': '2001:1:1::3',
    'h4': '2001:1:1::4',
    'h5': '2001:1:1::5',
}

def get_iface_info():
    result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
    iface = None
    for line in result.stdout.split('\n'):
        m = re.search(r'\d+:\s+([\w-]+eth\d+)', line)
        if m:
            iface = m.group(1)
            break
    if not iface:
        return None, "unknown"

    result = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True)
    ip6_m = re.search(r'inet6 (2001[0-9a-f:]+)/\d+', result.stdout)
    if ip6_m:
        ipv6 = ip6_m.group(1)
    else:
        hostname = iface.split('-eth')[0]
        ipv6 = IPV6_MAP.get(hostname, "unknown")
        if ipv6 != "unknown":
            subprocess.run(['ip', '-6', 'addr', 'add', 'nodad', ipv6 + '/64', 'dev', iface],
                           capture_output=True)
            print(f"[flood] Assigned {ipv6}/64 to {iface} (nodad)")

    return iface, ipv6

iface, my_ipv6 = get_iface_info()

# Static neighbor entry for h0 — bypasses NDP
if iface:
    subprocess.run(['ip', '-6', 'neigh', 'replace', VICTIM_IP,
                    'lladdr', VICTIM_MAC, 'dev', iface, 'nud', 'permanent'],
                   capture_output=True)

def single_connection(idx):
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((VICTIM_IP, DST_PORT, 0, 0))
        s.send(b"GET / HTTP/1.0\r\nHost: server\r\n\r\n")
        s.recv(1024)
        s.close()
    except Exception:
        pass

print(f"[flood] Host  : {my_ipv6}")
print(f"[flood] Target: {VICTIM_IP}:{DST_PORT}")
print(f"[flood] Firing {BURST_SIZE} simultaneous connections (flash crowd)...")

threads = [threading.Thread(target=single_connection, args=(i,))
           for i in range(BURST_SIZE)]
for t in threads:
    t.start()
for t in threads:
    t.join()

print(f"[flood] Done — {BURST_SIZE} simultaneous connections from {my_ipv6}")
