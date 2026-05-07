"""
flood.py — Realistic flash crowd simulation with mixed traffic pattern.
Self-assigns IPv6 if p4-utils didn't.

Traffic pattern (200 total connections):
  Phase 1 —  70 simultaneous burst   (viral link / event spike)
  Phase 2 —  70 sequential @ 10/sec  (sustained high-interest traffic)
  Phase 3 —  30 simultaneous burst   (second spike / retweet wave)
  Phase 4 —  30 sequential @ random  (traffic settling back down)

All phases use real TCP connections — ACKs always cancel SYNs in CMS,
so the counter never cleanly accumulates to 64 regardless of rate.
Sequential phases are inherently safe: counter bounces 0→1→0 per connection.

Run from any legit host xterm:
    python3 /home/ayush/my/flood.py
"""

import socket, re, subprocess, threading, time, random

subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'], capture_output=True)

VICTIM_IP  = "2001:1:1::10"
VICTIM_MAC = "aa:00:00:00:00:00"
DST_PORT   = 80

IPV6_MAP = {
    'h0': '2001:1:1::10', 'h1': '2001:1:1::1', 'h2': '2001:1:1::2',
    'h3': '2001:1:1::3',  'h4': '2001:1:1::4', 'h5': '2001:1:1::5',
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

if iface:
    subprocess.run(['ip', '-6', 'neigh', 'replace', VICTIM_IP,
                    'lladdr', VICTIM_MAC, 'dev', iface, 'nud', 'permanent'],
                   capture_output=True)

def single_connection():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((VICTIM_IP, DST_PORT, 0, 0))
        s.send(b"GET / HTTP/1.0\r\nHost: server\r\n\r\n")
        s.recv(1024)
        s.close()
    except Exception:
        pass

def burst(n, label):
    print(f"[flood] {label}: firing {n} simultaneous connections...")
    threads = [threading.Thread(target=single_connection) for _ in range(n)]
    for t in threads: t.start()
    for t in threads: t.join()
    print(f"[flood] {label}: done")

print(f"[flood] Host  : {my_ipv6}")
print(f"[flood] Target: {VICTIM_IP}:{DST_PORT}")
print(f"[flood] Pattern: 70 burst → 70 @ 10/sec → 30 burst → 30 @ random")

# Phase 1: 70 simultaneous burst
burst(70, "Phase-1 burst")

# Phase 2: 70 sequential at 10/sec (faster than traffic.py but safe — ACKs cancel SYNs)
print(f"[flood] Phase-2: 70 connections at 10/sec...")
for i in range(70):
    single_connection()
    time.sleep(0.1)
print(f"[flood] Phase-2: done")

# Phase 3: 30 simultaneous burst
burst(30, "Phase-3 burst")

# Phase 4: 30 at random speed between 5–15/sec (0.067–0.2s interval)
print(f"[flood] Phase-4: 30 connections at random speed (5–15/sec)...")
for i in range(30):
    single_connection()
    time.sleep(random.uniform(0.067, 0.2))
print(f"[flood] Phase-4: done")

print(f"[flood] Done — 200 connections total from {my_ipv6}")
