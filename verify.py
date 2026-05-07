#!/usr/bin/env python3
"""
verify.py — Post-experiment DDoS detection metrics calculator.

BEFORE the experiment, start tcpdump on h0:
    (in h0 xterm)  tcpdump -i h0-eth0 -w /home/ayush/my/capture.pcap &

After experiment, stop it:
    kill %1   (or killall tcpdump)

Then run this script:
    python3 /home/ayush/my/verify.py
    python3 /home/ayush/my/verify.py /path/to/other.pcap
"""

from scapy.all import rdpcap, IPv6, TCP
import sys, os

IP_TO_HOST = {
    '2001:1:1::1':  'h1',
    '2001:1:1::2':  'h2',
    '2001:1:1::3':  'h3',
    '2001:1:1::4':  'h4',
    '2001:1:1::5':  'h5',
    '2001:1:1::10': 'h0 (server)',
}

ALL_CLIENT_IPS = {
    '2001:1:1::1', '2001:1:1::2', '2001:1:1::3',
    '2001:1:1::4', '2001:1:1::5',
}

# Each scenario defines: attacker_ips, legit_ips, total_attack, total_legit
SCENARIOS = {
    '1': {
        'name':          'run_all.py  —  h1,h2 attack  |  h3,h4,h5 legit',
        'attacker_ips':  {'2001:1:1::1', '2001:1:1::2'},
        'legit_ips':     {'2001:1:1::3', '2001:1:1::4', '2001:1:1::5'},
        'total_attack':  4000,  # 2000 SYNs × 2 attacker hosts
        'total_legit':   180,   # 60 conns × 3 legit hosts
    },
    '2': {
        'name':          'attacks.py  —  h1–h5 all attack',
        'attacker_ips':  ALL_CLIENT_IPS.copy(),
        'legit_ips':     set(),
        'total_attack':  10000, # 2000 SYNs × 5 hosts
        'total_legit':   0,
    },
    '3': {
        'name':          'flooding.py  —  h1–h5 all flash crowd (legit)',
        'attacker_ips':  set(),
        'legit_ips':     ALL_CLIENT_IPS.copy(),
        'total_attack':  0,
        'total_legit':   1000,  # 200 conns × 5 hosts
    },
    '4': {
        'name':          'legit-traffic.py  —  h1–h5 all legit traffic',
        'attacker_ips':  set(),
        'legit_ips':     ALL_CLIENT_IPS.copy(),
        'total_attack':  0,
        'total_legit':   300,   # 60 conns × 5 hosts
    },
    '5': {
        'name':          'Single attack.py from h1 only',
        'attacker_ips':  {'2001:1:1::1'},
        'legit_ips':     set(),
        'total_attack':  2000,
        'total_legit':   0,
    },
}


def pick_scenario():
    print("\n" + "=" * 60)
    print("  verify.py — DDoS Detection Metrics")
    print("=" * 60)
    print("\nWhich script did you run?\n")
    for k, v in SCENARIOS.items():
        print(f"  {k}.  {v['name']}")
    print("  6.  Custom — enter IPs and counts manually\n")

    choice = input("Enter choice [1-6]: ").strip()

    if choice in SCENARIOS:
        s = SCENARIOS[choice]
        attacker_ips = s['attacker_ips']
        legit_ips    = s['legit_ips']
        total_attack = s['total_attack']
        total_legit  = s['total_legit']

    elif choice == '6':
        print("\nEnter attacker IPs comma-separated (e.g. 2001:1:1::1,2001:1:1::2):")
        raw = input("  Attacker IPs (blank = none): ").strip()
        attacker_ips = {ip.strip() for ip in raw.split(',') if ip.strip()}

        print("Enter legit IPs comma-separated (blank = none):")
        raw = input("  Legit IPs: ").strip()
        legit_ips = {ip.strip() for ip in raw.split(',') if ip.strip()}

        total_attack = int(input("  Total attack SYNs sent (e.g. 200): ").strip())
        total_legit  = int(input("  Total legit conns sent (e.g. 180): ").strip())

    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)

    return attacker_ips, legit_ips, total_attack, total_legit


def count_syns(pkts, attacker_ips, legit_ips):
    """Count pure SYN (SYN=1, ACK=0) packets reaching h0 from each group."""
    TCP_SYN = 0x002
    TCP_ACK = 0x010

    attack_reached   = 0
    legit_reached    = 0
    attack_per_ip    = {}
    legit_per_ip     = {}

    for pkt in pkts:
        if IPv6 not in pkt or TCP not in pkt:
            continue
        flags = int(pkt[TCP].flags)
        if not ((flags & TCP_SYN) and not (flags & TCP_ACK)):
            continue                    # skip SYN-ACKs, ACKs, data, FIN etc.

        src = pkt[IPv6].src
        if src in attacker_ips:
            attack_reached += 1
            attack_per_ip[src] = attack_per_ip.get(src, 0) + 1
        elif src in legit_ips:
            legit_reached += 1
            legit_per_ip[src] = legit_per_ip.get(src, 0) + 1

    return attack_reached, legit_reached, attack_per_ip, legit_per_ip


def print_results(attack_reached, legit_reached, attack_per_ip, legit_per_ip,
                  attacker_ips, legit_ips, total_attack, total_legit):

    FN = attack_reached                  # attack SYNs that slipped through to h0
    TN = legit_reached                   # legit SYNs that correctly reached h0
    TP = max(0, total_attack - FN)       # attack SYNs blocked by the switch
    FP = max(0, total_legit  - TN)       # legit SYNs incorrectly blocked

    total     = TP + TN + FP + FN
    accuracy  = (TP + TN) / total                         if total            > 0 else 0
    precision = TP / (TP + FP)                            if (TP + FP)        > 0 else 0
    recall    = TP / (TP + FN)                            if (TP + FN)        > 0 else 0
    f1        = 2*precision*recall / (precision + recall) if (precision+recall)> 0 else 0

    # ── IP breakdown ──────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("IP BREAKDOWN")
    print("=" * 60)

    per_attacker = (total_attack // len(attacker_ips)) if attacker_ips else 0
    print(f"\n  Attacker IPs ({len(attacker_ips)}):")
    if attacker_ips:
        for ip in sorted(attacker_ips):
            host    = IP_TO_HOST.get(ip, ip)
            reached = attack_per_ip.get(ip, 0)
            blocked = max(0, per_attacker - reached)
            print(f"    {host:6s} ({ip})  —  reached h0: {reached:4d}  blocked: {blocked:4d}")
    else:
        print("    none")

    print(f"\n  Legit IPs ({len(legit_ips)}):")
    if legit_ips:
        for ip in sorted(legit_ips):
            host    = IP_TO_HOST.get(ip, ip)
            reached = legit_per_ip.get(ip, 0)
            print(f"    {host:6s} ({ip})  —  SYNs reached h0: {reached:4d}")
    else:
        print("    none")

    # ── Confusion matrix ──────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("CONFUSION MATRIX")
    print("=" * 60)
    print(f"  TP  attack SYNs blocked          : {TP:6d}   (total_attack_sent - FN)")
    print(f"  FN  attack SYNs reached h0       : {FN:6d}   (slipped through)")
    print(f"  TN  legit SYNs reached h0        : {TN:6d}   (correctly passed)")
    print(f"  FP  legit SYNs blocked           : {FP:6d}   (total_legit_sent - TN)")
    print(f"  ---")
    print(f"  total_attack_sent                : {total_attack:6d}")
    print(f"  total_legit_sent                 : {total_legit:6d}")

    # ── Metrics ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("METRICS")
    print("=" * 60)
    print(f"  accuracy  : {accuracy:.4f}   ({accuracy:.2%})")
    print(f"  precision : {precision:.4f}   ({precision:.2%})")
    print(f"  recall    : {recall:.4f}   ({recall:.2%})")
    print(f"  f1        : {f1:.4f}   ({f1:.2%})")
    print("=" * 60)


def main():
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else '/home/ayush/my/capture.pcap'

    if not os.path.exists(pcap_file):
        print(f"\nERROR: pcap not found: {pcap_file}")
        print("\nStart tcpdump on h0 BEFORE the experiment:")
        print("  (h0 xterm)  tcpdump -i h0-eth0 -w /home/ayush/my/capture.pcap &")
        print("  After experiment: kill %1")
        sys.exit(1)

    attacker_ips, legit_ips, total_attack, total_legit = pick_scenario()

    print(f"\nReading {pcap_file} ...")
    pkts = rdpcap(pcap_file)
    print(f"  {len(pkts)} total packets loaded")

    attack_reached, legit_reached, attack_per_ip, legit_per_ip = \
        count_syns(pkts, attacker_ips, legit_ips)

    print_results(attack_reached, legit_reached, attack_per_ip, legit_per_ip,
                  attacker_ips, legit_ips, total_attack, total_legit)


if __name__ == '__main__':
    main()
