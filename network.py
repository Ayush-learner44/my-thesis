from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()
net.setLogLevel('info')

# ================================================================
# ASYMMETRIC TOPOLOGY
#
#   h1 h2 h3 h4 h5
#        |
#     merge_sw          (traffic_splitter.p4)
#     /        \
# path_a_sw  path_b_sw  (ddos_detector.p4 on both)
#     \        /
#       h0 (server — two interfaces, one per path)
#
# merge_sw ports:
#   1=h1  2=h2  3=h3  4=h4  5=h5  6=path_a_sw  7=path_b_sw
#
# path_a_sw ports:
#   1=merge_sw  2=h0 (h0-eth0)
#
# path_b_sw ports:
#   1=merge_sw  2=h0 (h0-eth1)
# ================================================================

# ── Switches ────────────────────────────────────────────────────
net.addP4RuntimeSwitch('merge_sw')
net.addP4RuntimeSwitch('path_a_sw')
net.addP4RuntimeSwitch('path_b_sw')

net.setP4Source('merge_sw',  'p4src/traffic_splitter.p4')
net.setP4Source('path_a_sw', 'p4src/ddos_detector.p4')
net.setP4Source('path_b_sw', 'p4src/ddos_detector.p4')
net.setCompiler(p4rt=True)

# ── Hosts ───────────────────────────────────────────────────────
net.addHost('h0')   # server — connects to BOTH path_a_sw and path_b_sw
net.addHost('h1')
net.addHost('h2')
net.addHost('h3')
net.addHost('h4')
net.addHost('h5')

# ── Links ───────────────────────────────────────────────────────
# h1-h5 → merge_sw (client side, ports 1-5)
net.addLink('merge_sw', 'h1', port1=1, port2=0)
net.addLink('merge_sw', 'h2', port1=2, port2=0)
net.addLink('merge_sw', 'h3', port1=3, port2=0)
net.addLink('merge_sw', 'h4', port1=4, port2=0)
net.addLink('merge_sw', 'h5', port1=5, port2=0)

# merge_sw → path_a_sw (port 6) and path_b_sw (port 7)
# PATH_A_PORT=6 and PATH_B_PORT=7 in traffic_splitter.p4 must match these
net.addLink('merge_sw', 'path_a_sw', port1=6, port2=1)
net.addLink('merge_sw', 'path_b_sw', port1=7, port2=1)

# path_a_sw → h0 (h0 gets eth0 from this link)
net.addLink('path_a_sw', 'h0', port1=2, port2=0)

# path_b_sw → h0 (h0 gets eth1 from this link)
net.addLink('path_b_sw', 'h0', port1=2, port2=1)

# ── MACs ────────────────────────────────────────────────────────
# Clients
net.setIntfMac('h1', 'merge_sw', 'aa:00:00:00:00:01')
net.setIntfMac('h2', 'merge_sw', 'aa:00:00:00:00:02')
net.setIntfMac('h3', 'merge_sw', 'aa:00:00:00:00:03')
net.setIntfMac('h4', 'merge_sw', 'aa:00:00:00:00:04')
net.setIntfMac('h5', 'merge_sw', 'aa:00:00:00:00:05')

# h0 gets the SAME MAC on both interfaces so all switches use one entry
# for h0 and all client scripts keep targeting aa:00:00:00:00:00
net.setIntfMac('h0', 'path_a_sw', 'aa:00:00:00:00:00')
net.setIntfMac('h0', 'path_b_sw', 'aa:00:00:00:00:00')

# ── IPv6 ────────────────────────────────────────────────────────
net.setIntfIp('h1', 'merge_sw', '2001:1:1::1/64')
net.setIntfIp('h2', 'merge_sw', '2001:1:1::2/64')
net.setIntfIp('h3', 'merge_sw', '2001:1:1::3/64')
net.setIntfIp('h4', 'merge_sw', '2001:1:1::4/64')
net.setIntfIp('h5', 'merge_sw', '2001:1:1::5/64')
net.setIntfIp('h0', 'path_a_sw', '2001:1:1::10/64')

# ── No ARP (Scapy sendp + static NDP in scripts) ────────────────
net.disableArpTables()
net.disableGwArp()

# ── Ports per switch ────────────────────────────────────────────
net.setThriftPort('merge_sw',  9090)
net.setThriftPort('path_a_sw', 9091)
net.setThriftPort('path_b_sw', 9092)

net.setGrpcPort('merge_sw',  9559)
net.setGrpcPort('path_a_sw', 9560)
net.setGrpcPort('path_b_sw', 9561)

net.enableCli()

print("""
\033[1;36m
================================================================
  EXPERIMENT QUICK REFERENCE  (scroll up if buried)
================================================================

  STEP 1 — CONTROLLER  (separate Linux terminal, run first):
    cd /home/ayush/my/controller
    python3 controller.py

  STEP 2 — SERVER  (open h0 xterm, run before traffic):
    xterm h0
    python3 /home/ayush/my/server.py

  STEP 3 — TRAFFIC  (paste into mininet CLI below):

    run_all.py    h1+h2 SYN flood  |  h3+h4+h5 legit
      py exec(open('/home/ayush/my/run_all.py').read(), {'net': net, '__builtins__': __builtins__})

    attacks.py    all 5 hosts SYN flood
      py exec(open('/home/ayush/my/attacks.py').read(), {'net': net, '__builtins__': __builtins__})

    flooding.py   all 5 hosts flash crowd (legit burst)
      py exec(open('/home/ayush/my/flooding.py').read(), {'net': net, '__builtins__': __builtins__})

    legit-traffic.py   all 5 hosts slow legit traffic
      py exec(open('/home/ayush/my/legit-traffic.py').read(), {'net': net, '__builtins__': __builtins__})

  STEP 4 — VERIFY  (Ctrl+C server.py first, then):
    python3 /home/ayush/my/verify.py

================================================================\033[0m
""")

net.startNetwork()
