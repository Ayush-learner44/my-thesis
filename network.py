from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()
net.setLogLevel('info')

# Switch — single P4RuntimeSwitch enables gRPC/P4Runtime control plane
net.addP4RuntimeSwitch('s1')
net.setP4SourceAll('p4src/ddos_detector.p4')
net.setCompiler(p4rt=True)   # generates ddos_detector_p4rt.txt alongside ddos_detector.json

# Hosts
net.addHost('h0')   # server (right side, port 6)
net.addHost('h1')   # clients (left side, ports 1-5)
net.addHost('h2')
net.addHost('h3')
net.addHost('h4')
net.addHost('h5')

# Links with explicit port numbers
# s1: h1=1, h2=2, h3=3, h4=4, h5=5, h0=6
net.addLink('s1', 'h1', port1=1, port2=0)
net.addLink('s1', 'h2', port1=2, port2=0)
net.addLink('s1', 'h3', port1=3, port2=0)
net.addLink('s1', 'h4', port1=4, port2=0)
net.addLink('s1', 'h5', port1=5, port2=0)
net.addLink('s1', 'h0', port1=6, port2=0)

# No CPU ports — digest() sends features via gRPC stream directly,
# no virtual interface needed.

# MACs — must match hardcoded values in attack/benign scripts
net.setIntfMac('h1', 's1', 'aa:00:00:00:00:01')
net.setIntfMac('h2', 's1', 'aa:00:00:00:00:02')
net.setIntfMac('h3', 's1', 'aa:00:00:00:00:03')
net.setIntfMac('h4', 's1', 'aa:00:00:00:00:04')
net.setIntfMac('h5', 's1', 'aa:00:00:00:00:05')
net.setIntfMac('h0', 's1', 'aa:00:00:00:00:00')

# IPv6 addresses only — p4-utils stores one IP per interface edge,
# calling setIntfIp twice overwrites. P4 program is IPv6-only anyway.
net.setIntfIp('h1', 's1', '2001:1:1::1/64')
net.setIntfIp('h2', 's1', '2001:1:1::2/64')
net.setIntfIp('h3', 's1', '2001:1:1::3/64')
net.setIntfIp('h4', 's1', '2001:1:1::4/64')
net.setIntfIp('h5', 's1', '2001:1:1::5/64')
net.setIntfIp('h0', 's1', '2001:1:1::10/64')

# No ARP needed — Scapy scripts use sendp() with hardcoded MACs (L2 injection)
net.disableArpTables()
net.disableGwArp()

# Thrift port (P4RuntimeSwitch still exposes Thrift — kept for register access)
net.setThriftPort('s1', 9090)

# gRPC port for P4Runtime controller
net.setGrpcPort('s1', 9559)

# net.enableLogAll()
# net.enablePcapDumpAll()
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
