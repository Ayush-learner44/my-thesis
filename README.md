# my — SYN Flood Detection (Improved Architecture)

Improved implementation over P4M3 paper.
Single switch topology. IPv6 only. gRPC/P4Runtime controller.
CMS with dual digest (FIRST_SEEN + THRESHOLD). IP-based blocking.

---

## Topology

```
h1 ──┐
h2 ──┤
h3 ──┤── switch ── h0  (server)
h4 ──┤
h5 ──┘
```

- h0 : server (victim)
- h1, h2 : attackers
- h3, h4, h5 : legit hosts

---

## Files

| File | Purpose |
|------|---------|
| `network.py` | Mininet topology |
| `p4src/ddos_detector.p4` | P4 data plane |
| `controller/controller.py` | Python gRPC controller + ML |
| `server.py` | TCP server for h0 |
| `attack.py` | SYN flood — auto-detects host MAC/IPv6 |
| `traffic.py` | Legit traffic — real TCP handshakes |
| `flood.py` | Flash crowd — burst of simultaneous connections |
| `run_all.py` | Fire all hosts simultaneously from mininet CLI |
| `ml/models/` | Copy from p4m3-grpc (same models) |

---

## How to Run

### Step 1 — Start topology
```bash
cd /home/ayush/my
sudo python3 network.py
```

### Step 2 — Start controller (new terminal)
```bash
cd /home/ayush/my
sudo python3 controller/controller.py
```

### Step 3 — Start server on h0
In mininet CLI:
```
mininet> xterm h0
```
In h0 xterm:
```bash
python3 /home/ayush/my/server.py
```

### Step 4 — Fire all traffic simultaneously
In mininet CLI:
```
mininet> py exec(open('/home/ayush/my/run_all.py').read())
```

### Step 5 — Check logs
```
mininet> py net.get('h1').cmd('cat /tmp/my_h1.log')
mininet> py net.get('h3').cmd('cat /tmp/my_h3.log')
```

---

## Flash Crowd Test (separate experiment)

Open xterms for h3, h4, h5 and run flood.py simultaneously:
```
mininet> xterm h3
mininet> xterm h4
mininet> xterm h5
```
In each xterm at the same time:
```bash
python3 /home/ayush/my/flood.py
```
System should NOT flag this as attack (all handshakes complete).

---

## Update VICTIM_MAC

After running network.py, check h0's MAC:
```
mininet> h0 ip link show
```
Update `VICTIM_MAC` in `attack.py` to match.

---

## ML Models

Copy ml folder from p4m3-grpc:
```bash
cp -r /home/ayush/p4m3-grpc/ml /home/ayush/my/
```

---

## Improvements Over P4M3

| Metric | P4M3 Paper | This System |
|--------|-----------|-------------|
| Accuracy | 86% (recall) | 88.97% |
| Precision | not reported | 100% |
| Recall | 86% | 85.67% |
| F1 | not reported | 92.28% |
| False Positives | not reported | 0 |
| Blocking | MAC-based | IP-based (spoof-resistant) |
| Digest types | single | dual (FIRST_SEEN + THRESHOLD) |
