# P4-Based SYN Flood DDoS Detection System

An in-network SYN flood DDoS detection and mitigation system implemented on a BMv2 P4 software switch. The system combines a **Count-Min Sketch (CMS)** in the data plane with a **5-model ML ensemble** in the control plane to detect and block SYN flood attackers at line rate — without any packet sampling, mirroring, or external monitoring.

Improves on the P4M3 paper baseline (86% recall, 89% F1) achieving **96.70% recall, 100% precision, 98.32% F1**.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Topology](#topology)
3. [Prerequisites & Installation](#prerequisites--installation)
4. [Project Structure](#project-structure)
5. [P4 Data Plane](#p4-data-plane)
6. [Control Plane & ML Ensemble](#control-plane--ml-ensemble)
7. [Running the System](#running-the-system)
8. [Traffic Scripts](#traffic-scripts)
9. [Experiment Scenarios](#experiment-scenarios)
10. [Verification & Metrics](#verification--metrics)
11. [Results](#results)
12. [Key Design Decisions](#key-design-decisions)

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE                            │
│                                                                  │
│   controller.py                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  FlowStartTable      EnsembleClassifier                 │   │
│   │  (flow start times)  (KNN+RF+DT+XGB+SVM → majority)    │   │
│   │         │                      │                        │   │
│   │    FIRST_SEEN             THRESHOLD                     │   │
│   │    digest handler         digest handler                │   │
│   │         └──────────┬──────────┘                        │   │
│   │              gRPC / P4Runtime                           │   │
│   └────────────────────┼────────────────────────────────────┘  │
└────────────────────────┼────────────────────────────────────────┘
                         │ table_add (block rule)
┌────────────────────────┼────────────────────────────────────────┐
│                   DATA PLANE (BMv2)                              │
│                                                                  │
│  h1 ──► ┌──────────────┴──────────────────────────┐ ──► h0     │
│  h2 ──► │  1. dangerous_table  (drop blocked IPs)  │ ──► h0     │
│  h3 ──► │  2. CMS update       (count SYNs per     │            │
│  h4 ──► │     2-row sketch      flow; decrement     │            │
│  h5 ──► │     on pure ACK)      on ACK)             │            │
│         │  3. Digest to ctrl   (FIRST_SEEN @        │            │
│         │                       SYN#1; THRESHOLD    │            │
│         │                       every 64 SYNs)      │            │
│         │  4. l2_forward       (MAC → port)         │            │
│         └────────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

**Detection flow:**
1. First SYN from a new flow → switch sends `FIRST_SEEN` digest to controller → controller records switch timestamp
2. Every 64th SYN → switch sends `THRESHOLD` digest (with `cms_min` count) → controller computes pps → ML ensemble votes → if ATTACK: install drop rule in `dangerous_table`
3. Subsequent packets from blocked IP → dropped at ingress before any further processing

---

## Topology

```
h1 (2001:1:1::1)  ──── port 1 ──┐
h2 (2001:1:1::2)  ──── port 2 ──┤
h3 (2001:1:1::3)  ──── port 3 ──┤──── s1 (BMv2) ──── port 6 ──── h0 (2001:1:1::10)
h4 (2001:1:1::4)  ──── port 4 ──┤                              (server / victim)
h5 (2001:1:1::5)  ──── port 5 ──┘
```

| Host | IPv6 Address    | MAC               | Role              |
|------|-----------------|-------------------|-------------------|
| h0   | 2001:1:1::10    | aa:00:00:00:00:00 | Server (victim)   |
| h1   | 2001:1:1::1     | aa:00:00:00:00:01 | Client (attacker) |
| h2   | 2001:1:1::2     | aa:00:00:00:00:02 | Client (attacker) |
| h3   | 2001:1:1::3     | aa:00:00:00:00:03 | Client (legit)    |
| h4   | 2001:1:1::4     | aa:00:00:00:00:04 | Client (legit)    |
| h5   | 2001:1:1::5     | aa:00:00:00:00:05 | Client (legit)    |

**IPv6 only.** No IPv4 addresses. All traffic uses the `2001:1:1::/64` prefix. Static ARP/NDP entries are pre-installed by `server.py` and each client script — no multicast NDP is needed through the P4 switch.

---

## Prerequisites & Installation

### System requirements
- Ubuntu 20.04 / 22.04 (or WSL2 with Ubuntu)
- Python 3.8+
- p4-utils (BMv2 + p4c + p4runtime tools)
- Mininet

### Python dependencies
```bash
pip3 install scapy numpy scikit-learn xgboost
```

### Verify p4-utils is installed
```bash
python3 -c "from p4utils.mininetlib.network_API import NetworkAPI; print('ok')"
```

### ML models
The trained models live in `ml/models/`. If they are missing, retrain from the CIC-DDoS2019 SYN flood dataset:
```bash
python3 ml/train_models.py --csv /path/to/Syn.csv
```
See [ML Ensemble section](#control-plane--ml-ensemble) for details.

---

## Project Structure

```
my/
├── network.py                  # Mininet topology definition
├── p4src/
│   ├── ddos_detector.p4        # P4 data plane program
│   ├── ddos_detector.json      # Compiled BMv2 JSON (auto-generated)
│   └── ddos_detector_p4rt.txt  # P4Info for P4Runtime (auto-generated)
├── controller/
│   └── controller.py           # gRPC controller + ML ensemble
├── ml/
│   ├── train_models.py         # Train the 5 ML models from CIC-DDoS2019
│   └── models/
│       ├── knn_model.pkl
│       ├── rf_model.pkl
│       ├── dt_model.pkl
│       ├── xgb_model.pkl
│       ├── svm_model.pkl
│       ├── scaler.pkl
│       └── feature_names.pkl
├── server.py                   # TCP server for h0 (auto-starts tcpdump)
├── attack.py                   # SYN flood — 2000 SYNs, 4-phase pattern
├── attacks.py                  # Run attack.py on all 5 hosts simultaneously
├── traffic.py                  # Legitimate TCP traffic — 60 conns at 3/sec
├── legit-traffic.py            # Run traffic.py on all 5 hosts simultaneously
├── flood.py                    # Flash crowd — 200 simultaneous burst connections
├── flooding.py                 # Run flood.py on all 5 hosts simultaneously
├── run_all.py                  # Mixed: h1+h2 attack, h3+h4+h5 legit
├── verify.py                   # Post-experiment pcap metrics calculator
└── topology.json               # Auto-generated by p4-utils at runtime
```

---

## P4 Data Plane

**File:** `p4src/ddos_detector.p4`

### Packet pipeline (ingress order)

```
Packet in
    │
    ▼
① dangerous_table       ← drop if src_ip is in blocklist → EXIT
    │
    ▼
② Parse TCP flags
    ├── pure SYN (SYN=1, ACK=0)?
    │       │
    │       ├── compute CMS hash (CRC16, CRC32) on 4-tuple
    │       ├── increment both CMS rows
    │       ├── cms_min = min(row0, row1)
    │       ├── if (row0==0 || row1==0) before increment → FIRST_SEEN digest
    │       └── if (cms_min % 64 == 0) → THRESHOLD digest
    │
    └── pure ACK (ACK=1, SYN=0)?
            │
            └── decrement both CMS rows (floor at 0)
    │
    ▼
③ l2_forward            ← forward by destination MAC
```

### Count-Min Sketch (CMS)

| Parameter   | Value                                              |
|-------------|----------------------------------------------------|
| Rows        | 2                                                  |
| Columns     | 1024                                               |
| Cell width  | 32-bit counter                                     |
| Hash row 0  | CRC16 on `{src_ip, dst_ip, dst_port, proto}`       |
| Hash row 1  | CRC32 on `{src_ip, dst_ip, dst_port, proto}`       |
| Increment   | pure SYN only (SYN=1, ACK=0)                       |
| Decrement   | pure ACK only (ACK=1, SYN=0) — **NOT SYN-ACK**    |
| `cms_min`   | `min(row0_count, row1_count)` after increment      |

**Critical design note:** SYN-ACK packets (SYN=1, ACK=1) are **excluded from decrement**. When the server has hundreds of half-open connections, it retransmits SYN-ACKs continuously. Each SYN-ACK has the ACK bit set and passes back through the switch. Including SYN-ACK in the decrement path causes random hash collisions with the attacker's CMS bucket, lowering the apparent count and delaying detection from `cms_min=64` to `cms_min=1024`. Excluding SYN-ACK from decrement keeps the attacker's counter monotonically increasing.

**Flow key:** `(src_ip, dst_ip, dst_port, protocol)` — source port is intentionally excluded. All connections from the same attacker host to the same server port (regardless of ephemeral source port) accumulate in the same CMS bucket. This makes detection fast and robust.

### Digest structs

**`first_seen_digest_t`** — sent on the first SYN of a new flow:
```
src_ip    bit<128>
dst_ip    bit<128>
dst_port  bit<16>
protocol  bit<8>
timestamp bit<48>    # ingress_global_timestamp (microseconds)
```

**`threshold_digest_t`** — sent every time `cms_min` hits an exact multiple of 64:
```
src_ip    bit<128>
dst_ip    bit<128>
dst_port  bit<16>
protocol  bit<8>
cms_min   bit<32>
timestamp bit<48>    # ingress_global_timestamp (microseconds)
```

### Tables

**`dangerous_table`** — blocklist (controller installs entries on ATTACK decision):
- Key: `hdr.ipv6.srcAddr` (exact match)
- Action: `drop()` — marks packet for drop, exits pipeline immediately
- Size: 1024 entries

**`l2_forward`** — L2 forwarding (controller installs at startup):
- Key: `hdr.ethernet.dstAddr` (exact match)
- Action: `forward(port)` — sets egress port
- Size: 64 entries

---

## Control Plane & ML Ensemble

**File:** `controller/controller.py`

### Startup sequence

1. Load all 5 ML models + scaler from `ml/models/`
2. Connect to s1 via gRPC (P4Runtime)
3. Install L2 forwarding rules for all 6 hosts
4. Enable both digest types (`first_seen_digest_t`, `threshold_digest_t`)
5. Spawn digest receiver thread (blocks on gRPC stream)
6. Print stats every 10 seconds

### FIRST_SEEN digest handler

When the switch sees the first SYN of a new flow (at least one CMS cell was zero before increment), it sends a `first_seen_digest_t`. The controller:

1. Decodes `src_ip`, `dst_ip`, `dst_port`, `protocol`, `timestamp`
2. Builds `flow_key = (src_ip, dst_ip, dst_port, protocol)`
3. Calls `flow_table.record(flow_key, timestamp)` — stores the switch clock timestamp of the first SYN

This timestamp is later used to compute how long the flow has been active.

### THRESHOLD digest handler

When `cms_min % 64 == 0` (every 64 SYNs), the switch sends a `threshold_digest_t`. The controller:

1. Checks `blocked_ips` — if already blocked, skip (block rule already installed)
2. Retrieves `start_time` from `flow_table` for this flow key
3. Computes `elapsed = (threshold_timestamp - start_time) / 1_000_000` (µs → seconds)
4. Computes `pps = cms_min / elapsed`
5. Scales: `pps_scaled = pps * 5000.0` (matches CIC-DDoS2019 training distribution)
6. Runs ML ensemble prediction
7. If ATTACK (majority vote ≥ 3/5): installs drop rule in `dangerous_table` on all switches

### ML Ensemble

Five models trained on the **CIC-DDoS2019 SYN flood dataset**:

| Model         | Type                        | Trained on     |
|---------------|-----------------------------|----------------|
| KNN           | K-Nearest Neighbors (k=5)   | scaled pps     |
| RF            | Random Forest (100 trees)   | scaled pps     |
| DT            | Decision Tree (depth=10)    | scaled pps     |
| XGBoost       | Gradient Boosted Trees      | scaled pps     |
| SVM           | RBF kernel, C=1.0           | scaled pps     |

**Decision rule:** majority vote — if ≥ 3 out of 5 models predict ATTACK, the flow is classified as attack.

**Feature:** `pps * 5000` (single feature). The 5000x scale factor bridges the gap between the real-world network speeds in the CIC-DDoS2019 dataset (millions of pps) and the BMv2 software switch speeds (~24 pps actual).

### Retrain models

```bash
# Download CIC-DDoS2019 dataset (Syn.csv from the SYN flood category)
python3 ml/train_models.py --csv /path/to/Syn.csv
```

The training script outputs per-model precision/recall/F1 and compares against paper Table I targets.

### FlowStartTable

In-memory dict mapping `flow_key → switch_timestamp_us` of the first SYN. Bounded at 100,000 entries (LRU eviction). Protected by `threading.Lock()`.

If `FIRST_SEEN` was missed (flow_key not found at THRESHOLD time), elapsed defaults to 1 second — conservative fallback that keeps pps reasonable.

---

## Running the System

### Quick start (correct order)

**Step 1 — Start the controller** (separate Linux terminal, before mininet):
```bash
cd /home/ayush/my/controller
python3 controller.py
```
Wait until you see:
```
DDoS Detection Controller RUNNING
```

**Step 2 — Start mininet** (another terminal):
```bash
cd /home/ayush/my
sudo python3 network.py
```
The topology compiles the P4 program, starts BMv2, connects all hosts and the switch. A command reference is printed before the `mininet>` prompt.

**Step 3 — Start the server on h0**:
```
mininet> xterm h0
```
In the h0 xterm:
```bash
python3 /home/ayush/my/server.py
```
Wait for:
```
[server] tcpdump capturing on h0-eth0 -> /home/ayush/my/capture.pcap
[server] Listening on [::]:80 (IPv6)
```
`server.py` automatically starts `tcpdump` on `h0-eth0` and saves all traffic to `capture.pcap`. The pcap is finalized when you press `Ctrl+C`.

**Step 4 — Run a traffic scenario** (in mininet CLI):
```
mininet> py exec(open('/home/ayush/my/run_all.py').read(), {'net': net, '__builtins__': __builtins__})
```

**Step 5 — Stop and verify**:
```
Ctrl+C    # in h0 xterm (stops server + saves pcap)
python3 /home/ayush/my/verify.py
```

### Important notes

- **Always restart mininet between experiments.** BMv2 registers (CMS counters) and P4 table entries persist across runs. `sudo python3 network.py` resets everything.
- **Always restart the controller between experiments.** The controller's in-memory `blocked_ips` set persists. If you don't restart it, previously blocked IPs won't be re-blocked even after mininet restart (because the dangerous_table is cleared by mininet but blocked_ips still shows them as already blocked).
- **Start the controller BEFORE mininet.** The controller needs `topology.json` which is written by mininet at startup.

---

## Traffic Scripts

### `server.py` — TCP server (runs on h0)

- Binds to `[::]` port 80 (all IPv6 addresses)
- Self-assigns `2001:1:1::10/64` to `h0-eth0` with `nodad` (skips DAD — critical to avoid 1-second delay that causes the first 2 connections to fail)
- Installs static neighbor entries for all 5 client hosts (bypasses NDP through the P4 switch)
- Automatically starts `tcpdump -i h0-eth0 -w /home/ayush/my/capture.pcap`
- Monitors SYN_RECV half-open connections every 0.3s and prints attack alerts
- On `Ctrl+C`: terminates tcpdump cleanly (flushes pcap), prints total connections served

```bash
# In h0 xterm:
python3 /home/ayush/my/server.py
```

---

### `attack.py` — SYN flood attacker

Sends **2000 raw Scapy SYNs** to h0:80 using L2 injection (bypasses kernel TCP stack). Source port increments (`sport=10000+i`) so each SYN has a unique 4-tuple at h0, creating many distinct SYN_RECV entries.

**4-phase traffic pattern:**

| Phase | Count | Speed        | Purpose                                   |
|-------|-------|--------------|-------------------------------------------|
| 1     | 60    | Burst (max)  | Below threshold — counter reaches 60      |
| 2     | 1000  | 1000 pps     | Threshold fires at SYN #64 → ML → BLOCK  |
| 3     | 64    | Burst (max)  | Second threshold batch (already blocked)  |
| 4     | 876   | 1000 pps     | Sustained flood — all dropped by switch   |

**ip6tables RST drop:** Raw Scapy SYNs bypass the kernel. When h0 replies with SYN-ACK, the kernel sees an unexpected reply and would send RST-ACK. This RST passes through the switch, hits the P4 ACK decrement logic, and resets the CMS counter. The script pre-emptively drops all outgoing RSTs with ip6tables to prevent this.

```bash
# In any host xterm (h1, h2, ...):
python3 /home/ayush/my/attack.py
```
Prints actual pps achieved and elapsed time for each phase.

---

### `attacks.py` — Simultaneous SYN flood from all 5 hosts

Launches `attack.py` on h1, h2, h3, h4, h5 simultaneously using Mininet's `popen()`. All hosts attack in parallel. Controller must detect and block each independently.

```
mininet> py exec(open('/home/ayush/my/attacks.py').read(), {'net': net, '__builtins__': __builtins__})
```

Expected: controller logs `ATTACK DETECTED` for all 5 IPs. verify.py scenario **2**.

---

### `traffic.py` — Legitimate TCP traffic

Sends **60 real kernel TCP connections** to h0:80 at 3 connections/second (0.333s interval). Uses `socket.connect()` — full 3-way handshake. Each connection: SYN → SYN-ACK → ACK → GET request → response → close.

Because the 3-way handshake completes, the CMS counter increments on SYN (+1) and decrements on ACK (-1) for each connection — net 0. The counter never accumulates to 64, so no THRESHOLD digest fires.

```bash
# In any legit host xterm:
python3 /home/ayush/my/traffic.py
```

---

### `legit-traffic.py` — Simultaneous legitimate traffic from all 5 hosts

Launches `traffic.py` on h1–h5 simultaneously using `popen()`. All 5 hosts send real TCP connections in parallel. Controller should NOT block any of them.

```
mininet> py exec(open('/home/ayush/my/legit-traffic.py').read(), {'net': net, '__builtins__': __builtins__})
```

Expected: FP=0, all 300 connections (60 × 5 hosts) reach h0. verify.py scenario **4**.

---

### `flood.py` — Flash crowd simulation

Simulates a realistic flash crowd event (viral link, event spike) with **200 total TCP connections** in a 4-phase burst pattern. Uses real kernel sockets — full handshakes complete.

**4-phase pattern:**

| Phase | Count | Speed          | Simulates                       |
|-------|-------|----------------|---------------------------------|
| 1     | 70    | Simultaneous   | Viral link / event spike        |
| 2     | 70    | 10/sec (serial)| Sustained high-interest traffic |
| 3     | 30    | Simultaneous   | Second spike / retweet wave     |
| 4     | 30    | 5–15/sec random| Traffic settling down           |

Because all connections are real TCP, the CMS counter never cleanly accumulates to 64 (ACKs cancel SYNs within each connection). The system should correctly classify this as benign.

```bash
# In any host xterm:
python3 /home/ayush/my/flood.py
```

---

### `flooding.py` — Simultaneous flash crowd from all 5 hosts

Launches `flood.py` on h1–h5 simultaneously using `popen()`. Simulates a large-scale flash crowd from 5 different source IPs.

```
mininet> py exec(open('/home/ayush/my/flooding.py').read(), {'net': net, '__builtins__': __builtins__})
```

Expected: controller may log BENIGN decisions if any burst phase momentarily accumulates enough simultaneous SYNs to hit threshold (64 SYNs before ACKs return). No block rules should be installed. verify.py scenario **3**.

---

### `run_all.py` — Mixed attack + legit traffic

Launches all hosts simultaneously via `cmd()` (background process, output to `/tmp/my_hX.log`):
- h1, h2 → `attack.py` (SYN flood)
- h3, h4, h5 → `traffic.py` (legitimate)

```
mininet> py exec(open('/home/ayush/my/run_all.py').read(), {'net': net, '__builtins__': __builtins__})
```

Check individual host logs after:
```
mininet> py net.get("h1").cmd("cat /tmp/my_h1.log")
mininet> py net.get("h3").cmd("cat /tmp/my_h3.log")
```

Expected: h1 and h2 blocked at cms_min=64 (first threshold), h3/h4/h5 not blocked. verify.py scenario **1**.

---

## Experiment Scenarios

| # | Script            | Attackers    | Legit           | Attack SYNs | Legit Conns |
|---|-------------------|--------------|-----------------|-------------|-------------|
| 1 | `run_all.py`      | h1, h2       | h3, h4, h5      | 4000        | 180         |
| 2 | `attacks.py`      | h1–h5 (all)  | none            | 10000       | 0           |
| 3 | `flooding.py`     | none         | h1–h5 (all)     | 0           | 1000        |
| 4 | `legit-traffic.py`| none         | h1–h5 (all)     | 0           | 300         |
| 5 | `attack.py` (h1)  | h1 only      | none            | 2000        | 0           |

**Before each experiment:**
1. Exit mininet (`mininet> exit`)
2. Restart controller (`Ctrl+C`, then `python3 controller.py`)
3. Restart mininet (`sudo python3 network.py`)
4. Start server on h0 (`python3 /home/ayush/my/server.py`)

---

## Verification & Metrics

**File:** `verify.py`

Post-experiment metrics calculator. Reads the pcap captured by `server.py` on `h0-eth0` and counts pure SYN packets (SYN=1, ACK=0) from each IP group to build a confusion matrix.

### How it works

1. Reads `/home/ayush/my/capture.pcap` (or pass a custom path as argument)
2. Prompts you to select which scenario was run (1–6)
3. Counts SYN packets from attacker IPs → False Negatives (FNs) = attack SYNs that reached h0
4. Counts SYN packets from legit IPs → True Negatives (TNs) = legit SYNs that correctly reached h0
5. Derives TP, FP from the known total_attack and total_legit counts

### Confusion matrix definitions

| Metric | Definition                                                        |
|--------|-------------------------------------------------------------------|
| TP     | Attack SYNs blocked by the switch (total_attack − FN)            |
| FN     | Attack SYNs that reached h0 (counted from pcap)                  |
| TN     | Legit SYNs that correctly reached h0 (counted from pcap)         |
| FP     | Legit SYNs incorrectly blocked (total_legit − TN)                |

### Usage

```bash
python3 /home/ayush/my/verify.py
# or with a specific pcap:
python3 /home/ayush/my/verify.py /path/to/other.pcap
```

### Prerequisites

Start `tcpdump` via `server.py` BEFORE the experiment. `server.py` does this automatically on startup. On `Ctrl+C`, the pcap is saved.

If you need to capture manually:
```bash
# In h0 xterm (BEFORE any traffic):
tcpdump -i h0-eth0 -w /home/ayush/my/capture.pcap &
# After experiment:
kill %1
```

### Scenario menu

```
1. run_all.py   — h1,h2 attack  |  h3,h4,h5 legit
2. attacks.py   — h1–h5 all attack
3. flooding.py  — h1–h5 all flash crowd (legit)
4. legit-traffic.py — h1–h5 all legit traffic
5. Single attack.py from h1 only
6. Custom — enter IPs and counts manually
```

---

## Results

Results from `run_all.py` (h1+h2 attack, h3+h4+h5 legit):

```
IP BREAKDOWN
  h1 (2001:1:1::1) — reached h0:   66  blocked: 1934
  h2 (2001:1:1::2) — reached h0:   66  blocked: 1934
  h3 (2001:1:1::3) — SYNs reached h0:   60
  h4 (2001:1:1::4) — SYNs reached h0:   60
  h5 (2001:1:1::5) — SYNs reached h0:   60

CONFUSION MATRIX
  TP  attack SYNs blocked   : 3868
  FN  attack SYNs reached h0:  132   (detection window: ~64 SYNs × 2 hosts + latency)
  TN  legit SYNs reached h0 :  180   (all 60 conns × 3 hosts)
  FP  legit SYNs blocked    :    0
```

```
METRICS
  accuracy  : 96.84%
  precision : 100.00%
  recall    : 96.70%
  f1        : 98.32%
```

### Comparison with baseline paper

| Metric    | P4M3 Paper (baseline) | This System |
|-----------|----------------------|-------------|
| Recall    | 86%                  | **96.70%**  |
| Precision | ~98%                 | **100.00%** |
| F1        | 89%                  | **98.32%**  |
| FP rate   | not reported         | **0%**      |

**Why ~66 FNs per attacker are irreducible:** The P4 algorithm cannot block a flow until it has seen 64 SYNs (the threshold). The first 64 SYNs must reach h0 before detection fires. Add ~2 more during the gRPC round-trip to install the block rule. Total unavoidable FN ≈ 66 per attacker.

To improve recall further: send more total SYNs. At 2000 SYNs/host with 2 attackers (4000 total), 66/2000 = 3.3% per-host FN rate → 96.7% recall. For 98%+ recall, send 3500+ SYNs per host.

---

## Key Design Decisions

### 1. IPv6 only
The entire system operates on IPv6 (`2001:1:1::/64`). IPv4 is not configured on any host. This simplifies the P4 parser (no IPv4 header handling) and avoids ARP complications.

### 2. Source port excluded from CMS hash
The CMS flow key is `(src_ip, dst_ip, dst_port, protocol)` — no `src_port`. This is intentional: all TCP connections from the same host to the same server port accumulate in a single CMS bucket, regardless of the ephemeral source port used. This means 64 connections from the same attacker trigger detection, not 64 connections to 64 different source ports (which would spread across different buckets with src_port included).

### 3. Dual digest design
Two digest types serve distinct purposes:
- `FIRST_SEEN` — records the switch clock timestamp of the flow's first SYN. This is the start time for PPS calculation. Without it, elapsed time would be unknown at threshold time.
- `THRESHOLD` — triggers ML inference. Fires every 64 SYNs so the controller can react quickly without being overwhelmed by per-packet digests.

### 4. SYN-ACK excluded from CMS decrement
The decrement condition is `ACK=1 AND SYN=0` (pure ACK only), not `ACK=1` (any ACK). SYN-ACK packets (SYN=1, ACK=1) are excluded. This is critical: with hundreds of half-open connections, the server retransmits SYN-ACKs through the switch at high rate. Including SYN-ACK in decrement causes random CMS bucket collisions that lower the attacker's counter and delay detection from cms_min=64 to cms_min=1024 (a 16× delay in detection).

### 5. IP-based blocking (not MAC-based)
The `dangerous_table` matches on `hdr.ipv6.srcAddr`. Attackers cannot bypass the block by spoofing a different source MAC — the IPv6 source address is checked. This is more robust than MAC-based blocking used in some P4 demos.

### 6. Majority vote ensemble
3/5 models must vote ATTACK for the flow to be blocked. This reduces false positives from individual model noise. Typical legitimate flash crowd traffic (burst TCP connections) votes 0/5 or 1/5, well below threshold. Attack traffic at threshold pps votes 3/5 or 4/5.

### 7. No src_port RST blocking
Attack script (`attack.py`) uses raw Scapy to send SYNs without a kernel TCP socket. When h0 responds with SYN-ACK, the kernel on the attacker host sees an unexpected SYN-ACK and would send RST-ACK. This RST passes through the switch, hits the P4 ACK decrement, and resets the CMS counter to 0. The attack script pre-emptively drops all outgoing RSTs via `ip6tables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`.

### 8. `nodad` on server IPv6 assignment
`server.py` assigns `2001:1:1::10/64` with `nodad` (no Duplicate Address Detection). Without `nodad`, Linux takes ~1 second to complete DAD, during which the address is TENTATIVE and the kernel refuses to send SYN-ACK from it. The first 2 connections from each client arrive during this window and time out. `nodad` eliminates this delay and ensures the first connection succeeds.

### 9. Static neighbor entries
All scripts install permanent NDP neighbor entries (`ip neigh replace ... nud permanent`) before sending traffic. This bypasses Neighbor Discovery Protocol (NDP multicast), which the P4 switch does not handle (it only supports unicast L2 forwarding). Without static entries, the first packet to an unknown neighbor would trigger an NDP multicast that the switch cannot resolve.

### 10. Automatic pcap capture
`server.py` automatically starts `tcpdump` on `h0-eth0` at startup and saves to `capture.pcap`. On `Ctrl+C`, it sends SIGTERM to tcpdump and waits for it to flush and write the pcap file trailer before exiting. This ensures a complete, valid pcap is always available for `verify.py` without requiring a separate tcpdump setup step.
