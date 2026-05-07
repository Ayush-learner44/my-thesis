"""
DDoS Detection Controller — Pure gRPC / P4Runtime
Implements the control plane algorithm from myarchitecture.txt:
  1. Connect to s1 via P4Runtime/gRPC
  2. Install L2 forwarding rules (MAC -> port)
  3. Enable first_seen_digest_t and threshold_digest_t on s1
  4. On FIRST_SEEN digest: record flow start timestamp (switch clock, microseconds)
  5. On THRESHOLD digest: compute pps, run ML ensemble, block src_ip if ATTACK
"""

import os, sys, time, pickle, threading, logging, ipaddress
import numpy as np

sys.path.insert(0, '/home/ayush/p4-tools/p4-utils')
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.helper import load_topo

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger('DDoS')
log.propagate = False

_PROJECT_ROOT = os.path.join(os.path.dirname(__file__), '..')
MODELS_DIR = os.path.join(_PROJECT_ROOT, 'ml', 'models')
P4RT_PATH  = os.path.join(_PROJECT_ROOT, 'p4src', 'ddos_detector_p4rt.txt')
JSON_PATH  = os.path.join(_PROJECT_ROOT, 'p4src', 'ddos_detector.json')

# MACs must match network.py setIntfMac values
HOST_MACS = {
    'h0': 'aa:00:00:00:00:00',
    'h1': 'aa:00:00:00:00:01',
    'h2': 'aa:00:00:00:00:02',
    'h3': 'aa:00:00:00:00:03',
    'h4': 'aa:00:00:00:00:04',
    'h5': 'aa:00:00:00:00:05',
}

# Port numbers match port1= values in network.py addLink calls on s1
PORT_MAP = {
    'h1': 1,
    'h2': 2,
    'h3': 3,
    'h4': 4,
    'h5': 5,
    'h0': 6,
}

MAX_FLOW_TABLE_SIZE = 100_000


def _bytes_to_ipv6(raw):
    return str(ipaddress.ip_address(bytes(raw)))


# ================================================================
# ML ENSEMBLE
# ================================================================

class EnsembleClassifier:
    def __init__(self, models_dir):
        self.models = {}
        self.scaler = None
        log.info(f"Loading ML models from {models_dir}/")
        for name, fname in [('knn', 'knn_model.pkl'), ('rf',  'rf_model.pkl'),
                             ('dt',  'dt_model.pkl'),  ('xgb', 'xgb_model.pkl'),
                             ('svm', 'svm_model.pkl')]:
            path = os.path.join(models_dir, fname)
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    self.models[name] = pickle.load(f)
                log.info(f"  Loaded: {name}")
            else:
                log.warning(f"  Missing: {path}")
        scaler_path = os.path.join(models_dir, 'scaler.pkl')
        if os.path.exists(scaler_path):
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
        log.info(f"Ensemble ready: {len(self.models)} models loaded")

    def predict(self, pps):
        # Scale PPS to match CICDDoS2019 training distribution (millions of pps)
        pps_scaled = pps * 5000.0
        features = np.array([[pps_scaled]])
        if self.scaler:
            features = self.scaler.transform(features)
        votes = sum(1 for m in self.models.values() if m.predict(features)[0] == 1)
        total = len(self.models)
        return votes > (total / 2), votes, total


# ================================================================
# FLOW START TABLE
# ================================================================

class FlowStartTable:
    """
    Maps 4-tuple flow keys to their first-SYN switch timestamp (microseconds).
    Key:   (src_ip_str, dst_ip_str, dst_port, protocol)
    Value: ingress_global_timestamp of the first SYN (48-bit, microseconds)
    """

    def __init__(self, max_size=MAX_FLOW_TABLE_SIZE):
        self._table = {}
        self._lock  = threading.Lock()
        self._max   = max_size

    def record(self, flow_key, timestamp_us):
        """Store start timestamp for a new flow. No-op if flow already tracked.
        Returns True if this is a genuinely new entry."""
        with self._lock:
            if flow_key in self._table:
                return False
            if len(self._table) >= self._max:
                # Evict the oldest entry (insertion-order dict, Python 3.7+)
                del self._table[next(iter(self._table))]
            self._table[flow_key] = timestamp_us
            return True

    def get_start(self, flow_key):
        with self._lock:
            return self._table.get(flow_key)


# ================================================================
# CONTROLLER
# ================================================================

class DDoSController:
    def __init__(self):
        self.ensemble    = EnsembleClassifier(MODELS_DIR)
        self.flow_table  = FlowStartTable()
        self.switches    = {}
        self.blocked_ips = set()   # set of IPv6 strings already blocked
        self.stats       = {'first_seen': 0, 'threshold': 0,
                            'attacks': 0,    'benign': 0}
        self._lock       = threading.Lock()

        self.topo = load_topo('topology.json')
        self._connect_switches()
        self._install_forwarding_rules()
        self._enable_digests()

    # ------------------------------------------------------------------
    # SETUP
    # ------------------------------------------------------------------

    def _connect_switches(self):
        log.info("Connecting to switches via P4Runtime/gRPC...")
        for sw in self.topo.get_p4switches():
            device_id = self.topo.get_p4switch_id(sw)
            grpc_port = self.topo.get_grpc_port(sw)
            try:
                self.switches[sw] = SimpleSwitchP4RuntimeAPI(
                    device_id = device_id,
                    grpc_port = grpc_port,
                    p4rt_path = P4RT_PATH,
                    json_path = JSON_PATH,
                )
                log.info(f"  Connected: {sw} (device_id={device_id} grpc={grpc_port})")
            except Exception as e:
                log.error(f"  Failed to connect {sw}: {e}")

    def _install_forwarding_rules(self):
        log.info("Installing L2 forwarding rules on s1...")
        api = self.switches.get('s1')
        if not api:
            log.error("s1 not connected — skipping forwarding rules")
            return
        for host, port in PORT_MAP.items():
            mac = HOST_MACS.get(host)
            if not mac:
                continue
            try:
                api.table_add('MyIngress.l2_forward', 'MyIngress.forward',
                              [mac], [str(port)])
                log.info(f"  s1: {host} ({mac}) -> port {port}")
            except Exception as e:
                if 'already exists' not in str(e).lower():
                    log.warning(f"  Rule failed s1->{host}: {e}")

    def _enable_digests(self):
        """Enable both digest types on s1.
        max_timeout_ns=0, max_list_size=1, ack_timeout_ns=0 → per-packet, no batching.
        The wrapper ACKs automatically after each get_digest_list() call."""
        log.info("Enabling digests on s1...")
        api = self.switches.get('s1')
        if not api:
            log.error("s1 not connected — cannot enable digests")
            return
        for name in ('first_seen_digest_t', 'threshold_digest_t'):
            try:
                api.digest_enable(name, max_timeout_ns=0,
                                  max_list_size=1, ack_timeout_ns=0)
                log.info(f"  Enabled: {name}")
            except Exception as e:
                log.warning(f"  digest_enable({name}): {e}")

    # ------------------------------------------------------------------
    # BLOCKING
    # ------------------------------------------------------------------

    def _push_block_rule(self, src_ip_str):
        """Install drop rule for src_ip in dangerous_table on ALL switches."""
        for sw_name, api in self.switches.items():
            try:
                api.table_add('MyIngress.dangerous_table', 'MyIngress.drop',
                              [src_ip_str])
                log.info(f"  Block rule installed on {sw_name}: {src_ip_str}")
            except Exception as e:
                if 'already exists' not in str(e).lower():
                    log.warning(f"  Block rule failed {sw_name}: {e}")

    # ------------------------------------------------------------------
    # DIGEST HANDLERS
    # ------------------------------------------------------------------

    def _handle_first_seen(self, members):
        """
        first_seen_digest_t field order (matches P4 struct definition):
          [0] src_ip    bit<128>
          [1] dst_ip    bit<128>
          [2] dst_port  bit<16>
          [3] protocol  bit<8>
          [4] timestamp bit<48>  (ingress_global_timestamp, microseconds)
        """
        src_ip    = _bytes_to_ipv6(members[0].bitstring)
        dst_ip    = _bytes_to_ipv6(members[1].bitstring)
        dst_port  = int.from_bytes(members[2].bitstring, 'big')
        protocol  = int.from_bytes(members[3].bitstring, 'big')
        timestamp = int.from_bytes(members[4].bitstring, 'big')

        flow_key = (src_ip, dst_ip, dst_port, protocol)
        is_new = self.flow_table.record(flow_key, timestamp)

        with self._lock:
            self.stats['first_seen'] += 1

        if is_new:
            log.info(f"FIRST_SEEN  {src_ip} -> {dst_ip}:{dst_port} "
                     f"proto={protocol}  ts={timestamp}us")

    def _handle_threshold(self, members):
        """
        threshold_digest_t field order (matches P4 struct definition):
          [0] src_ip    bit<128>
          [1] dst_ip    bit<128>
          [2] dst_port  bit<16>
          [3] protocol  bit<8>
          [4] cms_min   bit<32>
          [5] timestamp bit<48>  (ingress_global_timestamp, microseconds)
        """
        src_ip    = _bytes_to_ipv6(members[0].bitstring)
        dst_ip    = _bytes_to_ipv6(members[1].bitstring)
        dst_port  = int.from_bytes(members[2].bitstring, 'big')
        protocol  = int.from_bytes(members[3].bitstring, 'big')
        cms_min   = int.from_bytes(members[4].bitstring, 'big')
        timestamp = int.from_bytes(members[5].bitstring, 'big')

        flow_key = (src_ip, dst_ip, dst_port, protocol)

        with self._lock:
            self.stats['threshold'] += 1
            already_blocked = src_ip in self.blocked_ips

        if already_blocked:
            return   # drop rule already installed, skip ML

        # Elapsed time using switch clock (microseconds, same epoch for both digests)
        start_time = self.flow_table.get_start(flow_key)
        if start_time is None:
            # Fallback: FIRST_SEEN was missed — assume 1 second elapsed
            start_time = timestamp - 1_000_000

        elapsed = (timestamp - start_time) / 1_000_000.0   # µs → seconds
        if elapsed <= 0:
            elapsed = 1.0

        total_fwd_pkts = cms_min
        pps = total_fwd_pkts / elapsed

        is_attack, votes, total = self.ensemble.predict(pps)

        log.info(f"THRESHOLD   {src_ip} -> :{dst_port}  cms_min={cms_min}  "
                 f"elapsed={elapsed:.3f}s  vote={votes}/{total}")

        if is_attack:
            log.warning("=" * 60)
            log.warning(f"ATTACK DETECTED: {src_ip}")
            log.warning(f"  cms_min={cms_min}  vote={votes}/{total}")
            log.warning(f"  -> installing drop rule on all switches")
            log.warning("=" * 60)
            with self._lock:
                self.blocked_ips.add(src_ip)
                self.stats['attacks'] += 1
            self._push_block_rule(src_ip)
        else:
            log.info("=" * 60)
            log.info(f"BENIGN: {src_ip}")
            log.info(f"  cms_min={cms_min}  vote={votes}/{total}")
            log.info(f"  -> allowed, no action taken")
            log.info("=" * 60)
            with self._lock:
                self.stats['benign'] += 1

    # ------------------------------------------------------------------
    # DIGEST RECEIVER THREAD
    # ------------------------------------------------------------------

    def _recv_digest(self, sw_name):
        """Block on the P4Runtime gRPC stream from sw_name.

        Both digest types arrive on the same stream. They are differentiated
        by struct member count:
          6 members → first_seen_digest_t
          7 members → threshold_digest_t

        The wrapper sends the ACK automatically after each get_digest_list().
        timeout=1 is a recovery heartbeat only, not a polling interval.
        """
        api = self.switches.get(sw_name)
        if not api:
            log.error(f"Digest receiver: no API for {sw_name}")
            return

        log.info(f"Digest receiver ready on {sw_name} (blocking on gRPC stream)")
        while True:
            try:
                digest_list = api.get_digest_list(timeout=1)
                if digest_list is None:
                    continue

                for digest_entry in digest_list.data:
                    members = digest_entry.struct.members
                    n = len(members)

                    if n == 5:
                        self._handle_first_seen(members)
                    elif n == 6:
                        self._handle_threshold(members)
                    else:
                        log.warning(f"Unexpected digest on {sw_name}: {n} members")

            except Exception as e:
                if 'timeout' not in str(e).lower():
                    log.error(f"Digest stream error on {sw_name}: {e}")

    # ------------------------------------------------------------------
    # MAIN LOOP
    # ------------------------------------------------------------------

    def start(self):
        t = threading.Thread(target=self._recv_digest, args=('s1',), daemon=True)
        t.start()

        log.info("")
        log.info("=" * 60)
        log.info("DDoS Detection Controller RUNNING")
        log.info("  Digest 1: FIRST_SEEN  -> records flow start timestamp")
        log.info("  Digest 2: THRESHOLD   -> fires every 64 SYNs -> ML")
        log.info("  Block key: src IPv6 address in dangerous_table")
        log.info("  Features: [pps * 5000]")
        log.info("=" * 60)

        try:
            while True:
                time.sleep(10)
                with self._lock:
                    s = self.stats.copy()
                    n_blocked = len(self.blocked_ips)
                log.info(f"STATS | FirstSeen:{s['first_seen']}  "
                         f"Threshold:{s['threshold']}  "
                         f"Attacks:{s['attacks']}  Benign:{s['benign']}  "
                         f"Blocked:{n_blocked}")
        except KeyboardInterrupt:
            with self._lock:
                s = self.stats.copy()
                n_blocked = len(self.blocked_ips)
            print("\n" + "=" * 60)
            print("FINAL STATS")
            print(f"  FIRST_SEEN digests  : {s['first_seen']}")
            print(f"  THRESHOLD digests   : {s['threshold']}")
            print(f"  Attacks detected    : {s['attacks']}")
            print(f"  Benign flows        : {s['benign']}")
            print(f"  IPs blocked         : {n_blocked}")
            print("=" * 60)


if __name__ == '__main__':
    ctrl = DDoSController()
    ctrl.start()
