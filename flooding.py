"""
flooding.py — Simultaneous flash crowd from ALL client hosts (h1–h5).

Run from the Mininet CLI:
    mininet> py exec(open('/home/ayush/my/flooding.py').read(), {'net': net, '__builtins__': __builtins__})

Uses popen() so all 5 hosts start in parallel without needing threading.
"""

SCRIPT = '/home/ayush/my/flood.py'
HOSTS  = ['h1', 'h2', 'h3', 'h4', 'h5']

print(f"[flooding] Launching flood.py on {HOSTS} simultaneously...")

procs = {h: net.get(h).popen(['python3', SCRIPT]) for h in HOSTS}

for h, p in procs.items():
    out, _ = p.communicate()
    for line in out.decode().strip().splitlines():
        print(f"[flooding] {h}: {line}")

print("[flooding] All hosts done")
