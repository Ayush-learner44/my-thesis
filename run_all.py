"""
run_all.py — Fire all traffic simultaneously from mininet CLI
h1, h2       → attack.py  (SYN flood)
h3, h4, h5   → traffic.py (legit traffic)

Run from mininet CLI:
    mininet> py exec(open('/home/ayush/my/run_all.py').read())

Check logs after:
    mininet> py net.get('h1').cmd('cat /tmp/my_h1.log')
"""

import time

BASE = '/home/ayush/my'

hosts_scripts = [
    ('h1', 'attack.py'),
    ('h2', 'attack.py'),
    ('h3', 'traffic.py'),
    ('h4', 'traffic.py'),
    ('h5', 'traffic.py'),
]

for host, script in hosts_scripts:
    net.get(host).cmd(f'cd {BASE} && python3 {script} > /tmp/my_{host}.log 2>&1 &')
    print(f'[run_all] {host} -> {script}')

print('[run_all] All launched simultaneously.')
print('[run_all] Check logs with:')
for host, _ in hosts_scripts:
    print(f'  mininet> py net.get("{host}").cmd("cat /tmp/my_{host}.log")')
