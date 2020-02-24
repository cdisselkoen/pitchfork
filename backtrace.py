#!/usr/bin/env python3

import sys
import re

fname = sys.argv[1]

with open(fname) as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if 'UNSAFE' in line:
        break
addr = re.search(r'Instruction Address 0x([0-9a-f]+)', lines[i+1])[1]
print(addr)
lines = lines[i::-1]
states = []
for line in lines:
    m = re.search(r'(state\d+):.*IMark\(0x' + addr, line)
    if m:
        states.append(m[1])
        break
for line in lines:
    m = re.search(r'new state {} copied from (state\d+)'.format(states[-1]), line)
    if m:
        states.append(m[1])
for line in reversed(lines):
    for state in states:
        if state + ':' in line:
            print(line, end='')
            break
