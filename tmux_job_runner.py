#!/usr/bin/env python3

import subprocess
import time
from fileinput import FileInput
import argparse

def run(my_pane, title, cmd):
    title += ' ' + cmd
    subprocess.run(f'tmux split-window -dv -t {my_pane} bash -c'.split() + [f"echo -en '\x1b]0;{title}\x07' ; " + cmd])
    subprocess.run(f'tmux select-layout -E -t {my_pane}'.split())
def num_jorbs(title):
    res = subprocess.run(['tmux', 'list-panes', '-F', '#{pane_title}'], stdout=subprocess.PIPE).stdout
    return int(len(list(filter(lambda s: s.startswith(title), res.decode('utf-8').strip().split('\n')))))
def next_cmd(fname):
    res = None
    with FileInput(files=(fname,), inplace=True) as f:
        for line in f:
            if line and not line.strip().startswith('#') and not res:
                res = line
                print('#' + line, end='')
            else:
                print(line, end='')
    return res

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', metavar='N', action='store', required=True)
    parser.add_argument('-p', '--prefix', action='store', default='jorb0')
    parser.add_argument('file')
    args = parser.parse_args()
    my_pane = subprocess.run(['tmux', 'display-message', '-p', '#{pane_id}'], stdout=subprocess.PIPE) \
        .stdout.decode('utf-8').strip()
    while True:
        if num_jorbs(args.prefix) < int(args.j):
            cmd = next_cmd(args.file)
            if not cmd:
                break
            run(my_pane, args.prefix, cmd)
        time.sleep(0.5)
