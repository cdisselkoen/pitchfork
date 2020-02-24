#!/bin/bash

git clone https://github.com/cdisselkoen/angr.git -b more-hooks angr-git
ln -s angr-git/angr angr
pypy3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
mkdir -p results
