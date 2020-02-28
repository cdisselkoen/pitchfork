#!/bin/bash

source venv/bin/activate
pypy3 -c "import pitchfork; pitchfork.alltests(kocher=False, spectrev1=False, forwarding=True, tweetnacl=False)"
