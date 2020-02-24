#!/bin/bash
set -eu

mkdir -p results
source venv/bin/activate
fname=$(pypy3 eval.py "$@" --generating-filename 2>/dev/null)
echo "Writing output to results/$fname" >&2
for x in {1..20}; do
  echo >> results/$fname
done
date >> results/$fname
echo >> results/$fname

set +e
function kall() {
  pkill -P $$ 2>/dev/null
}
trap kall EXIT

pypy3 eval.py "$@" >& >(tee -a results/$fname | grep -C1 UNSAFE) &
pid=$!
echo pid: $pid | tee -a results/$fname
sleep 2
tail -f results/$fname | xargs -I{} echo -n . &
tail -f results/$fname | grep -qm1 -e UNSAFE -e "running time" && kill $pid 2>/dev/null
pkill -P $$ 2>/dev/null
echo
echo -e "\e[0mFinished at:" | tee -a results/$fname
date | tee -a results/$fname
