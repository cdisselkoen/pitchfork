#!/bin/bash

cp ../../fact-eval/openssl-mee/tests/openssl-c/apps/openssl c_mee.O3
cp ../../fact-eval/openssl-mee/obj/20170717_latest{,.O3}.o .
musl-clang -static 20170717_latest.o mee_stub.c -o fact_mee
musl-clang -static 20170717_latest.O3.o mee_stub.c -o fact_mee.O3
