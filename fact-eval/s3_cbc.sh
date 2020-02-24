#!/bin/bash

cp ../../fact-eval/openssl-ssl3/tests/openssl-c/apps/openssl c_s3_cbc.O3
cp ../../fact-eval/openssl-ssl3/obj/s3_cbc{,.O3}.o .
musl-clang -static s3_cbc.o s3_stub.c -o fact_s3_cbc
musl-clang -static s3_cbc.O3.o s3_stub.c -o fact_s3_cbc.O3
