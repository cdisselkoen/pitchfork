#!/bin/bash

cp ../../fact-eval/crypto_secretbox/obj/*.o .

musl-clang -static crypto_secretbox.cref.o secretbox_stub.c -o fact_secretbox.cref
musl-clang -static crypto_secretbox.asm.o secretbox_stub.c -o fact_secretbox.asm
musl-clang -static crypto_secretbox.cref.O2.o secretbox_stub.c -o fact_secretbox.cref.O2
musl-clang -static crypto_secretbox.asm.O2.o secretbox_stub.c -o fact_secretbox.asm.O2

# can't use musl-clang due to some missing library dependencies,
# but thankfully the analysis here doesn't hit the libc plt stuff
# so it works out
clang -static -L../../fact-eval/crypto_secretbox/tests/libsodium-c-cref/src/libsodium/.libs c_secretbox_stub.c -o c_secretbox.cref.O2 -lsodium -lpthread
clang -static -L../../fact-eval/crypto_secretbox/tests/libsodium-c-asm/src/libsodium/.libs c_secretbox_stub.c -o c_secretbox.asm.O2 -lsodium -lpthread
