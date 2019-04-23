CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -O3

HEADERS = api.h crypto_scalarmult.h
SOURCES = smult.s smult_lfence.s base.c

all: test speed

test: ${HEADERS} ${SOURCES} test.c
	${CC} ${CFLAGS} ${SOURCES} test.c -o $@

speed: ${HEADERS} ${SOURCES} cpucycles.h cpucycles.c speed.c
	${CC} ${CFLAGS} ${SOURCES} speed.c cpucycles.c -o $@


smult.s: smult.c
	${CC} ${CFLAGS} -c -S -o $@ $^


.PHONY: clean

clean:
	-rm test speed smult.s *.o
