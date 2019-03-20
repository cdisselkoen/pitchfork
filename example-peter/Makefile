CC		 = /usr/bin/gcc
CFLAGS = -Wall -Wextra -g

main: main.c tweetnacl.c randombytes.c
	${CC} ${CFLAGS} $^ -o $@


.PHONY: clean

clean:
	-rm main
