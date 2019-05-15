CC=clang
CFLAGS=-O3

.PHONY: all
all : spectrev1 forwarding

spectrev1 : spectrev1.c
	$(CC) $(CFLAGS) $< -o $@

forwarding : forwarding.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: clean
clean :
	rm spectrev1 forwarding
