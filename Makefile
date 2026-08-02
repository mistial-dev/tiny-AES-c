CC ?= cc
CFLAGS ?= -Wall -Wextra -O2 -std=c99 -I.
TARGETS = test-aes-128 test-aes-192 test-aes-256

.PHONY: all clean test

all: $(TARGETS)

test-aes-128: aes.c test.c munit.c aes.h munit.h test_vectors.h
	$(CC) $(CFLAGS) -DAES128=1 -o $@ aes.c test.c munit.c

test-aes-192: aes.c test.c munit.c aes.h munit.h test_vectors.h
	$(CC) $(CFLAGS) -DAES192=1 -o $@ aes.c test.c munit.c

test-aes-256: aes.c test.c munit.c aes.h munit.h test_vectors.h
	$(CC) $(CFLAGS) -DAES256=1 -o $@ aes.c test.c munit.c

test: $(TARGETS)
	./test-aes-128
	./test-aes-192
	./test-aes-256

clean:
	rm -f $(TARGETS)
