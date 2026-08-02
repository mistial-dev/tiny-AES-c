CC ?= cc
CFLAGS ?= -Wall -Wextra -O2 -std=c99 -I.

AES_SBOX_MODE ?= secure
AES_WIDE_OPS ?= off
AES_ENABLE_CBC ?= 1
AES_ENABLE_ECB ?= 1
AES_ENABLE_CTR ?= 1
TEST_BUILD_DIR ?= .tiny-aes-tests

ifeq ($(AES_SBOX_MODE),secure)
SBOX_DEFINITION = -DAES_SBOX_MODE=1
else ifeq ($(AES_SBOX_MODE),runtime)
SBOX_DEFINITION = -DAES_SBOX_MODE=2
else ifeq ($(AES_SBOX_MODE),fast)
SBOX_DEFINITION = -DAES_SBOX_MODE=3
else
$(error AES_SBOX_MODE must be secure, runtime, or fast)
endif

ifeq ($(AES_WIDE_OPS),off)
WIDE_DEFINITION = -DAES_WIDE_OPS=0
else ifeq ($(AES_WIDE_OPS),auto)
WIDE_DEFINITION = -DAES_WIDE_OPS=1
else
$(error AES_WIDE_OPS must be off or auto)
endif

MODE_DEFINITIONS = -DCBC=$(AES_ENABLE_CBC) -DECB=$(AES_ENABLE_ECB) -DCTR=$(AES_ENABLE_CTR)
CONFIG_DEFINITIONS = $(MODE_DEFINITIONS) $(SBOX_DEFINITION) $(WIDE_DEFINITION)

.PHONY: all clean size test

all: aes.o

aes.o: aes.c aes.h
	$(CC) $(CFLAGS) $(CONFIG_DEFINITIONS) -c aes.c -o $@

size: aes.o
	size aes.o

test:
	@set -e; \
	mkdir -p $(TEST_BUILD_DIR); \
	$(CC) $(CFLAGS) -c munit.c -o $(TEST_BUILD_DIR)/munit.o; \
	for key in 128 192 256; do \
	  for mode in ecb cbc ctr ecb-cbc ecb-ctr cbc-ctr all; do \
	    case $$mode in \
	      ecb) cbc=0; ecb=1; ctr=0 ;; \
	      cbc) cbc=1; ecb=0; ctr=0 ;; \
	      ctr) cbc=0; ecb=0; ctr=1 ;; \
	      ecb-cbc) cbc=1; ecb=1; ctr=0 ;; \
	      ecb-ctr) cbc=0; ecb=1; ctr=1 ;; \
	      cbc-ctr) cbc=1; ecb=0; ctr=1 ;; \
	      all) cbc=1; ecb=1; ctr=1 ;; \
	    esac; \
	    for sbox in 1 2 3; do \
	      for wide in 0 1; do \
	        name=$${key}-$${mode}-sbox$${sbox}-wide$${wide}; \
	        $(CC) $(CFLAGS) -DCBC=$$cbc -DECB=$$ecb -DCTR=$$ctr \
	          -DAES$${key}=1 -DAES_SBOX_MODE=$$sbox -DAES_WIDE_OPS=$$wide \
	          -c aes.c -o $(TEST_BUILD_DIR)/aes-$${name}.o; \
	        $(CC) $(CFLAGS) -DCBC=$$cbc -DECB=$$ecb -DCTR=$$ctr \
	          -DAES$${key}=1 -DAES_SBOX_MODE=$$sbox -DAES_WIDE_OPS=$$wide \
	          -c test.c -o $(TEST_BUILD_DIR)/test-$${name}.o; \
	        $(CC) $(CFLAGS) -o $(TEST_BUILD_DIR)/test-$${name} \
	          $(TEST_BUILD_DIR)/aes-$${name}.o \
	          $(TEST_BUILD_DIR)/test-$${name}.o $(TEST_BUILD_DIR)/munit.o; \
	        $(TEST_BUILD_DIR)/test-$${name}; \
	      done; \
	    done; \
	  done; \
	done

clean:
	rm -f aes.o
	rm -rf $(TEST_BUILD_DIR)
