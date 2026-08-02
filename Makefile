# SPDX-FileCopyrightText: kokke
# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: Unlicense

CC ?= cc
CFLAGS ?= -Wall -Wextra -O2 -std=c99 -I.

AES_SBOX_MODE ?= secure
AES_WIDE_OPS ?= off
AES_ENABLE_CBC ?= 0
AES_ENABLE_ECB ?= 0
AES_ENABLE_CTR ?= 1
AES_ENABLE_OFB ?= 0
AES_ENABLE_GCM ?= 0
AES_ENABLE_CCM ?= 0
AES_CCM_CAVP ?= 0
AES_GCM_GHASH_MODE ?= auto
BENCHMARK_BYTES ?= 16384
BENCHMARK_ITERATIONS ?= 100
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

MODE_DEFINITIONS = -DCBC=$(AES_ENABLE_CBC) -DECB=$(AES_ENABLE_ECB) \
  -DCTR=$(AES_ENABLE_CTR) -DOFB=$(AES_ENABLE_OFB) -DGCM=$(AES_ENABLE_GCM) \
  -DCCM=$(AES_ENABLE_CCM)
ifeq ($(AES_GCM_GHASH_MODE),auto)
GHASH_DEFINITION = -DAES_GCM_GHASH_MODE=0
GHASH_MODE = 0
else ifeq ($(AES_GCM_GHASH_MODE),bitwise)
GHASH_DEFINITION = -DAES_GCM_GHASH_MODE=1
GHASH_MODE = 1
else ifeq ($(AES_GCM_GHASH_MODE),wide)
GHASH_DEFINITION = -DAES_GCM_GHASH_MODE=2
GHASH_MODE = 2
else ifeq ($(AES_GCM_GHASH_MODE),table4)
GHASH_DEFINITION = -DAES_GCM_GHASH_MODE=3
GHASH_MODE = 3
else ifeq ($(AES_GCM_GHASH_MODE),fast-table)
GHASH_DEFINITION = -DAES_GCM_GHASH_MODE=4
GHASH_MODE = 4
else ifeq ($(AES_GCM_GHASH_MODE),hardware)
GHASH_DEFINITION = -DAES_GCM_GHASH_MODE=5
GHASH_MODE = 5
else
$(error AES_GCM_GHASH_MODE must be auto, bitwise, wide, table4, fast-table, or hardware)
endif
CONFIG_DEFINITIONS = $(MODE_DEFINITIONS) $(SBOX_DEFINITION) $(WIDE_DEFINITION) $(GHASH_DEFINITION)

.PHONY: all clean size test benchmark

all: aes.o

aes.o: aes.c aes.h
	$(CC) $(CFLAGS) $(CONFIG_DEFINITIONS) -c aes.c -o $@

size: aes.o
	size aes.o

benchmark: benchmark.c aes.c aes.h
	mkdir -p $(TEST_BUILD_DIR)
	$(CC) $(CFLAGS) -DCBC=0 -DECB=0 -DCTR=0 -DOFB=0 -DGCM=1 -DAES128=1 -DAES_GCM_GHASH_MODE=$(GHASH_MODE) \
		-c aes.c -o $(TEST_BUILD_DIR)/benchmark-aes.o
	$(CC) $(CFLAGS) -DCBC=0 -DECB=0 -DCTR=0 -DOFB=0 -DGCM=1 -DAES128=1 -DAES_GCM_GHASH_MODE=$(GHASH_MODE) \
		-DBENCHMARK_BYTES=$(BENCHMARK_BYTES) -DBENCHMARK_ITERATIONS=$(BENCHMARK_ITERATIONS) \
		benchmark.c $(TEST_BUILD_DIR)/benchmark-aes.o -o $(TEST_BUILD_DIR)/benchmark
	$(TEST_BUILD_DIR)/benchmark

test:
	@set -e; \
	mkdir -p $(TEST_BUILD_DIR); \
    $(CC) $(CFLAGS) -UGCM -UAES_GCM_GHASH_MODE -c munit.c -o $(TEST_BUILD_DIR)/munit.o; \
	for key in 128 192 256; do \
	  for mode in none ecb cbc ctr ofb ecb-cbc ecb-ctr ecb-ofb cbc-ctr cbc-ofb ctr-ofb ecb-cbc-ctr ecb-cbc-ofb ecb-ctr-ofb cbc-ctr-ofb all; do \
	    case $$mode in \
	      none) cbc=0; ecb=0; ctr=0; ofb=0 ;; \
	      ecb) cbc=0; ecb=1; ctr=0; ofb=0 ;; \
	      cbc) cbc=1; ecb=0; ctr=0; ofb=0 ;; \
	      ctr) cbc=0; ecb=0; ctr=1; ofb=0 ;; \
	      ofb) cbc=0; ecb=0; ctr=0; ofb=1 ;; \
	      ecb-cbc) cbc=1; ecb=1; ctr=0; ofb=0 ;; \
	      ecb-ctr) cbc=0; ecb=1; ctr=1; ofb=0 ;; \
	      ecb-ofb) cbc=0; ecb=1; ctr=0; ofb=1 ;; \
	      cbc-ctr) cbc=1; ecb=0; ctr=1; ofb=0 ;; \
	      cbc-ofb) cbc=1; ecb=0; ctr=0; ofb=1 ;; \
	      ctr-ofb) cbc=0; ecb=0; ctr=1; ofb=1 ;; \
	      ecb-cbc-ctr) cbc=1; ecb=1; ctr=1; ofb=0 ;; \
	      ecb-cbc-ofb) cbc=1; ecb=1; ctr=0; ofb=1 ;; \
	      ecb-ctr-ofb) cbc=0; ecb=1; ctr=1; ofb=1 ;; \
	      cbc-ctr-ofb) cbc=1; ecb=0; ctr=1; ofb=1 ;; \
	      all) cbc=1; ecb=1; ctr=1; ofb=1 ;; \
	    esac; \
	  for gcm in 0 1; do \
	    if [ "$$mode" = none ]; then ccm_modes="0 1"; else ccm_modes="0"; fi; \
	    for ccm in $$ccm_modes; do \
      if [ $$gcm -eq 0 ]; then ghash_modes="0"; else ghash_modes="0 1 2 3 4"; fi; \
      for ghash in $$ghash_modes; do \
      for sbox in 1 2 3; do \
        for wide in 0 1; do \
          name=$${key}-$${mode}-gcm$${gcm}-ccm$${ccm}-ghash$${ghash}-sbox$${sbox}-wide$${wide}; \
          $(CC) $(CFLAGS) -DCBC=$$cbc -DECB=$$ecb -DCTR=$$ctr -DOFB=$$ofb -DGCM=$$gcm -DCCM=$$ccm -DAES_CCM_CAVP=$(AES_CCM_CAVP) \
          -DAES$${key}=1 -DAES_SBOX_MODE=$$sbox -DAES_WIDE_OPS=$$wide -DAES_GCM_GHASH_MODE=$$ghash \
          -c aes.c -o $(TEST_BUILD_DIR)/aes-$${name}.o; \
          $(CC) $(CFLAGS) -DCBC=$$cbc -DECB=$$ecb -DCTR=$$ctr -DOFB=$$ofb -DGCM=$$gcm -DCCM=$$ccm -DAES_CCM_CAVP=$(AES_CCM_CAVP) \
          -DAES$${key}=1 -DAES_SBOX_MODE=$$sbox -DAES_WIDE_OPS=$$wide -DAES_GCM_GHASH_MODE=$$ghash \
          -c test.c -o $(TEST_BUILD_DIR)/test-$${name}.o; \
	          $(CC) $(CFLAGS) -o $(TEST_BUILD_DIR)/test-$${name} \
          $(TEST_BUILD_DIR)/aes-$${name}.o \
          $(TEST_BUILD_DIR)/test-$${name}.o $(TEST_BUILD_DIR)/munit.o; \
	          $(TEST_BUILD_DIR)/test-$${name}; \
	        done; \
      done; \
      done; \
      done; \
    done; \
	  done; \
	done

clean:
	rm -f aes.o
	rm -rf $(TEST_BUILD_DIR)
