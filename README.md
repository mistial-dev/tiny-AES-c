<!--
SPDX-FileCopyrightText: kokke
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: Unlicense
-->

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](unlicense.txt)
[![Build Status](https://img.shields.io/badge/tests-100%25%20passing-brightgreen.svg)](https://github.com/mistial-dev/tiny-AES-c/actions)
### Tiny AES in C

This repository is a fork of [kokke/tiny-AES-c](https://github.com/kokke/tiny-AES-c).
Fork-specific changes are documented in [CHANGELOG.md](CHANGELOG.md).

This is a small and portable implementation of the AES [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29), [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29), [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29), [OFB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_.28OFB.29), and opt-in authenticated [CCM](https://en.wikipedia.org/wiki/CCM_mode), [EAX](https://eprint.iacr.org/2003/069), and [GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) modes written in C.

You can override the default key-size of 128 bit with 192 or 256 bit by defining the symbols AES192 or AES256 in [`aes.h`](aes.h).

The API is very simple and looks like this (I am using C99 `<stdint.h>`-style annotated types):

```C
/* Initialize context calling one of: */
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);

/* ... or reset IV at random point: */
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);

/* Then start encrypting and decrypting with the functions below: */
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);

void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

/* Same function for encrypting as for decrypting in CTR mode */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

/* Same function for encrypting as for decrypting in OFB mode */
void AES_OFB_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

/* Enable CCM=1 for one-shot authenticated encryption. */
int AES_CCM_encrypt(const uint8_t* key, const uint8_t* nonce,
                    size_t nonce_len, const uint8_t* aad, size_t aad_len,
                    const uint8_t* plaintext, size_t plaintext_len,
                    uint8_t* ciphertext, uint8_t* tag, size_t tag_len);

/* Enable EAX=1 for one-shot authenticated encryption. */
int AES_EAX_encrypt(const uint8_t* key, const uint8_t* nonce,
                    size_t nonce_len, const uint8_t* aad, size_t aad_len,
                    const uint8_t* plaintext, size_t plaintext_len,
                    uint8_t* ciphertext, uint8_t* tag, size_t tag_len);

/* Enable GCM with GCM=1 and use this streaming API. */
int AES_GCM_init(struct AES_GCM_ctx* ctx, const uint8_t* key,
                 const uint8_t* iv, size_t iv_len);
int AES_GCM_aad_update(struct AES_GCM_ctx* ctx, const uint8_t* aad, size_t length);
int AES_GCM_encrypt_update(struct AES_GCM_ctx* ctx, uint8_t* buf, size_t length);
int AES_GCM_decrypt_update(struct AES_GCM_ctx* ctx, uint8_t* buf, size_t length);
int AES_GCM_encrypt_finish(struct AES_GCM_ctx* ctx, uint8_t* tag, size_t tag_len);
int AES_GCM_decrypt_finish(struct AES_GCM_ctx* ctx, const uint8_t* tag, size_t tag_len);
```

Important notes: 
 * No padding is provided so for CBC and ECB all buffers should be multiples of 16 bytes. For padding [PKCS7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7) is recommendable.
 * OFB and CTR accept arbitrary buffer lengths and preserve their stream position across calls. OFB requires a unique IV for every message under the same key and provides confidentiality only; use CCM, GCM, or another authenticator when integrity is required.
 * ECB mode is considered unsafe for most uses and is not implemented in streaming mode. If you need this mode, call the function for every block of 16 bytes you need encrypted. See [wikipedia's article on ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)) for more details.
 * This library is designed for small code size and simplicity, intended for cases where small binary size, low memory footprint and portability is more important than high performance. If speed is a concern, you can try more complex libraries, e.g. [Mbed TLS](https://tls.mbed.org/), [OpenSSL](https://www.openssl.org/) etc.
 * This fork uses fixed-size masked scans for the AES S-boxes instead of secret-indexed table lookups, reducing cache-timing leakage. Constant-time behavior still depends on the compiler and target platform.

The default build enables only CTR. CBC, ECB, OFB, CCM, EAX, and GCM are opt-in so unused modes do not add their code or context state. Enable modes with `AES_ENABLE_CBC`, `AES_ENABLE_ECB`, `AES_ENABLE_OFB`, `AES_ENABLE_CCM`, `AES_ENABLE_EAX`, and `AES_ENABLE_GCM` in Make, or the corresponding `TINY_AES_ENABLE_*` CMake options. Direct users can define the `CBC`, `ECB`, `OFB`, `CCM`, `EAX`, and `GCM` symbols to `1` before including [`aes.h`](aes.h).

For example, enable OFB without the other optional modes:

    make AES_ENABLE_OFB=1
    cmake -S . -B build -DTINY_AES_ENABLE_OFB=ON

CCM is enabled independently with `make AES_ENABLE_CCM=1` or
`cmake -S . -B build -DTINY_AES_ENABLE_CCM=ON`. It is a packet-oriented,
one-shot mode: the nonce, AAD, and payload lengths are supplied up front.
Nonces must be 7–13 bytes and unique for the key; authentication tags must be
even-sized values from 4–16 bytes. CCM does not provide streaming semantics.
Encryption and decryption support in-place buffers. Decryption wipes the
plaintext output on authentication failure, and callers must still treat a
failure as rejection and must not use the output. CCM is compiled out unless
explicitly enabled.

EAX is enabled with `make AES_ENABLE_EAX=1` or
`cmake -S . -B build -DTINY_AES_ENABLE_EAX=ON`. It is a heap-free, one-shot
AEAD interface with arbitrary nonce and AAD lengths and tags from 0–16 bytes.
Nonce uniqueness remains the caller's responsibility. Decryption authenticates
before writing plaintext and leaves the output untouched on authentication
failure. EAX is compiled out unless explicitly enabled.

OFB is a synchronous stream mode: encryption and decryption use the same
function, do not require padding, and can process data in arbitrary chunks.
The IV is not secret, but it must never repeat with the same key. OFB does not
authenticate ciphertext or protect against replay.

C++ users should `#include` [aes.hpp](aes.hpp) instead of [aes.h](aes.h).

There is no built-in error checking or protection from out-of-bounds memory access errors as a result of malicious input.

Binary size and memory use depend on the compiler, target, enabled modes,
key size, and build profile.


## Build-time profiles

The secure profile is the default and uses fixed-size masked S-box scans. The
following named options are available in the Makefile:

    make AES_SBOX_MODE=secure AES_WIDE_OPS=off
    make AES_SBOX_MODE=runtime AES_WIDE_OPS=auto
    make AES_SBOX_MODE=fast AES_WIDE_OPS=auto

The equivalent CMake options are `TINY_AES_SBOX_MODE=secure|runtime|fast` and
`TINY_AES_WIDE_OPS=ON|OFF`.

The `runtime` S-box profile generates the tables in a fixed 256-byte RAM
allocation. Call `AES_init_sbox()` once before initializing an AES context.
Lookups still scan all entries and retain the constant-time memory-access
pattern; this profile trades ROM for RAM and startup work without using heap
allocation.

The `fast` profile uses direct table indexing and is not constant-time. Use it
only when cache-timing leakage is outside the threat model. Wide operations
use alignment-safe `memcpy` temporaries and automatically fall back to byte
operations on targets where a wider native type is not appropriate.

GCM is disabled by default. Enable it with `AES_ENABLE_GCM=1` in Make or
`TINY_AES_ENABLE_GCM=ON` in CMake. Its default GHASH implementation is
constant-time and uses fixed storage with no heap allocation. Full 16-byte
payload blocks use a block-wise counter/GHASH path; short or split updates
remain supported by the streaming path.

Select the GHASH implementation with `AES_GCM_GHASH_MODE` in Make or
`TINY_AES_GCM_GHASH_MODE` in CMake:

* `auto` (default) selects the portable constant-time implementation and uses
  wide operations when enabled.
* `bitwise` is the smallest constant-time implementation.
* `wide` uses native 64-bit arithmetic where available.
* `table4` uses an 8 KiB, fixed-layout constant-time lookup table.
* `fast-table` uses the same table with direct indexing and is not
  constant-time.
* `hardware` calls the target-provided `AES_GCM_GHASH_HARDWARE_MULTIPLY`
  macro, whose signature is `(result, input, hash_subkey)`.

For example, an embedded Cortex-A53 build can connect the hook to an
ARMv8-A PMULL implementation supplied by the platform crypto layer:

    /* target_ghash.h */
    void cortex_a53_ghash_multiply(uint8_t result[16],
                                   const uint8_t input[16],
                                   const uint8_t hash_subkey[16]);

    /* build flags */
    -DGCM=1 -DAES_GCM_GHASH_MODE=5 \
      -DAES_GCM_GHASH_HARDWARE_MULTIPLY=cortex_a53_ghash_multiply

`cortex_a53_ghash_multiply` would normally be a small wrapper around the
platform's ARMv8 PMULL routine, including the required GHASH byte order and
reduction polynomial conversion. The wrapper must be tested against the
portable profile and must preserve the constant-time properties required by
the application. Other processors can use the same hook for a vendor AES/GCM
peripheral or a native polynomial-multiply instruction; this library does not
depend on a particular SDK or hardware API.

For example:

    make AES_ENABLE_GCM=1 AES_GCM_GHASH_MODE=wide AES_WIDE_OPS=auto
    cmake -S . -B build -DTINY_AES_ENABLE_GCM=ON \
      -DTINY_AES_GCM_GHASH_MODE=table4

GCM has important application-level requirements. IVs/nonces must never be
reused with the same key; use a construction that guarantees uniqueness.
Each `AES_GCM_ctx` is single-direction: the first encrypt or decrypt update
selects its direction, and an update using the opposite direction returns
`AES_GCM_ERROR` without modifying the context or buffer. Reinitialize the
context with `AES_GCM_init` before switching direction, and check every update
return value.
`AES_GCM_decrypt_update` decrypts in place before authentication completes, so
callers must treat that buffer as unauthenticated and must not act on it until
`AES_GCM_decrypt_finish` returns `AES_GCM_SUCCESS`. Check every API return
value, use an authenticated tag of an appropriate length (16 bytes is the
normal choice), and wipe contexts with `AES_GCM_clear` when they are no longer
needed. GCM does not provide replay protection, key management, or nonce
generation.

Measure the exact configuration with:

    make size AES_SBOX_MODE=secure AES_WIDE_OPS=off

The host-only benchmark is opt-in and is not part of the unit-test matrix:

    make benchmark AES_ENABLE_GCM=1 AES_GCM_GHASH_MODE=auto \
      BENCHMARK_BYTES=16384 BENCHMARK_ITERATIONS=100

Targets can replace `AES_BENCHMARK_NOW()` and
`AES_BENCHMARK_TICKS_PER_SECOND` with a cycle counter and its calibration.
Benchmark results are meaningful only for the same compiler, optimization,
processor, clock, S-box profile, GHASH profile, and payload shape.

This implementation is verified against the data in:

[National Institute of Standards and Technology Special Publication 800-38A 2001 ED](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) Appendix F: Example Vectors for Modes of Operation of the AES.

The other appendices in the document are valuable for implementation details on e.g. padding, generation of IVs and nonces in CTR-mode etc.

For CAVP testing of ECB, CBC, OFB, CFB, and CTR modes from SP 800-38A,
see the [NIST CAVP block ciphers page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers).

The GCM implementation is checked against compact samples from the NIST CAVP
AES-GCM vectors in [SharedAES-GCM](https://github.com/mko-x/SharedAES-GCM/tree/master/Sources/gcm_test_vectors).
EAX is checked against the RFC-style Appendix G vectors from the EAX paper and
all 240 AES-EAX cases in the vendored [Wycheproof](https://github.com/C2SP/wycheproof)
JSON corpus. Attribution and license details are in
[`test_vectors/eax/README.md`](test_vectors/eax/README.md).

## Testing

Unit tests use the vendored [µunit (munit)](https://nemequ.github.io/munit/) framework and cover each mode in isolation, all AES key sizes, S-box profiles, GHASH profiles, and focused API boundaries. One all-enabled build checks integration without multiplying every mode subset. CCM, EAX, and GCM are compiled out when disabled.

Samples and focused tests run by default. Enable the complete vendored CAVP corpora with one switch:

    make AES_CAVP=1 test

Or with CMake:

    cmake -S . -B build -DTINY_AES_CAVP=ON
    cmake --build build
    ctest --test-dir build --output-on-failure --parallel 4

The CAVP run builds each mode independently and runs only that mode's corpus;
it does not repeat the same corpus across every mode subset. Every key size,
S-box profile, software GHASH profile, wide-operation path, and the hardware
GHASH dispatch hook is exercised at least once. CTR remains covered by SP
800-38A samples and focused tests because its counter-uniqueness requirement is
configuration-dependent. These vectors provide informal validation, not a
NIST certificate.

Run the Makefile test suite with:

    make test

Or use CMake and CTest on platforms supported by CMake:

    cmake -S . -B build
    cmake --build build
    ctest --test-dir build --output-on-failure


A heartfelt thank-you to [all the nice people](https://github.com/kokke/tiny-AES-c/graphs/contributors) out there who have contributed to the upstream project.


The AES implementation remains in the public domain. The vendored µunit
framework is distributed under its MIT license.
