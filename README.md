![CI](https://github.com/mistial-dev/tiny-AES-C/actions/workflows/c-cpp.yml/badge.svg)
### Tiny AES in C

This repository is a fork of [kokke/tiny-AES-c](https://github.com/kokke/tiny-AES-c).
Fork-specific changes are documented in [CHANGELOG.md](CHANGELOG.md).

This is a small and portable implementation of the AES [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29), [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29) and [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) encryption algorithms written in C.

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
```

Important notes: 
 * No padding is provided so for CBC and ECB all buffers should be multiples of 16 bytes. For padding [PKCS7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7) is recommendable.
 * ECB mode is considered unsafe for most uses and is not implemented in streaming mode. If you need this mode, call the function for every block of 16 bytes you need encrypted. See [wikipedia's article on ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)) for more details.
 * This library is designed for small code size and simplicity, intended for cases where small binary size, low memory footprint and portability is more important than high performance. If speed is a concern, you can try more complex libraries, e.g. [Mbed TLS](https://tls.mbed.org/), [OpenSSL](https://www.openssl.org/) etc.
 * This fork uses fixed-size masked scans for the AES S-boxes instead of secret-indexed table lookups, reducing cache-timing leakage. Constant-time behavior still depends on the compiler and target platform.

You can choose to use any or all of the modes-of-operations, by defining the symbols CBC, CTR or ECB in [`aes.h`](aes.h) (read the comments for clarification).

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

Measure the exact configuration with:

    make size AES_SBOX_MODE=secure AES_WIDE_OPS=off

This implementation is verified against the data in:

[National Institute of Standards and Technology Special Publication 800-38A 2001 ED](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) Appendix F: Example Vectors for Modes of Operation of the AES.

The other appendices in the document are valuable for implementation details on e.g. padding, generation of IVs and nonces in CTR-mode etc.

## Testing

Unit tests use the vendored [µunit (munit)](https://nemequ.github.io/munit/) framework and exercise all 126 compile-time combinations of AES-128/192/256, every non-empty ECB/CBC/CTR mode combination, all S-box profiles, and both wide-operation settings. Each enabled mode is checked against NIST SP 800-38A Appendix F vectors.

Run the Makefile test suite with:

    make test

Or use CMake and CTest on platforms supported by CMake:

    cmake -S . -B build
    cmake --build build
    ctest --test-dir build --output-on-failure


A heartfelt thank-you to [all the nice people](https://github.com/kokke/tiny-AES-c/graphs/contributors) out there who have contributed to the upstream project.


The AES implementation remains in the public domain. The vendored µunit
framework is distributed under its MIT license.
