/*
 * SPDX-FileCopyrightText: kokke
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: Unlicense
 */
#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// OFB enables encryption in output-feedback mode.
// ECB enables the basic ECB 16-byte block algorithm. Modes can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 0
#endif

#ifndef ECB
  #define ECB 0
#endif

#ifndef CTR
  #define CTR 1
#endif

#ifndef OFB
  #define OFB 0
#endif

#ifndef GCM
  #define GCM 0
#endif

/* GCM GHASH implementation profiles. */
#define AES_GCM_GHASH_MODE_AUTO       0
#define AES_GCM_GHASH_MODE_BITWISE    1
#define AES_GCM_GHASH_MODE_WIDE       2
#define AES_GCM_GHASH_MODE_TABLE4     3
#define AES_GCM_GHASH_MODE_FAST_TABLE 4
#define AES_GCM_GHASH_MODE_HARDWARE   5

#ifndef AES_GCM_GHASH_MODE
  #define AES_GCM_GHASH_MODE AES_GCM_GHASH_MODE_AUTO
#endif

#if (AES_GCM_GHASH_MODE < AES_GCM_GHASH_MODE_AUTO) || \
    (AES_GCM_GHASH_MODE > AES_GCM_GHASH_MODE_HARDWARE)
  #error "AES_GCM_GHASH_MODE is invalid"
#endif

/*
 * S-box implementation modes:
 *   AES_SBOX_MODE_CONSTANT_TIME - fixed-size masked scan (default)
 *   AES_SBOX_MODE_RUNTIME       - generated in RAM, then masked scan
 *   AES_SBOX_MODE_FAST          - direct lookup; not constant-time
 */
#define AES_SBOX_MODE_CONSTANT_TIME 1
#define AES_SBOX_MODE_RUNTIME       2
#define AES_SBOX_MODE_FAST          3

#ifndef AES_SBOX_MODE
  #define AES_SBOX_MODE AES_SBOX_MODE_CONSTANT_TIME
#endif

#if (AES_SBOX_MODE < AES_SBOX_MODE_CONSTANT_TIME) || \
    (AES_SBOX_MODE > AES_SBOX_MODE_FAST)
  #error "AES_SBOX_MODE must be AES_SBOX_MODE_CONSTANT_TIME, AES_SBOX_MODE_RUNTIME, or AES_SBOX_MODE_FAST"
#endif

/* 0 keeps byte-safe operations; 1 enables portable native-width helpers. */
#ifndef AES_WIDE_OPS
  #define AES_WIDE_OPS 0
#endif

#if (AES_WIDE_OPS != 0) && (AES_WIDE_OPS != 1)
  #error "AES_WIDE_OPS must be 0 or 1"
#endif

/* AES128 is the default when no key size is selected by the build. */
#if !defined(AES128) && !defined(AES192) && !defined(AES256)
  #define AES128 1
#endif

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1)) || \
    (defined(OFB) && (OFB == 1))
  uint8_t Iv[AES_BLOCKLEN];
#if defined(OFB) && (OFB == 1)
  uint8_t ofb_pos;
#endif
#endif
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
#if AES_SBOX_MODE == AES_SBOX_MODE_RUNTIME
/* Must be called before AES_init_ctx(), AES_init_ctx_iv(), or encryption. */
void AES_init_sbox(void);
#endif
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1)) || \
    (defined(OFB) && (OFB == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
#endif

#if defined(ECB) && (ECB == 1)
// buffer size is exactly AES_BLOCKLEN bytes; 
// you need only AES_init_ctx as IV is not used in ECB 
// NB: ECB is considered insecure for most uses
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);

#endif // #if defined(ECB) && (ECB == !)


#if defined(CBC) && (CBC == 1)
// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CBC) && (CBC == 1)


#if defined(CTR) && (CTR == 1)

// Same function for encrypting as for decrypting. 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CTR) && (CTR == 1)


#if defined(OFB) && (OFB == 1)

// Same function for encrypting as for decrypting.
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key
void AES_OFB_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(OFB) && (OFB == 1)


#if defined(GCM) && (GCM == 1)

#define AES_GCM_SUCCESS 0
#define AES_GCM_ERROR   (-1)

struct AES_GCM_ctx
{
  struct AES_ctx aes;
  uint8_t H[AES_BLOCKLEN];
  uint8_t J0[AES_BLOCKLEN];
  uint8_t counter[AES_BLOCKLEN];
  uint8_t stream[AES_BLOCKLEN];
  uint8_t S[AES_BLOCKLEN];
  uint8_t ghash[AES_BLOCKLEN];
#if (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_TABLE4) || \
    (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_FAST_TABLE)
      uint8_t ghash_table[32][16][AES_BLOCKLEN];
#endif
  uint64_t aad_len;
  uint64_t text_len;
  size_t stream_pos;
  size_t ghash_len;
  uint8_t phase;
  uint8_t direction;
};

/*
 * Initialize GCM with a key and nonce. The nonce may have any non-zero
 * length; the 96-bit form is the fast path recommended by NIST SP 800-38D.
 */
int AES_GCM_init(struct AES_GCM_ctx* ctx, const uint8_t* key,
                 const uint8_t* iv, size_t iv_len);

/* AAD must be supplied before the first encrypt/decrypt update. A context is
 * single-direction; reinitialize it before switching between encryption and
 * decryption. Every update return value must be checked. */
int AES_GCM_aad_update(struct AES_GCM_ctx* ctx, const uint8_t* aad,
                       size_t length);
int AES_GCM_encrypt_update(struct AES_GCM_ctx* ctx, uint8_t* buf,
                           size_t length);
int AES_GCM_decrypt_update(struct AES_GCM_ctx* ctx, uint8_t* buf,
                           size_t length);

/* Tag lengths permitted by SP 800-38D are 4, 8, and 12 through 16 bytes. */
int AES_GCM_encrypt_finish(struct AES_GCM_ctx* ctx, uint8_t* tag,
                           size_t tag_len);
int AES_GCM_decrypt_finish(struct AES_GCM_ctx* ctx, const uint8_t* tag,
                           size_t tag_len);

/* Clear expanded key material and intermediate authentication state. */
void AES_GCM_clear(struct AES_GCM_ctx* ctx);

#endif // #if defined(GCM) && (GCM == 1)


#endif // _AES_H_
