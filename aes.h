#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#ifndef CTR
  #define CTR 1
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
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
  uint8_t Iv[AES_BLOCKLEN];
#endif
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
#if AES_SBOX_MODE == AES_SBOX_MODE_RUNTIME
/* Must be called before AES_init_ctx(), AES_init_ctx_iv(), or encryption. */
void AES_init_sbox(void);
#endif
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
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


#endif // _AES_H_
