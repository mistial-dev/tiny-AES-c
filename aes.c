/*
 * SPDX-FileCopyrightText: kokke
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: Unlicense
 *

This is an implementation of the AES algorithm, specifically ECB, CTR, CBC, OFB,
CCM, EAX, and GCM modes.
Block size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97 
    f5d3d58503b9699de785895a96fdbaaf 
    43b1cd7f598ece23881b00e3ed030688 
    7b0c785e27e8ad3f8223207104725dd4 


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the key size is proportionally larger.

*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <string.h> /* memcpy, memset */
#include "aes.h"

/*****************************************************************************/
/* Integer width note (MCU / AVR-oriented):                                  */
/*   Use size_t only for API buffer lengths that may exceed 255.             */
/*   Prefer uint8_t for block offsets (0..15), rounds, and similar counters. */
/*****************************************************************************/

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
/* Number of columns in the AES state (constant for AES: 4). */
#define Nb 4

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4        // The number of 32 bit words in a key.
    #define Nr 10       // The number of rounds in AES Cipher.
#endif

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif




/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1) || \
    (defined(CTR) && CTR == 1) || (defined(OFB) && OFB == 1) || \
    (defined(GCM) && GCM == 1) || (defined(CCM) && CCM == 1) || \
    (defined(EAX) && EAX == 1) || \
    (defined(EAX_PRIME) && EAX_PRIME == 1) || \
    (defined(AES_CAVP) && AES_CAVP == 1)
// state - array holding the intermediate results during encryption/decryption.
typedef uint8_t state_t[4][4];
#endif



// The default lookup-tables are const so they can be placed in read-only
// storage. Runtime S-box mode trades this table storage for a fixed RAM table.
#if AES_SBOX_MODE == AES_SBOX_MODE_RUNTIME
static uint8_t sbox[256];
#else
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1) || \
    (defined(AES_CAVP) && AES_CAVP == 1)
#if AES_SBOX_MODE == AES_SBOX_MODE_RUNTIME
static uint8_t rsbox[256];
#else
static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
#endif
#endif

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
static uint8_t xtime(uint8_t x);
#if AES_SBOX_MODE == AES_SBOX_MODE_RUNTIME
static uint8_t sbox_multiply(uint8_t a, uint8_t b)
{
  uint8_t result = 0;
  unsigned i;

  for (i = 0; i < 8; ++i)
  {
    result ^= (uint8_t)(0u - (uint8_t)(b & 1u)) & a;
    a = (uint8_t)((a << 1) ^ (0x1bu & (uint8_t)(0u - (uint8_t)(a >> 7))));
    b >>= 1;
  }

  return result;
}

static uint8_t sbox_inverse(uint8_t value)
{
  uint8_t result = 1;
  uint8_t factor = value;
  unsigned exponent = 254;

  if (value == 0)
    return 0;

  while (exponent != 0)
  {
    if (exponent & 1u)
      result = sbox_multiply(result, factor);
    factor = sbox_multiply(factor, factor);
    exponent >>= 1;
  }

  return result;
}

static uint8_t sbox_rotate_left(uint8_t value, unsigned count)
{
  return (uint8_t)((value << count) | (value >> (8u - count)));
}

void AES_init_sbox(void)
{
  unsigned i;

  for (i = 0; i < 256; ++i)
  {
    const uint8_t inverse = sbox_inverse((uint8_t)i);
    sbox[i] = (uint8_t)(inverse ^
                        sbox_rotate_left(inverse, 1) ^
                        sbox_rotate_left(inverse, 2) ^
                        sbox_rotate_left(inverse, 3) ^
                        sbox_rotate_left(inverse, 4) ^ 0x63);
  }

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1) || \
    (defined(AES_CAVP) && AES_CAVP == 1)
  for (i = 0; i < 256; ++i)
    rsbox[sbox[i]] = (uint8_t)i;
#endif
}
#endif

#if AES_WIDE_OPS && defined(UINTPTR_MAX) && defined(UINT32_MAX)
#if defined(UINT64_MAX) && (UINTPTR_MAX >= UINT64_MAX)
typedef uint64_t aes_word_t;
#define AES_WIDE_OPS_ENABLED 1
#elif UINTPTR_MAX >= UINT32_MAX
typedef uint32_t aes_word_t;
#define AES_WIDE_OPS_ENABLED 1
#else
#define AES_WIDE_OPS_ENABLED 0
#endif
#else
#define AES_WIDE_OPS_ENABLED 0
#endif

static void aes_copy_bytes(uint8_t* dst, const uint8_t* src, size_t length)
{
#if AES_WIDE_OPS_ENABLED
  while (length >= sizeof(aes_word_t))
  {
    aes_word_t word;
    memcpy(&word, src, sizeof(word));
    memcpy(dst, &word, sizeof(word));
    src += sizeof(word);
    dst += sizeof(word);
    length -= sizeof(word);
  }
#endif
  while (length-- != 0)
    *dst++ = *src++;
}

void AES_secure_zero(void* memory, size_t length)
{
  volatile uint8_t* bytes = (volatile uint8_t*)memory;
  size_t i;

  for (i = 0; i < length; ++i)
    bytes[i] = 0;
}

void AES_ctx_clear(struct AES_ctx* ctx)
{
  if (ctx == NULL)
    return;
  AES_secure_zero(ctx, sizeof(*ctx));
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

#if defined(CBC) && (CBC == 1)
static void aes_xor_block(uint8_t* dst, const uint8_t* src)
{
#if AES_WIDE_OPS_ENABLED
  size_t offset;
  for (offset = 0; offset < AES_BLOCKLEN; offset += sizeof(aes_word_t))
  {
    aes_word_t left;
    aes_word_t right;
    memcpy(&left, dst + offset, sizeof(left));
    memcpy(&right, src + offset, sizeof(right));
    left ^= right;
    memcpy(dst + offset, &left, sizeof(left));
  }
#else
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i)
    dst[i] ^= src[i];
#endif
}
#endif

/*
 * Read the S-box without using a secret-indexed lookup. Reading every entry
 * keeps the memory-access pattern independent of the input byte. The
 * volatile pointer also prevents the compiler from replacing this scan with
 * a direct table lookup.
 */
static uint8_t getSBoxValue(uint8_t num)
{
#if AES_SBOX_MODE == AES_SBOX_MODE_FAST
  return sbox[num];
#else
  const volatile uint8_t *table = sbox;
  uint8_t value = 0;
  unsigned i;

  for (i = 0; i < 256; ++i)
  {
    const uint8_t mask = (uint8_t)(0u - (uint8_t)(i == num));
    value |= table[i] & mask;
  }

  return value;
#endif
}

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  uint8_t rcon = 0x01;
  
  // The first round key is the key itself.
  aes_copy_bytes(RoundKey, Key, Nk * 4);

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ rcon;
      rcon = xtime(rcon);
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
#if defined(OFB) && (OFB == 1)
  ctx->ofb_pos = AES_BLOCKLEN;
#endif
}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1)) || \
    (defined(OFB) && (OFB == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  aes_copy_bytes(ctx->Iv, iv, AES_BLOCKLEN);
#if defined(OFB) && (OFB == 1)
  ctx->ofb_pos = AES_BLOCKLEN;
#endif
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  aes_copy_bytes(ctx->Iv, iv, AES_BLOCKLEN);
#if defined(OFB) && (OFB == 1)
  ctx->ofb_pos = AES_BLOCKLEN;
#endif
}
#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1) || \
    (defined(CTR) && CTR == 1) || (defined(OFB) && OFB == 1) || \
    (defined(GCM) && GCM == 1) || (defined(CCM) && CCM == 1) || \
    (defined(EAX) && EAX == 1) || \
    (defined(EAX_PRIME) && EAX_PRIME == 1) || \
    (defined(AES_CAVP) && AES_CAVP == 1)

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1) || \
    (defined(AES_CAVP) && AES_CAVP == 1)
static uint8_t getSBoxInvert(uint8_t num)
{
#if AES_SBOX_MODE == AES_SBOX_MODE_FAST
  return rsbox[num];
#else
  const volatile uint8_t *table = rsbox;
  uint8_t value = 0;
  unsigned i;

  for (i = 0; i < 256; ++i)
  {
    const uint8_t mask = (uint8_t)(0u - (uint8_t)(i == num));
    value |= table[i] & mask;
  }

  return value;
#endif
}

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  { 
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right  
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right 
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns()
  for (round = 1; ; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  // Add round key to last round
  AddRoundKey(Nr, state, RoundKey);
}

#endif // forward AES cipher is used by an enabled mode

#if defined(AES_CAVP) && (AES_CAVP == 1)
void AES_CAVP_encrypt_block(const uint8_t* key, uint8_t block[AES_BLOCKLEN])
{
  struct AES_ctx ctx;

  AES_init_ctx(&ctx, key);
  Cipher((state_t*)block, ctx.RoundKey);
#if AES_ZEROIZE
  AES_ctx_clear(&ctx);
#endif
}

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1) || \
    (defined(AES_CAVP) && AES_CAVP == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without InvMixColumn()
  for (round = (Nr - 1); ; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    if (round == 0) {
      break;
    }
    InvMixColumns(state);
  }

}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

#if defined(AES_CAVP) && (AES_CAVP == 1)
void AES_CAVP_decrypt_block(const uint8_t* key, uint8_t block[AES_BLOCKLEN])
{
  struct AES_ctx ctx;

  AES_init_ctx(&ctx, key);
  InvCipher((state_t*)block, ctx.RoundKey);
#if AES_ZEROIZE
  AES_ctx_clear(&ctx);
#endif
}
#endif

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(ECB) && (ECB == 1)


void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  InvCipher((state_t*)buf, ctx->RoundKey);
}


#endif // #if defined(ECB) && (ECB == 1)





#if defined(CBC) && (CBC == 1)


static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  aes_xor_block(buf, Iv);
}

void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    XorWithIv(buf, Iv);
    Cipher((state_t*)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  /* store Iv in ctx for next call */
  aes_copy_bytes(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t storeNextIv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    aes_copy_bytes(storeNextIv, buf, AES_BLOCKLEN);
    InvCipher((state_t*)buf, ctx->RoundKey);
    XorWithIv(buf, ctx->Iv);
    aes_copy_bytes(ctx->Iv, storeNextIv, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }

}

#endif // #if defined(CBC) && (CBC == 1)



#if defined(CTR) && (CTR == 1)

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t buffer[AES_BLOCKLEN];
  
  size_t i;
  int bi;
  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
    {
      
      aes_copy_bytes(buffer, ctx->Iv, AES_BLOCKLEN);
      Cipher((state_t*)buffer,ctx->RoundKey);

      /* Increment Iv and handle overflow */
      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
      {
	/* inc will overflow */
        if (ctx->Iv[bi] == 255)
	{
          ctx->Iv[bi] = 0;
          continue;
        } 
        ctx->Iv[bi] += 1;
        break;   
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]);
  }
}

#endif // #if defined(CTR) && (CTR == 1)


#if defined(OFB) && (OFB == 1)

/* Symmetrical operation: same function for encrypting as for decrypting. */
void AES_OFB_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t pos = ctx->ofb_pos;

  while (length-- != 0)
  {
    if (pos == AES_BLOCKLEN)
    {
      Cipher((state_t*)ctx->Iv, ctx->RoundKey);
      pos = 0;
    }

    *buf++ ^= ctx->Iv[pos++];
  }

  ctx->ofb_pos = pos;
}

#endif // #if defined(OFB) && (OFB == 1)


#if defined(GCM) && (GCM == 1)

#define AES_GCM_PHASE_AAD   0u
#define AES_GCM_PHASE_TEXT  1u
#define AES_GCM_PHASE_FINAL 2u
#define AES_GCM_DIRECTION_NONE    0u
#define AES_GCM_DIRECTION_ENCRYPT 1u
#define AES_GCM_DIRECTION_DECRYPT 2u
#define AES_GCM_MAX_TEXT_BYTES ((((uint64_t)1) << 36) - 32u)

static void gcm_store_be64(uint8_t* dst, uint64_t value)
{
  unsigned i;
  for (i = 0; i < 8; ++i)
    dst[7u - i] = (uint8_t)(value >> (i * 8u));
}

#if defined(UINT64_MAX) && \
    ((AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_WIDE) || \
     ((AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_AUTO) && AES_WIDE_OPS))
static uint64_t gcm_load_be64(const uint8_t* src)
{
  uint64_t value = 0;
  unsigned i;
  for (i = 0; i < 8; ++i)
    value = (value << 8) | src[i];
  return value;
}
#endif

/* Constant-time bytewise multiplication in GF(2^128). */
#if (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_BITWISE) || \
    (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_AUTO && \
     (!AES_WIDE_OPS || !defined(UINT64_MAX))) || \
    (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_TABLE4) || \
    (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_FAST_TABLE) || \
    (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_WIDE && !defined(UINT64_MAX))
static void gcm_multiply_bitwise(uint8_t* result, const uint8_t* left,
                                 const uint8_t* right)
{
  uint8_t z[AES_BLOCKLEN] = { 0 };
  uint8_t v[AES_BLOCKLEN];
  unsigned bit;

  aes_copy_bytes(v, right, AES_BLOCKLEN);
  for (bit = 0; bit < 128; ++bit)
  {
    const uint8_t bit_mask = (uint8_t)(0u -
      (uint8_t)((left[bit / 8u] >> (7u - (bit % 8u))) & 1u));
    uint8_t carry = 0;
    unsigned i;

    for (i = 0; i < AES_BLOCKLEN; ++i)
      z[i] ^= (uint8_t)(v[i] & bit_mask);

    for (i = 0; i < AES_BLOCKLEN; ++i)
    {
      const uint8_t next_carry = (uint8_t)(v[i] & 1u);
      v[i] = (uint8_t)((v[i] >> 1) | (carry << 7));
      carry = next_carry;
    }
    v[0] ^= (uint8_t)(0xe1u & (uint8_t)(0u - carry));
  }
  aes_copy_bytes(result, z, AES_BLOCKLEN);
}
#endif

#if AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_WIDE || \
    ((AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_AUTO) && AES_WIDE_OPS)
#if defined(UINT64_MAX)
static void gcm_multiply_wide(uint8_t* result, const uint8_t* left,
                              const uint8_t* right)
{
  uint64_t xh = gcm_load_be64(left);
  uint64_t xl = gcm_load_be64(left + 8);
  uint64_t zh = 0;
  uint64_t zl = 0;
  uint64_t vh = gcm_load_be64(right);
  uint64_t vl = gcm_load_be64(right + 8);
  unsigned bit;

  for (bit = 0; bit < 128; ++bit)
  {
    const uint64_t bit_mask = 0u - (xh >> 63);
    const uint64_t reduction = 0xe100000000000000ULL & (0u - (vl & 1u));
    zh ^= vh & bit_mask;
    zl ^= vl & bit_mask;
    vl = (vl >> 1) | (vh << 63);
    vh = (vh >> 1) ^ reduction;
    xh = (xh << 1) | (xl >> 63);
    xl <<= 1;
  }
  gcm_store_be64(result, zh);
  gcm_store_be64(result + 8, zl);
}
#endif
#endif

#if (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_TABLE4) || \
    (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_FAST_TABLE)
static void gcm_init_table(struct AES_GCM_ctx* ctx)
{
  uint8_t input[AES_BLOCKLEN];
  unsigned position;
  unsigned entry;

  for (position = 0; position < 32; ++position)
  {
    for (entry = 0; entry < 16; ++entry)
    {
      memset(input, 0, AES_BLOCKLEN);
      input[position / 2u] = (uint8_t)((position % 2u) == 0u ?
        entry << 4 : entry);
      gcm_multiply_bitwise(ctx->ghash_table[position][entry], input,
                           ctx->H);
    }
  }
}

#if AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_TABLE4
static void gcm_select_table4(uint8_t* selected,
                              const uint8_t table[16][AES_BLOCKLEN],
                              uint8_t nibble)
{
  unsigned entry;
  unsigned i;
  memset(selected, 0, AES_BLOCKLEN);
  for (entry = 0; entry < 16; ++entry)
  {
    const uint8_t mask = (uint8_t)(0u - (uint8_t)(entry == nibble));
    for (i = 0; i < AES_BLOCKLEN; ++i)
      selected[i] |= (uint8_t)(table[entry][i] & mask);
  }
}
#endif

static void gcm_multiply_table4(uint8_t* result, const uint8_t* left,
                                const struct AES_GCM_ctx* ctx)
{
  uint8_t value[AES_BLOCKLEN] = { 0 };
  uint8_t selected[AES_BLOCKLEN];
  unsigned position;

  for (position = 0; position < 32; ++position)
  {
    const uint8_t nibble = (uint8_t)((position % 2u) == 0u ?
      left[position / 2u] >> 4 : left[position / 2u] & 0x0fu);
#if AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_FAST_TABLE
    aes_copy_bytes(selected, ctx->ghash_table[position][nibble], AES_BLOCKLEN);
#else
    gcm_select_table4(selected, ctx->ghash_table[position], nibble);
#endif
    for (unsigned i = 0; i < AES_BLOCKLEN; ++i)
      value[i] ^= selected[i];
  }
  aes_copy_bytes(result, value, AES_BLOCKLEN);
}
#endif

#if AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_HARDWARE
#ifndef AES_GCM_GHASH_HARDWARE_MULTIPLY
#error "AES_GCM_GHASH_HARDWARE_MULTIPLY must be defined for hardware GHASH mode"
#endif
#endif

static void gcm_multiply(uint8_t* result, const uint8_t* left,
                         const struct AES_GCM_ctx* ctx)
{
#if AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_HARDWARE
  AES_GCM_GHASH_HARDWARE_MULTIPLY(result, left, ctx->H);
#elif (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_TABLE4) || \
      (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_FAST_TABLE)
  gcm_multiply_table4(result, left, ctx);
#elif AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_WIDE || \
      ((AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_AUTO) && AES_WIDE_OPS)
#if defined(UINT64_MAX)
  gcm_multiply_wide(result, left, ctx->H);
#else
  gcm_multiply_bitwise(result, left, ctx->H);
#endif
#else
  gcm_multiply_bitwise(result, left, ctx->H);
#endif
}

static void gcm_ghash_block(struct AES_GCM_ctx* ctx, const uint8_t* block)
{
  uint8_t value[AES_BLOCKLEN];
  unsigned i;

  for (i = 0; i < AES_BLOCKLEN; ++i)
    value[i] = (uint8_t)(ctx->S[i] ^ block[i]);
  gcm_multiply(ctx->S, value, ctx);
}

static void gcm_hash_bytes(struct AES_GCM_ctx* ctx, const uint8_t* data,
                           size_t length)
{
  uint8_t block[AES_BLOCKLEN] = { 0 };

  while (length >= AES_BLOCKLEN)
  {
    gcm_ghash_block(ctx, data);
    data += AES_BLOCKLEN;
    length -= AES_BLOCKLEN;
  }
  if (length != 0)
  {
    aes_copy_bytes(block, data, length);
    gcm_ghash_block(ctx, block);
  }
}

static void gcm_make_j0(struct AES_GCM_ctx* ctx, const uint8_t* iv,
                        size_t iv_len)
{
  uint8_t length_block[AES_BLOCKLEN] = { 0 };

  memset(ctx->S, 0, AES_BLOCKLEN);
  memset(ctx->ghash, 0, AES_BLOCKLEN);
  if (iv_len == 12)
  {
    memset(ctx->J0, 0, AES_BLOCKLEN);
    aes_copy_bytes(ctx->J0, iv, iv_len);
    ctx->J0[15] = 1;
  }
  else
  {
    gcm_hash_bytes(ctx, iv, iv_len);
    gcm_store_be64(length_block + 8, (uint64_t)iv_len * 8u);
    gcm_ghash_block(ctx, length_block);
    aes_copy_bytes(ctx->J0, ctx->S, AES_BLOCKLEN);
  }
  memset(ctx->S, 0, AES_BLOCKLEN);
  memset(ctx->ghash, 0, AES_BLOCKLEN);
}

static int gcm_length_is_valid(uint64_t current, size_t additional,
                               uint64_t limit)
{
  return (uint64_t)additional <= (limit - current);
}

static void gcm_pad_ghash(struct AES_GCM_ctx* ctx)
{
  if (ctx->ghash_len != 0)
  {
    memset(ctx->ghash + ctx->ghash_len, 0,
           AES_BLOCKLEN - ctx->ghash_len);
    gcm_ghash_block(ctx, ctx->ghash);
    ctx->ghash_len = 0;
    memset(ctx->ghash, 0, AES_BLOCKLEN);
  }
}

static void gcm_absorb(struct AES_GCM_ctx* ctx, const uint8_t* data,
                       size_t length)
{
  while (length != 0)
  {
    const size_t available = AES_BLOCKLEN - ctx->ghash_len;
    const size_t count = length < available ? length : available;
    aes_copy_bytes(ctx->ghash + ctx->ghash_len, data, count);
    ctx->ghash_len += count;
    data += count;
    length -= count;
    if (ctx->ghash_len == AES_BLOCKLEN)
    {
      gcm_ghash_block(ctx, ctx->ghash);
      ctx->ghash_len = 0;
      memset(ctx->ghash, 0, AES_BLOCKLEN);
    }
  }
}

static void gcm_increment_counter(uint8_t* counter)
{
  unsigned i;
  for (i = 0; i < 4; ++i)
  {
    const unsigned offset = 15u - i;
    if (counter[offset] != 0xffu)
    {
      ++counter[offset];
      break;
    }
    counter[offset] = 0;
  }
}

static void gcm_finish_ghash(struct AES_GCM_ctx* ctx)
{
  uint8_t length_block[AES_BLOCKLEN] = { 0 };

  gcm_pad_ghash(ctx);
  gcm_store_be64(length_block, ctx->aad_len * 8u);
  gcm_store_be64(length_block + 8, ctx->text_len * 8u);
  gcm_ghash_block(ctx, length_block);
}

static int gcm_tag_length_is_valid(size_t tag_len)
{
  return tag_len == 4 || tag_len == 8 || (tag_len >= 12 && tag_len <= 16);
}

static void gcm_make_tag(const struct AES_GCM_ctx* ctx, uint8_t* tag)
{
  uint8_t mask[AES_BLOCKLEN];
  uint8_t hash[AES_BLOCKLEN];
  unsigned i;

  aes_copy_bytes(mask, ctx->J0, AES_BLOCKLEN);
  Cipher((state_t*)mask, ctx->aes.RoundKey);
  aes_copy_bytes(hash, ctx->S, AES_BLOCKLEN);
  for (i = 0; i < AES_BLOCKLEN; ++i)
    tag[i] = (uint8_t)(mask[i] ^ hash[i]);
}

int AES_GCM_init(struct AES_GCM_ctx* ctx, const uint8_t* key,
                 const uint8_t* iv, size_t iv_len)
{
  uint8_t zero[AES_BLOCKLEN] = { 0 };

  if (ctx == NULL || key == NULL || iv == NULL || iv_len == 0 ||
      (uint64_t)iv_len > UINT64_MAX / 8u)
    return AES_ERR;

  AES_init_ctx(&ctx->aes, key);
  aes_copy_bytes(ctx->H, zero, AES_BLOCKLEN);
  Cipher((state_t*)ctx->H, ctx->aes.RoundKey);
#if (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_TABLE4) || \
    (AES_GCM_GHASH_MODE == AES_GCM_GHASH_MODE_FAST_TABLE)
  gcm_init_table(ctx);
#endif
  gcm_make_j0(ctx, iv, iv_len);
  aes_copy_bytes(ctx->counter, ctx->J0, AES_BLOCKLEN);
  aes_copy_bytes(ctx->S, zero, AES_BLOCKLEN);
  aes_copy_bytes(ctx->ghash, zero, AES_BLOCKLEN);
  ctx->aad_len = 0;
  ctx->text_len = 0;
  ctx->stream_pos = AES_BLOCKLEN;
  ctx->ghash_len = 0;
  ctx->phase = AES_GCM_PHASE_AAD;
  ctx->direction = AES_GCM_DIRECTION_NONE;
  return AES_OK;
}

int AES_GCM_aad_update(struct AES_GCM_ctx* ctx, const uint8_t* aad,
                       size_t length)
{
  if (ctx == NULL || ctx->phase != AES_GCM_PHASE_AAD ||
      (length != 0 && aad == NULL) ||
      !gcm_length_is_valid(ctx->aad_len, length, UINT64_MAX / 8u))
    return AES_ERR;

  gcm_absorb(ctx, aad, length);
  ctx->aad_len += (uint64_t)length;
  return AES_OK;
}

static int gcm_update(struct AES_GCM_ctx* ctx, uint8_t* buf, size_t length,
                      int decrypt)
{
  size_t i;
  const size_t total_length = length;
  const uint8_t direction = decrypt ? AES_GCM_DIRECTION_DECRYPT :
                                     AES_GCM_DIRECTION_ENCRYPT;

  if (ctx == NULL || ctx->phase == AES_GCM_PHASE_FINAL ||
      (length != 0 && buf == NULL) ||
      !gcm_length_is_valid(ctx->text_len, length, AES_GCM_MAX_TEXT_BYTES))
    return AES_ERR;
  if (ctx->direction != AES_GCM_DIRECTION_NONE &&
      ctx->direction != direction)
    return AES_ERR;
  if (ctx->direction == AES_GCM_DIRECTION_NONE)
    ctx->direction = direction;

  if (ctx->phase == AES_GCM_PHASE_AAD)
  {
    gcm_pad_ghash(ctx);
    ctx->phase = AES_GCM_PHASE_TEXT;
  }

  while (length >= AES_BLOCKLEN && ctx->stream_pos == AES_BLOCKLEN &&
         ctx->ghash_len == 0)
  {
    uint8_t ciphertext[AES_BLOCKLEN];
    unsigned j;

    gcm_increment_counter(ctx->counter);
    aes_copy_bytes(ctx->stream, ctx->counter, AES_BLOCKLEN);
    Cipher((state_t*)ctx->stream, ctx->aes.RoundKey);
    if (decrypt)
      aes_copy_bytes(ciphertext, buf, AES_BLOCKLEN);
    for (j = 0; j < AES_BLOCKLEN; ++j)
      buf[j] ^= ctx->stream[j];
    gcm_absorb(ctx, decrypt ? ciphertext : buf, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
    length -= AES_BLOCKLEN;
  }

  for (i = 0; i < length; ++i)
  {
    uint8_t ciphertext;
    if (ctx->stream_pos == AES_BLOCKLEN)
    {
      gcm_increment_counter(ctx->counter);
      aes_copy_bytes(ctx->stream, ctx->counter, AES_BLOCKLEN);
      Cipher((state_t*)ctx->stream, ctx->aes.RoundKey);
      ctx->stream_pos = 0;
    }

    ciphertext = decrypt ? buf[i] : (uint8_t)(buf[i] ^ ctx->stream[ctx->stream_pos]);
    gcm_absorb(ctx, &ciphertext, 1);
    if (decrypt)
      buf[i] ^= ctx->stream[ctx->stream_pos];
    else
      buf[i] = ciphertext;
    ++ctx->stream_pos;
  }
  ctx->text_len += (uint64_t)total_length;
  return AES_OK;
}

int AES_GCM_encrypt_update(struct AES_GCM_ctx* ctx, uint8_t* buf,
                           size_t length)
{
  return gcm_update(ctx, buf, length, 0);
}

int AES_GCM_decrypt_update(struct AES_GCM_ctx* ctx, uint8_t* buf,
                           size_t length)
{
  return gcm_update(ctx, buf, length, 1);
}

int AES_GCM_encrypt_finish(struct AES_GCM_ctx* ctx, uint8_t* tag,
                           size_t tag_len)
{
  uint8_t full_tag[AES_BLOCKLEN];

  if (ctx == NULL || tag == NULL || !gcm_tag_length_is_valid(tag_len) ||
      ctx->phase == AES_GCM_PHASE_FINAL)
    return AES_ERR;
  if (ctx->phase == AES_GCM_PHASE_AAD)
  {
    gcm_pad_ghash(ctx);
    ctx->phase = AES_GCM_PHASE_TEXT;
  }
  gcm_finish_ghash(ctx);
  gcm_make_tag(ctx, full_tag);
  aes_copy_bytes(tag, full_tag, tag_len);
  ctx->phase = AES_GCM_PHASE_FINAL;
  return AES_OK;
}

int AES_GCM_decrypt_finish(struct AES_GCM_ctx* ctx, const uint8_t* tag,
                           size_t tag_len)
{
  uint8_t expected[AES_BLOCKLEN];
  uint8_t difference = 0;
  size_t i;

  if (ctx == NULL || tag == NULL || !gcm_tag_length_is_valid(tag_len) ||
      ctx->phase == AES_GCM_PHASE_FINAL)
    return AES_ERR;
  if (ctx->phase == AES_GCM_PHASE_AAD)
  {
    gcm_pad_ghash(ctx);
    ctx->phase = AES_GCM_PHASE_TEXT;
  }
  gcm_finish_ghash(ctx);
  gcm_make_tag(ctx, expected);
  for (i = 0; i < tag_len; ++i)
    difference |= (uint8_t)(expected[i] ^ tag[i]);
  ctx->phase = AES_GCM_PHASE_FINAL;
  return difference == 0 ? AES_OK : AES_ERR;
}

void AES_GCM_clear(struct AES_GCM_ctx* ctx)
{
  if (ctx == NULL)
    return;
  AES_secure_zero(ctx, sizeof(*ctx));
}

#endif // #if defined(GCM) && (GCM == 1)

#if defined(CCM) && (CCM == 1)

#define AES_CCM_MIN_NONCE_LEN 7u
#define AES_CCM_MAX_NONCE_LEN 13u

static int ccm_tag_length_is_valid(size_t tag_len)
{
  return tag_len >= 4 && tag_len <= AES_BLOCKLEN && (tag_len & 1u) == 0;
}

static unsigned ccm_length_field_size(size_t nonce_len)
{
  return (unsigned)(15u - nonce_len);
}

static int ccm_payload_length_is_valid(size_t nonce_len, size_t length)
{
  const unsigned q = ccm_length_field_size(nonce_len);

  if (q == sizeof(uint64_t))
    return 1;
  return (uint64_t)length <= ((UINT64_C(1) << (8u * q)) - 1u);
}

static void ccm_store_length(uint8_t* dst, uint64_t value, unsigned length)
{
  while (length-- != 0)
  {
    dst[length] = (uint8_t)value;
    value >>= 8;
  }
}

static void ccm_mac_block(uint8_t* mac, const uint8_t* block,
                          const uint8_t* round_key)
{
  unsigned i;

  for (i = 0; i < AES_BLOCKLEN; ++i)
    mac[i] ^= block[i];
  Cipher((state_t*)mac, round_key);
}

static void ccm_mac_absorb(uint8_t* mac, uint8_t* block, size_t* used,
                           const uint8_t* data, size_t length,
                           const uint8_t* round_key)
{
  while (length != 0)
  {
    const size_t available = AES_BLOCKLEN - *used;
    const size_t count = length < available ? length : available;
    aes_copy_bytes(block + *used, data, count);
    *used += count;
    data += count;
    length -= count;
    if (*used == AES_BLOCKLEN)
    {
      ccm_mac_block(mac, block, round_key);
      *used = 0;
      memset(block, 0, AES_BLOCKLEN);
    }
  }
}

static void ccm_mac_pad(uint8_t* mac, uint8_t* block, size_t* used,
                        const uint8_t* round_key)
{
  if (*used != 0)
  {
    memset(block + *used, 0, AES_BLOCKLEN - *used);
    ccm_mac_block(mac, block, round_key);
    *used = 0;
    memset(block, 0, AES_BLOCKLEN);
  }
}

static void ccm_make_counter(uint8_t* counter, const uint8_t* nonce,
                             size_t nonce_len, uint64_t value)
{
  const unsigned q = ccm_length_field_size(nonce_len);

  memset(counter, 0, AES_BLOCKLEN);
  counter[0] = (uint8_t)(q - 1u);
  aes_copy_bytes(counter + 1, nonce, nonce_len);
  ccm_store_length(counter + 1 + nonce_len, value, q);
}

static void ccm_increment_counter(uint8_t* counter, unsigned q)
{
  unsigned i;

  for (i = AES_BLOCKLEN; i > AES_BLOCKLEN - q; --i)
  {
    const unsigned offset = i - 1u;
    if (++counter[offset] != 0)
      break;
  }
}

static void ccm_xor_block(uint8_t* dst, size_t length, uint8_t* counter,
                          const uint8_t* round_key)
{
  uint8_t stream[AES_BLOCKLEN];
  size_t i;

  aes_copy_bytes(stream, counter, AES_BLOCKLEN);
  Cipher((state_t*)stream, round_key);
  for (i = 0; i < length; ++i)
    dst[i] ^= stream[i];
}

static int ccm_crypt(const uint8_t* key, const uint8_t* nonce,
                     size_t nonce_len, const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, size_t input_len, uint8_t* output,
                     const uint8_t* tag, size_t tag_len, int decrypt)
{
  struct AES_ctx aes;
  uint8_t mac[AES_BLOCKLEN] = { 0 };
  uint8_t block[AES_BLOCKLEN] = { 0 };
  uint8_t b0[AES_BLOCKLEN] = { 0 };
  uint8_t counter[AES_BLOCKLEN];
  uint8_t s0[AES_BLOCKLEN];
  uint8_t full_tag[AES_BLOCKLEN];
  size_t used = 0;
  size_t offset = 0;
  unsigned q;
  unsigned i;

  if (key == NULL || nonce == NULL ||
      (aad_len != 0 && aad == NULL) ||
      (input_len != 0 && (input == NULL || output == NULL)) ||
      (decrypt && tag == NULL) || (!decrypt && tag == NULL) ||
      nonce_len < AES_CCM_MIN_NONCE_LEN || nonce_len > AES_CCM_MAX_NONCE_LEN ||
      !ccm_tag_length_is_valid(tag_len) ||
      !ccm_payload_length_is_valid(nonce_len, input_len) ||
      (uint64_t)aad_len > UINT64_MAX)
    return AES_ERR;

  q = ccm_length_field_size(nonce_len);
  b0[0] = (uint8_t)((aad_len != 0 ? 0x40u : 0u) |
                    (uint8_t)(((tag_len - 2u) / 2u) << 3) |
                    (uint8_t)(q - 1u));
  aes_copy_bytes(b0 + 1, nonce, nonce_len);
  ccm_store_length(b0 + 1 + nonce_len, (uint64_t)input_len, q);

  AES_init_ctx(&aes, key);
  ccm_mac_block(mac, b0, aes.RoundKey);

  if (aad_len != 0)
  {
    uint8_t aad_header[10] = { 0 };
    size_t header_len;

    if (aad_len < 0xff00u)
    {
      header_len = 2;
      ccm_store_length(aad_header, (uint64_t)aad_len, 2);
    }
    else if ((uint64_t)aad_len <= UINT32_MAX)
    {
      header_len = 6;
      aad_header[0] = 0xff;
      aad_header[1] = 0xfe;
      ccm_store_length(aad_header + 2, (uint64_t)aad_len, 4);
    }
    else
    {
      header_len = 10;
      aad_header[0] = 0xff;
      aad_header[1] = 0xff;
      ccm_store_length(aad_header + 2, (uint64_t)aad_len, 8);
    }
    ccm_mac_absorb(mac, block, &used, aad_header, header_len, aes.RoundKey);
    ccm_mac_absorb(mac, block, &used, aad, aad_len, aes.RoundKey);
    ccm_mac_pad(mac, block, &used, aes.RoundKey);
  }

  ccm_make_counter(counter, nonce, nonce_len, 0);
  aes_copy_bytes(s0, counter, AES_BLOCKLEN);
  Cipher((state_t*)s0, aes.RoundKey);
  ccm_increment_counter(counter, q);

  while (offset < input_len)
  {
    const size_t length = (input_len - offset < AES_BLOCKLEN) ?
                          input_len - offset : AES_BLOCKLEN;
    uint8_t plain[AES_BLOCKLEN] = { 0 };

    if (decrypt)
      aes_copy_bytes(plain, input + offset, length);
    else
      aes_copy_bytes(plain, input + offset, length);
    if (decrypt)
      ccm_xor_block(plain, length, counter, aes.RoundKey);
    ccm_mac_absorb(mac, block, &used, plain, length, aes.RoundKey);
    if (!decrypt)
    {
      aes_copy_bytes(output + offset, plain, length);
      ccm_xor_block(output + offset, length, counter, aes.RoundKey);
    }
    else
    {
      aes_copy_bytes(output + offset, plain, length);
    }
    ccm_increment_counter(counter, q);
    offset += length;
  }
  ccm_mac_pad(mac, block, &used, aes.RoundKey);

  for (i = 0; i < AES_BLOCKLEN; ++i)
    full_tag[i] = (uint8_t)(mac[i] ^ s0[i]);
  if (decrypt)
  {
    uint8_t difference = 0;
    for (i = 0; i < tag_len; ++i)
      difference |= (uint8_t)(full_tag[i] ^ tag[i]);
    if (difference != 0)
    {
      if (output != NULL)
        memset(output, 0, input_len);
#if AES_ZEROIZE
      AES_ctx_clear(&aes);
      AES_secure_zero(mac, sizeof(mac));
      AES_secure_zero(block, sizeof(block));
      AES_secure_zero(b0, sizeof(b0));
      AES_secure_zero(counter, sizeof(counter));
      AES_secure_zero(s0, sizeof(s0));
      AES_secure_zero(full_tag, sizeof(full_tag));
#endif
      return AES_ERR;
    }
  }
  else
  {
    aes_copy_bytes((uint8_t*)tag, full_tag, tag_len);
  }
#if AES_ZEROIZE
  AES_ctx_clear(&aes);
  AES_secure_zero(mac, sizeof(mac));
  AES_secure_zero(block, sizeof(block));
  AES_secure_zero(b0, sizeof(b0));
  AES_secure_zero(counter, sizeof(counter));
  AES_secure_zero(s0, sizeof(s0));
  AES_secure_zero(full_tag, sizeof(full_tag));
#endif
  return AES_OK;
}

int AES_CCM_encrypt(const uint8_t* key, const uint8_t* nonce,
                    size_t nonce_len, const uint8_t* aad, size_t aad_len,
                    const uint8_t* plaintext, size_t plaintext_len,
                    uint8_t* ciphertext, uint8_t* tag, size_t tag_len)
{
  return ccm_crypt(key, nonce, nonce_len, aad, aad_len, plaintext,
                   plaintext_len, ciphertext, tag, tag_len, 0);
}

int AES_CCM_decrypt(const uint8_t* key, const uint8_t* nonce,
                    size_t nonce_len, const uint8_t* aad, size_t aad_len,
                    const uint8_t* ciphertext, size_t ciphertext_len,
                    const uint8_t* tag, size_t tag_len, uint8_t* plaintext)
{
  return ccm_crypt(key, nonce, nonce_len, aad, aad_len, ciphertext,
                   ciphertext_len, plaintext, tag, tag_len, 1);
}

#endif // #if defined(CCM) && (CCM == 1)

#if (defined(EAX) && (EAX == 1)) || \
    (defined(EAX_PRIME) && (EAX_PRIME == 1))

#if defined(EAX) && (EAX == 1)
static void eax_double(uint8_t value[AES_BLOCKLEN])
{
  uint8_t carry = 0;
  unsigned i;

  for (i = AES_BLOCKLEN; i > 0; --i)
  {
    const unsigned offset = i - 1u;
    const uint8_t next = (uint8_t)(value[offset] >> 7);
    value[offset] = (uint8_t)((value[offset] << 1) | carry);
    carry = next;
  }
  value[AES_BLOCKLEN - 1u] ^= (uint8_t)(0x87u & (uint8_t)(0u - carry));
}
#endif

#if defined(EAX_PRIME) && (EAX_PRIME == 1)
/* C12.22 defines EAX' field values in the reference implementation's
 * little-endian byte order, so its doubling shifts toward higher indexes and
 * applies the reduction constant to byte zero. */
static void eax_prime_double(uint8_t value[AES_BLOCKLEN])
{
  uint8_t carry = 0;
  unsigned i;

  for (i = 0; i < AES_BLOCKLEN; ++i)
  {
    const uint8_t next = (uint8_t)(value[i] >> 7);
    value[i] = (uint8_t)((value[i] << 1) | carry);
    carry = next;
  }
  value[0] ^= (uint8_t)(0x87u & (uint8_t)(0u - carry));
}
#endif

static void eax_mac_block(uint8_t mac[AES_BLOCKLEN],
                          const uint8_t block[AES_BLOCKLEN],
                          const uint8_t* round_key)
{
  unsigned i;

  for (i = 0; i < AES_BLOCKLEN; ++i)
    mac[i] ^= block[i];
  Cipher((state_t*)mac, round_key);
}

#if defined(EAX) && (EAX == 1)
static void eax_key_constants(const struct AES_ctx* aes,
                              uint8_t d[AES_BLOCKLEN],
                              uint8_t q[AES_BLOCKLEN])
{
  uint8_t l[AES_BLOCKLEN] = { 0 };
  Cipher((state_t*)l, aes->RoundKey);
  aes_copy_bytes(d, l, AES_BLOCKLEN);
  eax_double(d);
  aes_copy_bytes(q, d, AES_BLOCKLEN);
  eax_double(q);
}
#endif

#if defined(EAX_PRIME) && (EAX_PRIME == 1)
static void eax_prime_key_constants(const struct AES_ctx* aes,
                                    uint8_t d[AES_BLOCKLEN],
                                    uint8_t q[AES_BLOCKLEN])
{
  uint8_t l[AES_BLOCKLEN] = { 0 };
  Cipher((state_t*)l, aes->RoundKey);
  aes_copy_bytes(d, l, AES_BLOCKLEN);
  eax_prime_double(d);
  aes_copy_bytes(q, d, AES_BLOCKLEN);
  eax_prime_double(q);
}
#endif

/* CMAC with an optional EAX domain prefix. Passing domain < 0 implements the
 * C12.22 CMAC' form, whose CBC initial value is D or Q. */
static void eax_cmac(const struct AES_ctx* aes,
                     const uint8_t initial[AES_BLOCKLEN], int domain,
                     const uint8_t* data, size_t length,
                     const uint8_t complete_subkey[AES_BLOCKLEN],
                     const uint8_t partial_subkey[AES_BLOCKLEN],
                     uint8_t result[AES_BLOCKLEN])
{
  uint8_t mac[AES_BLOCKLEN];
  uint8_t block[AES_BLOCKLEN] = { 0 };
  size_t count;

  aes_copy_bytes(mac, initial, AES_BLOCKLEN);
  if (domain >= 0 && length == 0)
  {
    block[AES_BLOCKLEN - 1u] = (uint8_t)domain;
    for (count = 0; count < AES_BLOCKLEN; ++count)
      block[count] ^= complete_subkey[count];
  }
  else
  {
    if (domain >= 0)
    {
      block[AES_BLOCKLEN - 1u] = (uint8_t)domain;
      eax_mac_block(mac, block, aes->RoundKey);
      memset(block, 0, AES_BLOCKLEN);
    }

    while (length > AES_BLOCKLEN)
    {
      eax_mac_block(mac, data, aes->RoundKey);
      data += AES_BLOCKLEN;
      length -= AES_BLOCKLEN;
    }

    if (length == AES_BLOCKLEN)
    {
      aes_copy_bytes(block, data, AES_BLOCKLEN);
      for (count = 0; count < AES_BLOCKLEN; ++count)
        block[count] ^= complete_subkey[count];
    }
    else
    {
      aes_copy_bytes(block, data, length);
      block[length] = 0x80;
      for (count = 0; count < AES_BLOCKLEN; ++count)
        block[count] ^= partial_subkey[count];
    }
  }
  eax_mac_block(mac, block, aes->RoundKey);
  aes_copy_bytes(result, mac, AES_BLOCKLEN);
}

#if defined(EAX) && (EAX == 1)
static void eax_omac(const struct AES_ctx* aes, const uint8_t d[AES_BLOCKLEN],
                     const uint8_t q[AES_BLOCKLEN], uint8_t domain,
                     const uint8_t* data, size_t length,
                     uint8_t result[AES_BLOCKLEN])
{
  uint8_t initial[AES_BLOCKLEN] = { 0 };
  eax_cmac(aes, initial, domain, data, length, d, q, result);
}
#endif

static void eax_increment(uint8_t counter[AES_BLOCKLEN])
{
  unsigned i;

  for (i = AES_BLOCKLEN; i > 0; --i)
  {
    if (++counter[i - 1u] != 0)
      break;
  }
}

static void eax_ctr_xor(const struct AES_ctx* aes,
                        const uint8_t initial[AES_BLOCKLEN],
                        const uint8_t* input, uint8_t* output, size_t length,
                        int prime)
{
  uint8_t counter[AES_BLOCKLEN];
  uint8_t stream[AES_BLOCKLEN];
  size_t offset = 0;

  aes_copy_bytes(counter, initial, AES_BLOCKLEN);
  if (prime)
  {
    counter[1] &= 0x7f;
    counter[3] &= 0x7f;
  }
  while (offset < length)
  {
    const size_t count = length - offset < AES_BLOCKLEN ?
                         length - offset : AES_BLOCKLEN;
    aes_copy_bytes(stream, counter, AES_BLOCKLEN);
    Cipher((state_t*)stream, aes->RoundKey);
    for (size_t i = 0; i < count; ++i)
      output[offset + i] = (uint8_t)(input[offset + i] ^ stream[i]);
    eax_increment(counter);
    offset += count;
  }
}

#if defined(EAX) && (EAX == 1)

static int eax_crypt(const uint8_t* key, const uint8_t* nonce,
                     size_t nonce_len, const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, size_t input_len, uint8_t* output,
                     uint8_t* tag, size_t tag_len, int decrypt)
{
  struct AES_ctx aes;
  uint8_t nonce_mac[AES_BLOCKLEN];
  uint8_t header_mac[AES_BLOCKLEN];
  uint8_t message_mac[AES_BLOCKLEN];
  uint8_t full_tag[AES_BLOCKLEN];
  uint8_t d[AES_BLOCKLEN];
  uint8_t q[AES_BLOCKLEN];
  uint8_t difference = 0;
  int status = AES_ERR;
  size_t i;

  if (key == NULL || (nonce_len != 0 && nonce == NULL) ||
      (aad_len != 0 && aad == NULL) ||
      (input_len != 0 && (input == NULL || output == NULL)) ||
      (tag_len != 0 && tag == NULL) || tag_len > AES_BLOCKLEN)
    return AES_ERR;

  AES_init_ctx(&aes, key);
  eax_key_constants(&aes, d, q);
  eax_omac(&aes, d, q, 0, nonce, nonce_len, nonce_mac);
  eax_omac(&aes, d, q, 1, aad, aad_len, header_mac);

  if (decrypt)
  {
    eax_omac(&aes, d, q, 2, input, input_len, message_mac);
    for (i = 0; i < AES_BLOCKLEN; ++i)
      full_tag[i] = (uint8_t)(nonce_mac[i] ^ header_mac[i] ^ message_mac[i]);
    for (i = 0; i < tag_len; ++i)
      difference |= (uint8_t)(full_tag[i] ^ tag[i]);
    if (difference == 0)
    {
      eax_ctr_xor(&aes, nonce_mac, input, output, input_len, 0);
      status = AES_OK;
    }
  }
  else
  {
    eax_ctr_xor(&aes, nonce_mac, input, output, input_len, 0);
    eax_omac(&aes, d, q, 2, output, input_len, message_mac);
    for (i = 0; i < AES_BLOCKLEN; ++i)
      full_tag[i] = (uint8_t)(nonce_mac[i] ^ header_mac[i] ^ message_mac[i]);
    aes_copy_bytes(tag, full_tag, tag_len);
    status = AES_OK;
  }

#if AES_ZEROIZE
  AES_ctx_clear(&aes);
  AES_secure_zero(nonce_mac, sizeof(nonce_mac));
  AES_secure_zero(header_mac, sizeof(header_mac));
  AES_secure_zero(message_mac, sizeof(message_mac));
  AES_secure_zero(full_tag, sizeof(full_tag));
  AES_secure_zero(d, sizeof(d));
  AES_secure_zero(q, sizeof(q));
#endif
  return status;
}

int AES_EAX_encrypt(const uint8_t* key, const uint8_t* nonce,
                    size_t nonce_len, const uint8_t* aad, size_t aad_len,
                    const uint8_t* plaintext, size_t plaintext_len,
                    uint8_t* ciphertext, uint8_t* tag, size_t tag_len)
{
  return eax_crypt(key, nonce, nonce_len, aad, aad_len, plaintext,
                   plaintext_len, ciphertext, tag, tag_len, 0);
}

int AES_EAX_decrypt(const uint8_t* key, const uint8_t* nonce,
                    size_t nonce_len, const uint8_t* aad, size_t aad_len,
                    const uint8_t* ciphertext, size_t ciphertext_len,
                    const uint8_t* tag, size_t tag_len, uint8_t* plaintext)
{
  return eax_crypt(key, nonce, nonce_len, aad, aad_len, ciphertext,
                   ciphertext_len, plaintext, (uint8_t*)tag, tag_len, 1);
}

#endif /* EAX */

#if defined(EAX_PRIME) && (EAX_PRIME == 1)

static int eax_prime_crypt(const uint8_t* key, const uint8_t* cleartext,
                           size_t cleartext_len, const uint8_t* input,
                           size_t input_len, uint8_t* output,
                           const uint8_t* tag, int decrypt)
{
  struct AES_ctx aes;
  uint8_t d[AES_BLOCKLEN];
  uint8_t q[AES_BLOCKLEN];
  uint8_t nonce_mac[AES_BLOCKLEN];
  uint8_t message_mac[AES_BLOCKLEN];
  uint8_t full_tag[AES_BLOCKLEN];
  uint8_t difference = 0;
  size_t i;
  int status = AES_ERR;

  if (key == NULL || (cleartext_len != 0 && cleartext == NULL) ||
      (input_len != 0 && (input == NULL || output == NULL)) || tag == NULL)
    return AES_ERR;

  AES_init_ctx(&aes, key);
  eax_prime_key_constants(&aes, d, q);
  eax_cmac(&aes, d, -1, cleartext, cleartext_len, d, q, nonce_mac);

  if (decrypt)
  {
    eax_cmac(&aes, q, -1, input, input_len, d, q, message_mac);
    for (i = 0; i < AES_BLOCKLEN; ++i)
      full_tag[i] = (uint8_t)(nonce_mac[i] ^ message_mac[i]);
    for (i = 0; i < AES_EAX_PRIME_TAG_LEN; ++i)
      difference |= (uint8_t)(full_tag[AES_BLOCKLEN - 1u - i] ^ tag[i]);
    if (difference == 0)
    {
      eax_ctr_xor(&aes, nonce_mac, input, output, input_len, 1);
      status = AES_OK;
    }
  }
  else
  {
    eax_ctr_xor(&aes, nonce_mac, input, output, input_len, 1);
    eax_cmac(&aes, q, -1, output, input_len, d, q, message_mac);
    for (i = 0; i < AES_BLOCKLEN; ++i)
      full_tag[i] = (uint8_t)(nonce_mac[i] ^ message_mac[i]);
    for (i = 0; i < AES_EAX_PRIME_TAG_LEN; ++i)
      ((uint8_t*)tag)[i] = full_tag[AES_BLOCKLEN - 1u - i];
    status = AES_OK;
  }

#if AES_ZEROIZE
  AES_ctx_clear(&aes);
  AES_secure_zero(d, sizeof(d));
  AES_secure_zero(q, sizeof(q));
  AES_secure_zero(nonce_mac, sizeof(nonce_mac));
  AES_secure_zero(message_mac, sizeof(message_mac));
  AES_secure_zero(full_tag, sizeof(full_tag));
#endif
  return status;
}

int AES_EAX_PRIME_encrypt(const uint8_t* key, const uint8_t* cleartext,
                          size_t cleartext_len, const uint8_t* plaintext,
                          size_t plaintext_len, uint8_t* ciphertext,
                          uint8_t tag[AES_EAX_PRIME_TAG_LEN])
{
  return eax_prime_crypt(key, cleartext, cleartext_len, plaintext,
                         plaintext_len, ciphertext, tag, 0);
}

int AES_EAX_PRIME_decrypt(const uint8_t* key, const uint8_t* cleartext,
                          size_t cleartext_len, const uint8_t* ciphertext,
                          size_t ciphertext_len,
                          const uint8_t tag[AES_EAX_PRIME_TAG_LEN],
                          uint8_t* plaintext)
{
  return eax_prime_crypt(key, cleartext, cleartext_len, ciphertext,
                         ciphertext_len, plaintext, tag, 1);
}

#endif /* EAX_PRIME */

#endif // EAX or EAX_PRIME
