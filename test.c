/*
 * SPDX-License-Identifier: Unlicense
 *
 * Unit tests for tiny-AES-c using munit: https://nemequ.github.io/munit/
 */

#include <string.h>

#include "aes.h"
#include "munit.h"
#include "test_vectors.h"

#if defined(AES256) && (AES256 == 1)
#define TEST_KEY aes256_key
#define TEST_ECB_CIPHERTEXT aes256_ecb_ciphertext
#define TEST_CBC_CIPHERTEXT aes256_cbc_ciphertext
#define TEST_CTR_CIPHERTEXT aes256_ctr_ciphertext
#elif defined(AES192) && (AES192 == 1)
#define TEST_KEY aes192_key
#define TEST_ECB_CIPHERTEXT aes192_ecb_ciphertext
#define TEST_CBC_CIPHERTEXT aes192_cbc_ciphertext
#define TEST_CTR_CIPHERTEXT aes192_ctr_ciphertext
#else
#define TEST_KEY aes128_key
#define TEST_ECB_CIPHERTEXT aes128_ecb_ciphertext
#define TEST_CBC_CIPHERTEXT aes128_cbc_ciphertext
#define TEST_CTR_CIPHERTEXT aes128_ctr_ciphertext
#endif

#if AES_SBOX_MODE == AES_SBOX_MODE_RUNTIME
static void test_initialize_sbox(void)
{
  AES_init_sbox();
}
#else
static void test_initialize_sbox(void)
{
}
#endif

#if defined(ECB) && (ECB == 1)
static MunitResult test_ecb(const MunitParameter params[], void* data)
{
  struct AES_ctx ctx;
  uint8_t buffer[AES_BLOCKLEN];

  (void) params;
  (void) data;

  test_initialize_sbox();
  AES_init_ctx(&ctx, TEST_KEY);
  memcpy(buffer, nist_plaintext, AES_BLOCKLEN);
  AES_ECB_encrypt(&ctx, buffer);
  munit_assert_memory_equal(AES_BLOCKLEN, buffer, TEST_ECB_CIPHERTEXT);

  AES_ECB_decrypt(&ctx, buffer);
  munit_assert_memory_equal(AES_BLOCKLEN, buffer, nist_plaintext);

  return MUNIT_OK;
}
#endif

#if defined(CBC) && (CBC == 1)
static MunitResult test_cbc(const MunitParameter params[], void* data)
{
  struct AES_ctx ctx;
  uint8_t buffer[sizeof(nist_plaintext)];

  (void) params;
  (void) data;

  test_initialize_sbox();
  AES_init_ctx_iv(&ctx, TEST_KEY, nist_iv);
  memcpy(buffer, nist_plaintext, sizeof(buffer));
  AES_CBC_encrypt_buffer(&ctx, buffer, sizeof(buffer));
  munit_assert_memory_equal(sizeof(buffer), buffer, TEST_CBC_CIPHERTEXT);

  AES_ctx_set_iv(&ctx, nist_iv);
  AES_CBC_decrypt_buffer(&ctx, buffer, sizeof(buffer));
  munit_assert_memory_equal(sizeof(buffer), buffer, nist_plaintext);

  return MUNIT_OK;
}
#endif

#if defined(CTR) && (CTR == 1)
static MunitResult test_ctr(const MunitParameter params[], void* data)
{
  struct AES_ctx ctx;
  uint8_t buffer[sizeof(nist_plaintext)];

  (void) params;
  (void) data;

  test_initialize_sbox();
  AES_init_ctx_iv(&ctx, TEST_KEY, nist_ctr_iv);
  memcpy(buffer, nist_plaintext, sizeof(buffer));
  AES_CTR_xcrypt_buffer(&ctx, buffer, sizeof(buffer));
  munit_assert_memory_equal(sizeof(buffer), buffer, TEST_CTR_CIPHERTEXT);

  AES_ctx_set_iv(&ctx, nist_ctr_iv);
  AES_CTR_xcrypt_buffer(&ctx, buffer, sizeof(buffer));
  munit_assert_memory_equal(sizeof(buffer), buffer, nist_plaintext);

  return MUNIT_OK;
}
#endif

static MunitTest test_suite_tests[] = {
#if defined(ECB) && (ECB == 1)
  { "/ecb", test_ecb, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if defined(CBC) && (CBC == 1)
  { "/cbc", test_cbc, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if defined(CTR) && (CTR == 1)
  { "/ctr", test_ctr, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static const MunitSuite test_suite = {
  "/tiny-aes-c",
  test_suite_tests,
  NULL,
  1,
  MUNIT_SUITE_OPTION_NONE
};

int main(int argc, char* argv[])
{
  return munit_suite_main(&test_suite, NULL, argc, argv);
}
