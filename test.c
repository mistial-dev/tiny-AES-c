/*
 * SPDX-License-Identifier: Unlicense
 * SPDX-FileCopyrightText: kokke
 * SPDX-FileCopyrightText: Mistial Dev
 *
 * Unit tests for tiny-AES-c using munit: https://nemequ.github.io/munit/
 */

#include <string.h>

#include "aes.h"
#include "munit.h"
#include "test_vectors.h"
#if defined(GCM) && (GCM == 1)
#include "gcm_test_vectors.h"
#endif

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

#if defined(GCM) && (GCM == 1)
#if defined(AES256) && (AES256 == 1)
#define TEST_GCM_VECTOR gcm_test_vectors[2]
#elif defined(AES192) && (AES192 == 1)
#define TEST_GCM_VECTOR gcm_test_vectors[1]
#else
#define TEST_GCM_VECTOR gcm_test_vectors[0]
#endif
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

#if defined(GCM) && (GCM == 1)
static MunitResult test_gcm(const MunitParameter params[], void* data)
{
  const struct gcm_test_vector* vector = &TEST_GCM_VECTOR;
  struct AES_GCM_ctx ctx;
  uint8_t buffer[16];
  uint8_t tag[16];
  uint8_t short_tag[4];
  uint8_t bad_tag[16];

  (void) params;
  (void) data;

  test_initialize_sbox();
  memcpy(buffer, vector->plaintext, vector->length);
  munit_assert_int(AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_aad_update(&ctx, vector->aad, 5), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_aad_update(&ctx, vector->aad + 5, vector->aad_len - 5), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_encrypt_update(&ctx, buffer, 3), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_encrypt_update(&ctx, buffer + 3, vector->length - 3), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_encrypt_finish(&ctx, tag, vector->tag_len), ==, AES_GCM_SUCCESS);
  munit_assert_memory_equal(vector->length, buffer, vector->ciphertext);
  munit_assert_memory_equal(vector->tag_len, tag, vector->tag);

  munit_assert_int(AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_aad_update(&ctx, vector->aad, vector->aad_len), ==, AES_GCM_SUCCESS);
  memcpy(buffer, vector->plaintext, vector->length);
  munit_assert_int(AES_GCM_encrypt_update(&ctx, buffer, vector->length), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_encrypt_finish(&ctx, short_tag, sizeof(short_tag)), ==, AES_GCM_SUCCESS);
  munit_assert_memory_equal(sizeof(short_tag), short_tag, vector->tag);

  munit_assert_int(AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_aad_update(&ctx, vector->aad, vector->aad_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_decrypt_update(&ctx, buffer, vector->length), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_decrypt_finish(&ctx, tag, vector->tag_len), ==, AES_GCM_SUCCESS);
  munit_assert_memory_equal(vector->length, buffer, vector->plaintext);

  memcpy(buffer, vector->ciphertext, vector->length);
  memcpy(bad_tag, tag, sizeof(bad_tag));
  bad_tag[0] ^= 1;
  munit_assert_int(AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_aad_update(&ctx, vector->aad, vector->aad_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_decrypt_update(&ctx, buffer, vector->length), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_decrypt_finish(&ctx, bad_tag, vector->tag_len), ==, AES_GCM_ERROR);
  munit_assert_int(AES_GCM_aad_update(&ctx, vector->aad, 1), ==, AES_GCM_ERROR);

  return MUNIT_OK;
}

static MunitResult test_gcm_direction(const MunitParameter params[], void* data)
{
  const struct gcm_test_vector* vector = &TEST_GCM_VECTOR;
  struct AES_GCM_ctx ctx;
  uint8_t buffer[16];
  uint8_t before[16];

  (void) params;
  (void) data;

  test_initialize_sbox();
  memcpy(buffer, vector->plaintext, vector->length);
  munit_assert_int(AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_encrypt_update(&ctx, buffer, 1), ==, AES_GCM_SUCCESS);
  memcpy(before, buffer, sizeof(before));
  munit_assert_int(AES_GCM_decrypt_update(&ctx, buffer, 1), ==, AES_GCM_ERROR);
  munit_assert_memory_equal(sizeof(before), buffer, before);

  memcpy(buffer, vector->ciphertext, vector->length);
  munit_assert_int(AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_decrypt_update(&ctx, buffer, 1), ==, AES_GCM_SUCCESS);
  memcpy(before, buffer, sizeof(before));
  munit_assert_int(AES_GCM_encrypt_update(&ctx, buffer, 1), ==, AES_GCM_ERROR);
  munit_assert_memory_equal(sizeof(before), buffer, before);

  memcpy(buffer, vector->ciphertext, vector->length);
  munit_assert_int(AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_aad_update(&ctx, vector->aad, vector->aad_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_decrypt_update(&ctx, buffer, vector->length), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_decrypt_finish(&ctx, (const uint8_t*)vector->tag,
                                          vector->tag_len), ==, AES_GCM_SUCCESS);
  munit_assert_memory_equal(vector->length, buffer, vector->plaintext);

  return MUNIT_OK;
}

#if !defined(AES192) && !defined(AES256)
static MunitResult test_gcm_non96_iv(const MunitParameter params[], void* data)
{
  const struct gcm_test_vector* vector = &gcm_non96_test_vector;
  struct AES_GCM_ctx ctx;
  uint8_t buffer[16];
  uint8_t tag[16];

  (void) params;
  (void) data;

  test_initialize_sbox();
  memcpy(buffer, vector->plaintext, vector->length);
  munit_assert_int(AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_aad_update(&ctx, vector->aad, vector->aad_len), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_encrypt_update(&ctx, buffer, vector->length), ==, AES_GCM_SUCCESS);
  munit_assert_int(AES_GCM_encrypt_finish(&ctx, tag, vector->tag_len), ==, AES_GCM_SUCCESS);
  munit_assert_memory_equal(vector->length, buffer, vector->ciphertext);
  munit_assert_memory_equal(vector->tag_len, tag, vector->tag);

  return MUNIT_OK;
}
#endif
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
#if defined(GCM) && (GCM == 1)
  { "/gcm", test_gcm, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/gcm-direction", test_gcm_direction, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#if !defined(AES192) && !defined(AES256)
  { "/gcm-non96-iv", test_gcm_non96_iv, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
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
