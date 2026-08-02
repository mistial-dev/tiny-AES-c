/*
 * SPDX-License-Identifier: Unlicense
 * SPDX-FileCopyrightText: kokke
 * SPDX-FileCopyrightText: Mistial Dev
 *
 * EAX RFC and Wycheproof tests. This translation unit is test-only.
 */

#include "aes.h"
#include "munit.h"

#include <stdio.h>
#include <string.h>

#ifndef EAX_VECTOR_FILE
#define EAX_VECTOR_FILE "test_vectors/eax/aes_eax_test.json"
#endif

#if defined(EAX) && (EAX == 1)

#if !defined(AES192) && !defined(AES256)
struct eax_rfc_vector
{
  const char* key;
  const char* nonce;
  const char* aad;
  const char* msg;
  const char* cipher_and_tag;
};

static const struct eax_rfc_vector eax_rfc_vectors[] = {
  { "233952DEE4D5ED5F9B9C6D6FF80FF478",
    "62EC67F9C3A4A407FCB2A8C49031A8B3", "6BFB914FD07EAE6B", "",
    "E037830E8389F27B025A2D6527E79D01" },
  { "91945D3F4DCBEE0BF45EF52255F095A4",
    "BECAF043B0A23D843194BA972C66DEBD", "FA3BFD4806EB53FA", "F7FB",
    "19DD5C4C9331049D0BDAB0277408F67967E5" },
  { "01F74AD64077F2E704C0F60ADA3DD523",
    "70C3DB4F0D26368400A10ED05D2BFF5E", "234A3463C1264AC6", "1A47CB4933",
    "D851D5BAE03A59F238A23E39199DC9266626C40F80" },
  { "D07CF6CBB7F313BDDE66B727AFD3C5E8",
    "8408DFFF3C1A2B1292DC199E46B7D617", "33CCE2EABFF5A79D", "481C9E39B1",
    "632A9D131AD4C168A4225D8E1FF755939974A7BEDE" },
  { "35B6D0580005BBC12B0587124557D2C2",
    "FDB6B06676EEDC5C61D74276E1F8E816", "AEB96EAEBE2970E9", "40D0C07DA5E4",
    "071DFE16C675CB0677E536F73AFE6A14B74EE49844DD" },
  { "BD8E6E11475E60B268784C38C62FEB22",
    "6EAC5C93072D8E8513F750935E46DA1B", "D4482D1CA78DCE0F",
    "4DE3B35C3FC039245BD1FB7D",
    "835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F" },
  { "7C77D6E813BED5AC98BAA417477A2E7D",
    "1A8C98DCD73D38393B2BF1569DEEFC19", "65D2017990D62528",
    "8B0A79306C9CE7ED99DAE4F87F8DD61636",
    "02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2" },
  { "5FFF20CAFAB119CA2FC73549E20F5B0D",
    "DDE59B97D722156D4D9AFF2BC7559826", "54B9F04E6A09189A",
    "1BDA122BCE8A8DBAF1877D962B8592DD2D56",
    "2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A" },
  { "A4A4782BCFFD3EC5E7EF6D8C34A56123",
    "B781FCF2F75FA5A8DE97A9CA48E522EC", "899A175897561D7E",
    "6CF36720872B8513F6EAB1A8A44438D5EF11",
    "0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700" },
  { "8395FCF1E95BEBD697BD010BC766AAC3",
    "22E7ADD93CFC6393C57EC0B3C17D6B44", "126735FCC320D25A",
    "CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7",
    "CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E" }
};
#endif

static int eax_hex_value(int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static size_t eax_decode_hex(const char* text, uint8_t* output,
                             size_t capacity)
{
  size_t length = 0;
  while (*text != '\0')
  {
    const int high = eax_hex_value((unsigned char)*text++);
    int low;
    if (high < 0) continue;
    low = eax_hex_value((unsigned char)*text++);
    if (low < 0 || length == capacity) return SIZE_MAX;
    output[length++] = (uint8_t)((high << 4) | low);
  }
  return length;
}

#if !defined(AES192) && !defined(AES256)
static int eax_decode_vector(const struct eax_rfc_vector* vector,
                             uint8_t* key, uint8_t* nonce, uint8_t* aad,
                             uint8_t* msg, uint8_t* cipher, uint8_t* tag,
                             size_t* key_len, size_t* nonce_len,
                             size_t* aad_len, size_t* msg_len,
                             size_t* cipher_len, size_t* tag_len)
{
  *key_len = eax_decode_hex(vector->key, key, 32);
  *nonce_len = eax_decode_hex(vector->nonce, nonce, 2048);
  *aad_len = eax_decode_hex(vector->aad, aad, 2048);
  *msg_len = eax_decode_hex(vector->msg, msg, 2048);
  *cipher_len = eax_decode_hex(vector->cipher_and_tag, cipher, 2048);
  if (*key_len == SIZE_MAX || *nonce_len == SIZE_MAX || *aad_len == SIZE_MAX ||
      *msg_len == SIZE_MAX || *cipher_len == SIZE_MAX || *cipher_len < 16)
    return 0;
  *tag_len = 16;
  memcpy(tag, cipher + *cipher_len - *tag_len, *tag_len);
  *cipher_len -= *tag_len;
  return 1;
}
#endif

static MunitResult test_eax_rfc(const MunitParameter params[], void* data)
{
  size_t i;

  (void) params;
  (void) data;
#if AES_SBOX_MODE == AES_SBOX_MODE_RUNTIME
  AES_init_sbox();
#endif
#if !defined(AES192) && !defined(AES256)
  for (i = 0; i < sizeof(eax_rfc_vectors) / sizeof(eax_rfc_vectors[0]); ++i)
  {
    uint8_t key[32], nonce[2048], aad[2048], msg[2048];
    uint8_t expected[2048], tag[16], generated[16], output[2048];
    size_t key_len, nonce_len, aad_len, msg_len, cipher_len, tag_len;

    munit_assert_true(eax_decode_vector(&eax_rfc_vectors[i], key, nonce, aad,
                                        msg, expected, tag, &key_len,
                                        &nonce_len, &aad_len, &msg_len,
                                        &cipher_len, &tag_len));
    munit_assert_int(AES_EAX_encrypt(key, nonce, nonce_len, aad, aad_len, msg,
                                     msg_len, output, generated, tag_len), ==,
                     AES_EAX_SUCCESS);
    munit_assert_memory_equal(cipher_len, output, expected);
    munit_assert_memory_equal(tag_len, generated, tag);
    munit_assert_int(AES_EAX_decrypt(key, nonce, nonce_len, aad, aad_len,
                                     expected, cipher_len, tag, tag_len,
                                     output), ==, AES_EAX_SUCCESS);
    munit_assert_memory_equal(msg_len, output, msg);
  }
#else
  (void)i;
#endif
  return MUNIT_OK;
}

static int eax_json_field(const char* line, const char* name, char* output,
                          size_t capacity)
{
  char marker[32];
  const char* start;
  const char* end;
  size_t length;

  (void) snprintf(marker, sizeof(marker), "\"%s\"", name);
  start = strstr(line, marker);
  if (start == NULL) return 0;
  start = strchr(start + strlen(marker), ':');
  if (start == NULL || (start = strchr(start + 1, '"')) == NULL) return 0;
  end = strchr(start + 1, '"');
  if (end == NULL) return 0;
  length = (size_t)(end - start - 1);
  if (length >= capacity) return 0;
  memcpy(output, start + 1, length);
  output[length] = '\0';
  return 1;
}

static MunitResult test_eax_wycheproof(const MunitParameter params[], void* data)
{
  FILE* file;
  char line[4096];
  char key_text[4096] = { 0 }, iv_text[4096] = { 0 };
  char aad_text[4096] = { 0 }, msg_text[4096] = { 0 };
  char ct_text[4096] = { 0 }, tag_text[4096] = { 0 };
  char result[32] = { 0 };
  unsigned tc_id = 0;
  size_t vector_count = 0;

  (void) params;
  (void) data;
  file = fopen(EAX_VECTOR_FILE, "rb");
  munit_assert_not_null(file);
  while (fgets(line, sizeof(line), file) != NULL)
  {
    unsigned parsed_id;
    if (sscanf(line, " %*[^0-9]%u", &parsed_id) == 1 &&
        strstr(line, "\"tcId\"") != NULL)
    {
      tc_id = parsed_id;
      key_text[0] = iv_text[0] = aad_text[0] = msg_text[0] = '\0';
      ct_text[0] = tag_text[0] = result[0] = '\0';
    }
    (void) eax_json_field(line, "key", key_text, sizeof(key_text));
    (void) eax_json_field(line, "iv", iv_text, sizeof(iv_text));
    (void) eax_json_field(line, "aad", aad_text, sizeof(aad_text));
    (void) eax_json_field(line, "msg", msg_text, sizeof(msg_text));
    (void) eax_json_field(line, "ct", ct_text, sizeof(ct_text));
    (void) eax_json_field(line, "tag", tag_text, sizeof(tag_text));
    if (eax_json_field(line, "result", result, sizeof(result)))
    {
      uint8_t key[32], iv[2048], aad[2048], msg[2048], ct[2048], tag[32];
      uint8_t output[2048], generated[32];
      const size_t key_len = eax_decode_hex(key_text, key, sizeof(key));
      const size_t iv_len = eax_decode_hex(iv_text, iv, sizeof(iv));
      const size_t aad_len = eax_decode_hex(aad_text, aad, sizeof(aad));
      const size_t msg_len = eax_decode_hex(msg_text, msg, sizeof(msg));
      const size_t ct_len = eax_decode_hex(ct_text, ct, sizeof(ct));
      const size_t tag_len = eax_decode_hex(tag_text, tag, sizeof(tag));

      munit_assert_uint(tc_id, >, 0);
      ++vector_count;
      if (key_len != AES_KEYLEN)
        continue;
      munit_assert_size(iv_len, !=, SIZE_MAX);
      munit_assert_size(aad_len, !=, SIZE_MAX);
      munit_assert_size(msg_len, !=, SIZE_MAX);
      munit_assert_size(ct_len, !=, SIZE_MAX);
      munit_assert_size(tag_len, ==, 16);
      if (strcmp(result, "valid") == 0)
      {
        munit_assert_int(AES_EAX_encrypt(key, iv, iv_len, aad, aad_len, msg,
                                         msg_len, output, generated, tag_len),
                         ==, AES_EAX_SUCCESS);
        munit_assert_memory_equal(ct_len, output, ct);
        munit_assert_memory_equal(tag_len, generated, tag);
      }
      memset(output, 0xa5, sizeof(output));
      munit_assert_int(AES_EAX_decrypt(key, iv, iv_len, aad, aad_len, ct,
                                       ct_len, tag, tag_len, output), ==,
                       strcmp(result, "valid") == 0 ? AES_EAX_SUCCESS :
                                                       AES_EAX_ERROR);
      if (strcmp(result, "valid") == 0)
        munit_assert_memory_equal(msg_len, output, msg);
    }
  }
  fclose(file);
  munit_assert_size(vector_count, ==, 240);
  return MUNIT_OK;
}

static MunitResult test_eax_api(const MunitParameter params[], void* data)
{
  static const uint8_t key[16] = {
    0x23, 0x39, 0x52, 0xde, 0xe4, 0xd5, 0xed, 0x5f,
    0x9b, 0x9c, 0x6d, 0x6f, 0xf8, 0x0f, 0xf4, 0x78
  };
  static const uint8_t nonce[16] = {
    0x62, 0xec, 0x67, 0xf9, 0xc3, 0xa4, 0xa4, 0x07,
    0xfc, 0xb2, 0xa8, 0xc4, 0x90, 0x31, 0xa8, 0xb3
  };
  static const uint8_t aad[8] = {
    0x6b, 0xfb, 0x91, 0x4f, 0xd0, 0x7e, 0xae, 0x6b
  };
  uint8_t message[32] = { 0 };
  uint8_t ciphertext[32] = { 0 };
  uint8_t tag[16] = { 0 };
  uint8_t bad[32];
  uint8_t bad_tag[16];
  uint8_t empty_tag[1];
  uint8_t untouched[32];

  (void) params;
  (void) data;
  munit_assert_int(AES_EAX_encrypt(key, nonce, sizeof(nonce), aad,
                                   sizeof(aad), message, sizeof(message),
                                   ciphertext, tag, sizeof(tag)), ==,
                   AES_EAX_SUCCESS);

  memcpy(bad, message, sizeof(message));
  munit_assert_int(AES_EAX_encrypt(key, nonce, sizeof(nonce), aad,
                                   sizeof(aad), bad, sizeof(bad), bad, tag,
                                   sizeof(tag)), ==, AES_EAX_SUCCESS);
  munit_assert_memory_equal(sizeof(ciphertext), bad, ciphertext);

  memcpy(bad, ciphertext, sizeof(ciphertext));
  munit_assert_int(AES_EAX_decrypt(key, nonce, sizeof(nonce), aad,
                                   sizeof(aad), bad, sizeof(bad), tag,
                                   sizeof(tag), bad), ==, AES_EAX_SUCCESS);
  munit_assert_memory_equal(sizeof(message), bad, message);

  memcpy(bad_tag, tag, sizeof(bad_tag));
  bad_tag[0] ^= 1;
  memset(bad, 0xa5, sizeof(bad));
  memset(untouched, 0xa5, sizeof(untouched));
  munit_assert_int(AES_EAX_decrypt(key, nonce, sizeof(nonce), aad,
                                   sizeof(aad), ciphertext, sizeof(ciphertext),
                   bad_tag, sizeof(bad_tag), bad), ==,
                   AES_EAX_ERROR);
  munit_assert_memory_equal(sizeof(bad), bad, untouched);

  bad[0] = ciphertext[0] ^ 1;
  memcpy(bad + 1, ciphertext + 1, sizeof(ciphertext) - 1);
  munit_assert_int(AES_EAX_decrypt(key, nonce, sizeof(nonce), aad,
                                   sizeof(aad), bad, sizeof(bad), tag,
                                   sizeof(tag), NULL), ==, AES_EAX_ERROR);
  munit_assert_int(AES_EAX_decrypt(key, nonce, sizeof(nonce), aad,
                                   sizeof(aad), ciphertext, sizeof(ciphertext),
                                   tag, sizeof(tag), NULL), ==, AES_EAX_ERROR);

  bad[0] = aad[0] ^ 1;
  munit_assert_int(AES_EAX_decrypt(key, nonce, sizeof(nonce), bad,
                                   sizeof(aad), ciphertext, sizeof(ciphertext),
                                   tag, sizeof(tag), bad), ==, AES_EAX_ERROR);
  bad[0] = nonce[0] ^ 1;
  munit_assert_int(AES_EAX_decrypt(key, bad, sizeof(nonce), aad, sizeof(aad),
                                   ciphertext, sizeof(ciphertext), tag,
                                   sizeof(tag), bad), ==, AES_EAX_ERROR);

  munit_assert_int(AES_EAX_encrypt(key, NULL, 0, NULL, 0, NULL, 0, NULL,
                                   NULL, 0), ==, AES_EAX_SUCCESS);
  munit_assert_int(AES_EAX_decrypt(key, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                                   NULL), ==, AES_EAX_SUCCESS);
  munit_assert_int(AES_EAX_encrypt(key, nonce, sizeof(nonce), aad, sizeof(aad),
                                   message, sizeof(message), ciphertext, tag,
                                   sizeof(tag) + 1), ==, AES_EAX_ERROR);
  munit_assert_int(AES_EAX_encrypt(NULL, nonce, sizeof(nonce), aad, sizeof(aad),
                                   message, sizeof(message), ciphertext, tag,
                                   sizeof(tag)), ==, AES_EAX_ERROR);
  munit_assert_int(AES_EAX_encrypt(key, NULL, 1, aad, sizeof(aad), message,
                                   sizeof(message), ciphertext, tag,
                                   sizeof(tag)), ==, AES_EAX_ERROR);
  munit_assert_int(AES_EAX_encrypt(key, nonce, sizeof(nonce), NULL, 1, message,
                                   sizeof(message), ciphertext, tag,
                                   sizeof(tag)), ==, AES_EAX_ERROR);
  munit_assert_int(AES_EAX_encrypt(key, nonce, sizeof(nonce), aad, sizeof(aad),
                                   message, sizeof(message), ciphertext, NULL,
                                   sizeof(tag)), ==, AES_EAX_ERROR);
  munit_assert_int(AES_EAX_encrypt(key, nonce, sizeof(nonce), aad, sizeof(aad),
                                   message, sizeof(message), ciphertext,
                                   empty_tag, 0), ==, AES_EAX_SUCCESS);
  return MUNIT_OK;
}

MunitResult test_eax(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;
  return test_eax_rfc(params, data) == MUNIT_OK &&
                 test_eax_wycheproof(params, data) == MUNIT_OK &&
                 test_eax_api(params, data) == MUNIT_OK ?
             MUNIT_OK : MUNIT_FAIL;
}

#endif
