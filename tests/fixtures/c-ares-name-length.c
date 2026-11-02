/* SPDX-License-Identifier: MIT
 * Bounded regression for CVE-2026-69184 on the legacy c-ares 1.15 API.
 */
#include <sys/select.h>
#include <ares.h>
#include <stdio.h>
#include <string.h>

static size_t add_label(unsigned char *buffer, size_t offset, size_t length)
{
  buffer[offset++] = (unsigned char)length;
  memset(buffer + offset, 'a', length);
  return offset + length;
}

static int expand(const unsigned char *encoded, const unsigned char *message,
                  int message_length, const char *expected, long expected_length)
{
  char *name = NULL;
  long encoded_length = 0;
  int status = ares_expand_name(encoded, message, message_length, &name,
                                &encoded_length);
  int passed = status == ARES_SUCCESS && name != NULL &&
               strlen(name) == strlen(expected) &&
               strcmp(name, expected) == 0 && encoded_length == expected_length;
  if (name != NULL)
    ares_free_string(name);
  return passed;
}

int main(void)
{
  unsigned char message[300] = {0};
  size_t offset = 0;
  size_t overlong_offset;
  char maximum_name[256];
  size_t i;
  char *expanded = NULL;
  long encoded_length = 0;
  int status;

  /* A 192-octet target name, then a 63-octet label and pointer to it.
   * The resulting wire name exceeds RFC 1035's 255-octet limit. */
  offset = add_label(message, offset, 63);
  offset = add_label(message, offset, 63);
  offset = add_label(message, offset, 63);
  message[offset++] = 0;
  overlong_offset = offset;
  offset = add_label(message, offset, 63);
  message[offset++] = (unsigned char)(0xc0 | ((0 >> 8) & 0x3f));
  message[offset++] = 0;

  status = ares_expand_name(message + overlong_offset, message, (int)offset,
                            &expanded, &encoded_length);
  if (expanded != NULL)
    ares_free_string(expanded);
  if (status != ARES_SUCCESS && status != ARES_EBADNAME)
    return 2;
  printf("overlong_status=%d rejected=%s\n", status,
         status == ARES_EBADNAME ? "yes" : "no");

  /* RFC-valid maximum: 63 + 63 + 63 + 61 label bytes, four length
   * octets, and a root terminator = 255 wire octets. */
  memset(message, 0, sizeof(message));
  offset = 0;
  offset = add_label(message, offset, 63);
  offset = add_label(message, offset, 63);
  offset = add_label(message, offset, 63);
  offset = add_label(message, offset, 61);
  message[offset++] = 0;
  for (i = 0; i < 63; i++) maximum_name[i] = 'a';
  maximum_name[63] = '.';
  for (i = 64; i < 127; i++) maximum_name[i] = 'a';
  maximum_name[127] = '.';
  for (i = 128; i < 191; i++) maximum_name[i] = 'a';
  maximum_name[191] = '.';
  for (i = 192; i < 253; i++) maximum_name[i] = 'a';
  maximum_name[253] = '\0';

  if (!expand(message, message, (int)offset, maximum_name, (long)offset))
    return 1;
  puts("maximum_name_accepted=yes");
  return 0;
}
