/* Safe regression probe for CVE-2026-69184.
 * Builds one bounded DNS response with a 200-hop backward compression chain.
 * It checks parser behavior without measuring or attempting CPU exhaustion. */
#include <ares.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void put16(uint8_t *data, size_t *length, size_t value) {
  data[(*length)++] = (uint8_t)((value >> 8) & 0xff);
  data[(*length)++] = (uint8_t)(value & 0xff);
}

static void put32zero(uint8_t *data, size_t *length) {
  data[(*length)++] = 0;
  data[(*length)++] = 0;
  data[(*length)++] = 0;
  data[(*length)++] = 0;
}

int main(void) {
  uint8_t packet[2048] = {0};
  const uint8_t valid_packet[] = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4
  };
  size_t length = 12;
  const size_t hops = 200;
  size_t rdata_offset;
  size_t previous;
  size_t chain_top;
  ares_dns_record_t *record = NULL;
  ares_status_t status;
  int valid_ok;

  packet[0] = 0x12;
  packet[1] = 0x34;
  packet[2] = 0x81;
  packet[3] = 0x80;
  packet[5] = 1;  /* one question */
  packet[7] = 2;  /* two answer records */

  packet[length++] = 1;
  packet[length++] = 'a';
  packet[length++] = 0;
  put16(packet, &length, 1);  /* QTYPE A */
  put16(packet, &length, 1);  /* QCLASS IN */

  packet[length++] = 0;       /* RR1 owner name: root */
  put16(packet, &length, 0xfffe); /* unknown type, raw RDATA */
  put16(packet, &length, 1);  /* class IN */
  put32zero(packet, &length); /* TTL */

  rdata_offset = length + 2;
  previous = rdata_offset;
  chain_top = previous;
  put16(packet, &length, 1 + 2 * hops);
  packet[length++] = 0;       /* deepest pointer target: root */
  for (size_t i = 0; i < hops; i++) {
    size_t current = rdata_offset + 1 + 2 * i;
    packet[length++] = (uint8_t)(0xc0 | ((previous >> 8) & 0x3f));
    packet[length++] = (uint8_t)(previous & 0xff);
    chain_top = current;
    previous = current;
  }

  packet[length++] = (uint8_t)(0xc0 | ((chain_top >> 8) & 0x3f));
  packet[length++] = (uint8_t)(chain_top & 0xff);
  put16(packet, &length, 1);  /* TYPE A */
  put16(packet, &length, 1);  /* CLASS IN */
  put32zero(packet, &length);
  put16(packet, &length, 4);
  packet[length++] = 1;
  packet[length++] = 2;
  packet[length++] = 3;
  packet[length++] = 4;

  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    fputs("init_failed\n", stderr);
    return 2;
  }
  status = ares_dns_parse(packet, length, 0, &record);
  printf("status=%d record=%s\n", status, record ? "present" : "null");
  ares_dns_record_destroy(record);
  record = NULL;
  status = ares_dns_parse(valid_packet, sizeof(valid_packet), 0, &record);
  printf("valid_status=%d valid_record=%s\n", status,
         record ? "present" : "null");
  valid_ok = status == ARES_SUCCESS && record != NULL;
  ares_dns_record_destroy(record);
  ares_library_cleanup();
  return valid_ok ? 0 : 1;
}
