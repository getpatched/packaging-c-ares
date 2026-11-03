/* CVE-2026-69186 regression probe. The 12-byte response advertises the
 * maximum record count in each section without carrying any records. */
#include <ares.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
  static const uint8_t malformed[] = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
  };
  static const uint8_t valid[] = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 'a', 0x00,
    0x00, 0x01, 0x00, 0x01,
  };
  ares_dns_record_t *record = NULL;
  ares_status_t status;
  int malformed_rejected;
  int valid_accepted;

  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    fputs("init_failed\n", stderr);
    return 2;
  }

  status = ares_dns_parse(malformed, sizeof(malformed), 0, &record);
  malformed_rejected = status == ARES_EBADRESP && record == NULL;
  printf("malformed_rejected=%s\n", malformed_rejected ? "yes" : "no");
  ares_dns_record_destroy(record);
  record = NULL;

  status = ares_dns_parse(valid, sizeof(valid), 0, &record);
  valid_accepted = status == ARES_SUCCESS && record != NULL;
  printf("valid_status=%d valid_record=%s\n", status,
         record ? "present" : "null");
  ares_dns_record_destroy(record);
  ares_library_cleanup();

  return malformed_rejected && valid_accepted ? 0 : 1;
}
