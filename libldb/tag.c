#include "common.h"
#include "ldb/tag.h"

void ldb_tag_set(uint64_t tag) {
  event_record_now(LDB_EVENT_TAG_SET, tag, 0, 0);
}

void ldb_tag_clear() {
  ldb_tag_set(0);
}

void ldb_tag_block(uint64_t tag) {
  event_record_now(LDB_EVENT_TAG_BLOCK, tag, 0, 0);
}
