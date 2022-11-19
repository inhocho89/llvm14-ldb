#include "common.h"
#include "ldb/tag.h"

extern ldb_shmseg *ldb_shared;

void ldb_tag_add(uint64_t tag) {
  struct timespec now;
  pid_t thread_id = syscall(SYS_gettid);
  clock_gettime(CLOCK_MONOTONIC, &now);
  event_record(&ldb_shared->event, LDB_EVENT_TAG, now, thread_id, tag, 0, 0);
}

void ldb_tag_clear() {
  ldb_tag_add(0);
}
