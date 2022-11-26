#include "common.h"

extern ldb_shmseg *ldb_shared;

void event_record(ldb_event_buffer_t *ebuf, int event_type, struct timespec ts,
    uint32_t tid, uint64_t arg1, uint64_t arg2, uint64_t arg3) {

  if (unlikely(!ebuf || !ebuf->events))
    return;

  if ((ebuf->tail + 1) % LDB_EVENT_BUF_SIZE == ebuf->head) {
    //fprintf(stderr, "[%d] WARNING: event buffer full: event ignored\n", syscall(SYS_gettid));
    ebuf->nignored++;
    return;
  }

  ldb_event_entry *e = &ebuf->events[ebuf->tail];

  e->event_type = event_type;
  e->sec = ts.tv_sec;
  e->nsec = ts.tv_nsec;
  e->tid = tid;
  e->arg1 = arg1;
  e->arg2 = arg2;
  e->arg3 = arg3;

  ebuf->tail = (ebuf->tail + 1) % LDB_EVENT_BUF_SIZE;
}
