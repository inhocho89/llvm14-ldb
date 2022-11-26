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

inline void event_record_now(int event_type, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
  // attach shared memory
  if (unlikely(!ldb_shared)) {
    ldb_shared = attach_shared_memory();
  }

  struct timespec now;
  int tinfo_idx = get_thread_info_idx();
  ldb_thread_info_t *tinfo = &ldb_shared->ldb_thread_infos[tinfo_idx];

  clock_gettime(CLOCK_MONOTONIC, &now);

  event_record(tinfo->ebuf, event_type, now, tinfo->id, arg1, arg2, arg3);
}
