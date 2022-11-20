#include "common.h"

void event_record(ldb_event_handle_t *event, int event_type, struct timespec ts,
    uint32_t tid, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
  int head_;
  int tail_;
  int next_tail_;
  int len;

  do {
    head_ = event->head;
    tail_ = event->tail;
    next_tail_ = (tail_ + 1) % LDB_EVENT_BUF_SIZE;

    // ignore the data point if queue is full
    if (next_tail_ == head_) {
      fprintf(stderr, "[WARNING] event buffer full: data point ignored\n");
      event->nignored++;
      return;
    }
  } while (!CAS(&event->tail, tail_, next_tail_));

  // I own tail_
  ldb_event_entry *e = &event->events[tail_];

  e->event_type = event_type;
  e->sec = ts.tv_sec;
  e->nsec = ts.tv_nsec;
  e->tid = tid;
  e->arg1 = arg1;
  e->arg2 = arg2;
  e->arg3 = arg3;

  // write complete. Let's commit
  while (!CAS(&event->commit, tail_, next_tail_)) {
    continue;
  }
}
