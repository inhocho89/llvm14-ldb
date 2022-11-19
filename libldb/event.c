#include "common.h"

void event_record(ldb_event_handle_t *event, int event_type, struct timespec ts,
    uint32_t tid, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
  pthread_mutex_lock(&event->m_event);
  // now this becomes very unlikely
  if ((event->tail + 1) % LDB_EVENT_BUF_SIZE == event->head) {
    event->nignored++;
    pthread_cond_broadcast(&event->cv_event);
    pthread_mutex_unlock(&event->m_event);
    return;
  }

  ldb_event_entry *entry = &event->events[event->tail];
	
  entry->event_type = event_type;
  entry->sec = ts.tv_sec;
  entry->nsec = ts.tv_nsec;
  entry->tid = tid;
  entry->arg1 = arg1;
  entry->arg2 = arg2;
  entry->arg3 = arg3;

  event->tail = (event->tail + 1) % LDB_EVENT_BUF_SIZE;
  if (event_len(event) >= LDB_EVENT_THRESH ||
      ts.tv_sec - event->last_write >= LDB_EVENT_MIN_INT) {
    pthread_cond_broadcast(&event->cv_event);
  }
  pthread_mutex_unlock(&event->m_event);
}
