#include "common.h"

#define LDB_EVENT_OUTPUT "ldb.data"

extern ldb_shmseg *ldb_shared;
extern bool running;
static uint64_t nWakeup;

void *logger_main(void *arg) {
  FILE *ldb_fout = fopen(LDB_EVENT_OUTPUT, "wb");
  struct timespec now_;
  char cmd_buf[128];
  int len;
  ldb_event_handle_t *event = &ldb_shared->event;

  printf("logger thread starts\n");

  // store maps
  pid_t pid_self = syscall(SYS_getpid);
  sprintf(cmd_buf, "cat /proc/%d/maps > maps.data", pid_self);
  system(cmd_buf);
  clock_gettime(CLOCK_MONOTONIC, &now_);
  nWakeup = 0;

  pthread_mutex_lock(&event->m_event);
  event->last_write = now_.tv_sec;
  while (running) {
    while (running && event_len(event) < LDB_EVENT_THRESH &&
        now_.tv_sec - event->last_write < LDB_EVENT_MIN_INT) {
      pthread_cond_wait(&event->cv_event, &event->m_event);
      clock_gettime(CLOCK_MONOTONIC, &now_);
    }
    nWakeup++;

    len = event_len(event);

    if (event->head + len <= LDB_EVENT_BUF_SIZE) {
      fwrite(&event->events[event->head], sizeof(ldb_event_entry), len, ldb_fout);
    } else {
      fwrite(&event->events[event->head], sizeof(ldb_event_entry),
          LDB_EVENT_BUF_SIZE-event->head, ldb_fout);
      fwrite(&event->events[0], sizeof(ldb_event_entry),
          (event->head + len) % LDB_EVENT_BUF_SIZE, ldb_fout);
    }

    fflush(ldb_fout);
    system(cmd_buf);

    event->head = (event->head + len) % LDB_EVENT_BUF_SIZE;
    event->last_write = now_.tv_sec;
  } 
  pthread_mutex_unlock(&event->m_event);

  fclose(ldb_fout);

  printf("logger thread exiting... waken up %lu times\n", nWakeup);
  return NULL;
}
