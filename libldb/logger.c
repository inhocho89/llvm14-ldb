#include "common.h"

#define LDB_EVENT_OUTPUT "ldb.data"

extern ldb_shmseg *ldb_shared;
extern bool running;

void *logger_main(void *arg) {
  FILE *ldb_fout = fopen(LDB_EVENT_OUTPUT, "wb");
  char cmd_map_buf[128];
  int head_;
  int commit_;
  int len;
  ldb_event_handle_t *event = &ldb_shared->event;

  printf("logger thread starts\n");

  // store maps
  pid_t pid_self = syscall(SYS_getpid);
  sprintf(cmd_map_buf, "cat /proc/%d/maps > maps.data", pid_self);
  // does map information changes over time?
  system(cmd_map_buf);

  while (running) {
    head_ = event->head;
    commit_ = event->commit;
    len = (LDB_EVENT_BUF_SIZE + ((commit_ - head_) % LDB_EVENT_BUF_SIZE)) % LDB_EVENT_BUF_SIZE;

    // busy-running while waiting for entry
    if (len == 0)
      continue;

    if (head_ + len <= LDB_EVENT_BUF_SIZE) {
      fwrite(&event->events[head_], sizeof(ldb_event_entry), len, ldb_fout);
    } else {
      fwrite(&event->events[head_], sizeof(ldb_event_entry), LDB_EVENT_BUF_SIZE - head_,
          ldb_fout);
      fwrite(&event->events[0], sizeof(ldb_event_entry), (head_ + len) % LDB_EVENT_BUF_SIZE,
          ldb_fout);
    }

    fflush(ldb_fout);

    // only logger can modify head
    event->head = (head_ + len) % LDB_EVENT_BUF_SIZE;
  }

  fclose(ldb_fout);

  printf("logger thread exiting...\n");
  return NULL;
}
