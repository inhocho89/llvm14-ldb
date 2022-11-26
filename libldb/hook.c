#include "common.h"

static pthread_t monitor_th;
static pthread_t logger_th;

ldb_shmseg *ldb_shared;
bool running;

extern void *monitor_main(void *arg);
extern void *logger_main(void *arg);

// This is the main function instrumented
void __ldbInit(void) {
  // initialize canary
  setup_canary();

  // initialize stack
  char *rbp = get_rbp(); // this is rbp of __ldbInit()
  rbp = (char *)(*((uint64_t *)rbp)); // this is rbp of main()

  *((uint64_t *)(rbp + 16)) = 0;
  *((uint64_t *)(rbp + 8)) = (uint64_t)LDB_CANARY << 32;
  *((uint64_t *)rbp) = 0;

  // attach shared memory
  int shmid = shmget(SHM_KEY, sizeof(ldb_shmseg), 0666 | IPC_CREAT);
  ldb_shared = shmat(shmid, NULL, 0);

	// initialize thread info
  ldb_shared->ldb_thread_infos = (ldb_thread_info_t *)malloc(sizeof(ldb_thread_info_t) * LDB_MAX_NTHREAD);
  memset(ldb_shared->ldb_thread_infos, 0, sizeof(ldb_thread_info_t) * LDB_MAX_NTHREAD);

  // allocate & initialize event buffer
  ldb_event_buffer_t *ebuf = (ldb_event_buffer_t *)malloc(sizeof(ldb_event_buffer_t));
  memset(ebuf, 0, sizeof(ldb_event_buffer_t));
  ebuf->events = (ldb_event_entry *)malloc(sizeof(ldb_event_entry) * LDB_EVENT_BUF_SIZE);

  // initialize main thread's info
  ldb_shared->ldb_thread_infos[0].id = syscall(SYS_gettid);
  ldb_shared->ldb_thread_infos[0].fsbase = (char **)(rdfsbase());
  ldb_shared->ldb_thread_infos[0].stackbase = rbp;
  ldb_shared->ldb_thread_infos[0].ebuf = ebuf;
  clock_gettime(CLOCK_MONOTONIC, &ldb_shared->ldb_thread_infos[0].ts_wait);
  clock_gettime(CLOCK_MONOTONIC, &ldb_shared->ldb_thread_infos[0].ts_lock);

  ldb_shared->ldb_nthread = 1;
  ldb_shared->ldb_max_idx = 1;

  register_thread_info(0);

  pthread_spin_init(&ldb_shared->ldb_tlock, PTHREAD_PROCESS_SHARED);

  running = true;

  // Launch monitoring thread
  pthread_create(&monitor_th, NULL, &monitor_main, NULL);

  // Launch logger thread
  pthread_create(&logger_th, NULL, &logger_main, NULL);
}

void __ldbExit(void) {
  void *ret;
  // Remove main thread's fsbase
  ldb_shared->ldb_thread_infos[0].fsbase = NULL;

  // Join monitor and destroy spin lock?
  printf("Main app is exiting...\n");
  running = false;

  pthread_join(monitor_th, &ret);
  pthread_join(logger_th, &ret);

  free(ldb_shared->ldb_thread_infos[0].ebuf->events);
  free(ldb_shared->ldb_thread_infos[0].ebuf);
  free(ldb_shared->ldb_thread_infos);

  shmdt(ldb_shared);
}
