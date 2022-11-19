#pragma once
#include <pthread.h>

#define SHM_KEY 401916
#define LDB_MAX_NTHREAD 128
#define LDB_MAX_CALLDEPTH 1024
#define LDB_EVENT_BUF_SIZE 400000
#define LDB_EVENT_THRESH 100000
#define LDB_EVENT_MIN_INT 10
#define LDB_CANARY 0xDEADBEEF

#define barrier()       asm volatile("" ::: "memory")

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

typedef struct {
  pid_t id;
  char **fsbase;
  char *stackbase;
  char pad[8];
} ldb_thread_info_t;

enum ldb_event_type{
  LDB_EVENT_STACK = 1,
  LDB_EVENT_TAG,
  LDB_EVENT_MUTEX_WAIT,
  LDB_EVENT_MUTEX_LOCK,
  LDB_EVENT_MUTEX_UNLOCK,
  LDB_EVENT_JOIN_WAIT,
  LDB_EVENT_JOIN_JOINED
};

typedef struct {
  int event_type;
  uint32_t sec;
  uint32_t nsec;
  uint32_t tid;
  uint64_t arg1;
  uint64_t arg2;
  uint64_t arg3;
}__attribute__((packed, aligned(8))) ldb_event_entry;

typedef struct {
  int head;
  int tail;
  time_t last_write;
  uint64_t nignored;
  pthread_mutex_t m_event;
  pthread_cond_t cv_event;
  ldb_event_entry *events;
} ldb_event_handle_t;

typedef struct {
  ldb_thread_info_t *ldb_thread_infos;
  int ldb_nthread;
  int ldb_max_idx;
  pthread_spinlock_t ldb_tlock;
  ldb_event_handle_t event;
} ldb_shmseg;

static inline __attribute__((always_inline)) char *rdfsbase() {
  char *fsbase;

  asm volatile ("rdfsbase %0 \n\t" : "=r"(fsbase) :: "memory");

  return fsbase;
}

static inline int event_len(ldb_event_handle_t *event) {
  int i = event->tail - event->head;
  return (LDB_EVENT_BUF_SIZE + (i % LDB_EVENT_BUF_SIZE)) % LDB_EVENT_BUF_SIZE;
}

static void event_record(ldb_event_handle_t *event, int event_type, struct timespec ts,
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
