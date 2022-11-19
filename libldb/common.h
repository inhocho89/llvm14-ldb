#pragma once
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define CYCLES_PER_US 2396
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
  LDB_EVENT_TAG_SET,
  LDB_EVENT_TAG_BLOCK,
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

// Helper functions
inline __attribute__((always_inline)) uint64_t rdtsc(void)
{
  uint32_t a, d;
  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return ((uint64_t)a) | (((uint64_t)d) << 32);
}

inline __attribute__((always_inline)) void cpu_relax(void)
{
  asm volatile("pause");
}

inline __attribute__((always_inline)) void __time_delay_us(uint64_t us)
{
  uint64_t cycles = us * CYCLES_PER_US;
  unsigned long start = rdtsc();

  while (rdtsc() - start < cycles)
    cpu_relax();
}

inline __attribute__((always_inline)) char *get_fs_rbp() {
  char *rbp;

  asm volatile ("movq %%fs:-8, %0 \n\t" : "=r"(rbp) :: "memory");

  return rbp;
}

inline __attribute__((always_inline)) char *get_rbp() {
  char *rbp;

  asm volatile ("movq %%rbp, %0 \n\t" : "=r"(rbp) :: "memory");

  return rbp;
}

inline __attribute__((always_inline)) char *rdfsbase() {
  char *fsbase;

  asm volatile ("rdfsbase %0 \n\t" : "=r"(fsbase) :: "memory");

  return fsbase;
}

inline __attribute__((always_inline)) void setup_canary() {
  uint64_t tag = ((uint64_t)LDB_CANARY) << 32;
  __asm volatile ("movq %0, %%fs:-24 \n\t" :: "r"(tag): "memory");
}

/* shared memory related functions */
inline __attribute__((always_inline)) ldb_shmseg *attach_shared_memory() {
  int shmid = shmget(SHM_KEY, sizeof(ldb_shmseg), 0666);
  ldb_shmseg *ldb_shared = shmat(shmid, NULL, 0);

  return ldb_shared;
}

/* Event related functions */
inline int event_len(ldb_event_handle_t *event) {
  int i = event->tail - event->head;

  return (LDB_EVENT_BUF_SIZE + (i % LDB_EVENT_BUF_SIZE)) % LDB_EVENT_BUF_SIZE;
}

void event_record(ldb_event_handle_t *event, int event_type, struct timespec ts,
		uint32_t tid, uint64_t arg1, uint64_t arg2, uint64_t arg3);

static inline void
event_record_now(ldb_event_handle_t *event, int event_type,
                 uint64_t arg1, uint64_t arg2, uint64_t arg3) {
  struct timespec now;
  pid_t thread_id = syscall(SYS_gettid);
  clock_gettime(CLOCK_MONOTONIC, &now);
  event_record(event, event_type, now, thread_id, arg1, arg2, arg3);
}
