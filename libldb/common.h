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
#define LDB_EVENT_BUF_SIZE 524288
#define LDB_CANARY 0xDEADBEEF

#define LDB_MUTEX_EVENT_THRESH_NS 1000

#define barrier() asm volatile("" ::: "memory")
#define CAS(x,y,z) __sync_bool_compare_and_swap(x,y,z)

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

enum ldb_event_type {
  LDB_EVENT_STACK = 1,
  LDB_EVENT_TAG_SET,
  LDB_EVENT_TAG_BLOCK,
  LDB_EVENT_TAG_UNSET,
  LDB_EVENT_TAG_CLEAR,
  LDB_EVENT_MUTEX_WAIT,
  LDB_EVENT_MUTEX_LOCK,
  LDB_EVENT_MUTEX_UNLOCK,
  LDB_EVENT_JOIN_WAIT,
  LDB_EVENT_JOIN_JOINED,
  LDB_EVENT_THREAD_CREATE,
  LDB_EVENT_THREAD_EXIT,
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
  int head;   // current read index
  int tail;   // current write index
  uint64_t nignored;
  ldb_event_entry *events;
} ldb_event_buffer_t;

typedef struct {
  pid_t id;
  char **fsbase;
  char *stackbase;
  struct timespec ts_wait;
  struct timespec ts_lock;
  struct timespec ts_scan;
  ldb_event_buffer_t *ebuf;
} ldb_thread_info_t;

typedef struct {
  ldb_thread_info_t *ldb_thread_infos;
  int ldb_nthread;
  int ldb_max_idx;
  pthread_spinlock_t ldb_tlock;
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

inline __attribute__((always_inline)) void __time_delay_ns(uint64_t ns)
{
  uint64_t cycles = ns * CYCLES_PER_US / 1000;
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

inline __attribute__((always_inline)) void register_thread_info(int idx) {
  __asm volatile ("mov %0, %%fs:-32 \n\t" :: "r"(idx): "memory");
}

inline __attribute__((always_inline)) pid_t get_thread_info_idx() {
  int idx;

  __asm volatile ("mov %%fs:-32, %0 \n\t" : "=r"(idx) :: "memory");

  return idx;
}

/* shared memory related functions */
inline __attribute__((always_inline)) ldb_shmseg *attach_shared_memory() {
  int shmid = shmget(SHM_KEY, sizeof(ldb_shmseg), 0666);
  ldb_shmseg *ldb_shared = shmat(shmid, NULL, 0);

  return ldb_shared;
}

/* Event logging functions */
void event_record(ldb_event_buffer_t *event, int event_type, struct timespec ts,
		uint32_t tid, uint64_t arg1, uint64_t arg2, uint64_t arg3);
void event_record_now(int event_type, uint64_t arg1, uint64_t arg2, uint64_t arg3);
