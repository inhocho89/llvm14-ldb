#pragma once
#include <pthread.h>

#define SHM_KEY 401916
#define LDB_MAX_NTHREAD 128

typedef struct {
  pid_t id;
  char **fsbase;
  char *stackbase;
  char pad[8];
} ldb_thread_info_t;

typedef struct {
  ldb_thread_info_t ldb_thread_info[LDB_MAX_NTHREAD];
  int ldb_nthread;
  int ldb_max_idx;
  pthread_spinlock_t ldb_tlock;
} ldb_shmseg;

static inline __attribute__((always_inline)) char *rdfsbase() {
  char *fsbase;

  asm volatile ("rdfsbase %0 \n\t" : "=r"(fsbase) :: "memory");

  return fsbase;
}
