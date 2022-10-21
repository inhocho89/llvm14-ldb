#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <bits/pthreadtypes.h>
#include <dlfcn.h>

#include "ldb.h"

ldb_shmseg *ldb_shared;

typedef struct {   
    void *(*worker_func)(void *param);
    void *param;
} pthread_param_t;

static inline __attribute__((always_inline)) uint64_t get_ngen() {
  uint64_t ngen;

  asm volatile ("movq %%fs:-16, %0 \n\t" : "=r"(ngen) :: "memory");

  return ngen;
}

static inline __attribute__((always_inline)) char *get_rbp() {
  char *rbp;

  asm volatile ("movq %%fs:-8, %0 \n\t" : "=r"(rbp) :: "memory");

  return rbp;
}

static inline __attribute__((always_inline)) char *get_real_rbp() {
  char *rbp;

  asm volatile ("movq %%rbp, %0 \n\t" : "=r"(rbp) :: "memory");

  return rbp;
}

int __ldb_get_tidx() {
  // find reusable slot
  for (int i = 0; i < ldb_shared->ldb_max_idx; ++i) {
    if (ldb_shared->ldb_thread_info[i].fsbase == NULL) {
      ldb_shared->ldb_nthread++;
      return i;
    }
  }

  // new slot
  ldb_shared->ldb_max_idx++;
  ldb_shared->ldb_nthread++;

  return (ldb_shared->ldb_max_idx - 1);
}

void __ldb_put_tidx(int tidx) {
  ldb_shared->ldb_thread_info[tidx].fsbase = NULL;

  // This is the last slot
  if (tidx == ldb_shared->ldb_max_idx - 1) {
    ldb_shared->ldb_max_idx--;
  }
  ldb_shared->ldb_nthread--;
}

void *__ldb_thread_start(void *arg) {
  void *ret;
  int tidx;
  pthread_param_t real_thread_params;

  memcpy(&real_thread_params, arg, sizeof(pthread_param_t));

  free(arg);

  printf("New interposed thread is starting...\n");
  printf("ngen = %lu, tls rbp = %p, real rbp = %p\n", get_ngen(), get_rbp(), get_real_rbp());

  // attach shared memory
  key_t shm_key = ftok("ldb", 65);
  int shmid = shmget(shm_key, sizeof(ldb_shmseg), 0644|IPC_CREAT);
  ldb_shared = shmat(shmid, NULL, 0);

  // start tracking
  pthread_spin_lock(&(ldb_shared->ldb_tlock));
  tidx = __ldb_get_tidx();
  ldb_shared->ldb_thread_info[tidx].id = pthread_self();
  ldb_shared->ldb_thread_info[tidx].fsbase = (char **)(rdfsbase());
  pthread_spin_unlock(&(ldb_shared->ldb_tlock));

  ret = real_thread_params.worker_func(real_thread_params.param);

  pthread_spin_lock(&(ldb_shared->ldb_tlock));
  __ldb_put_tidx(tidx);
  pthread_spin_unlock(&(ldb_shared->ldb_tlock));

  return ret;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg) {
    char *error;
    int (*real_pthread_create)(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg);

    real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
    if( (error = dlerror()) != NULL) {
        fputs(error, stderr);
        return 0;
    }

    pthread_param_t *worker_params;

    worker_params = malloc(sizeof(pthread_param_t));

    worker_params->worker_func  = start_routine;
    worker_params->param        = arg;

    /* Call the real pthread_create function and return the value like a normal
        call to pthread_create*/
    return real_pthread_create(thread, attr, &__ldb_thread_start, worker_params);
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
  char *error;
  int (*real_pthread_mutex_lock)(pthread_mutex_t *m);

  real_pthread_mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
  if ((error = dlerror()) != NULL) {
    fputs(error, stderr);
    return 0;
  }

  return real_pthread_mutex_lock(mutex);
}

int rand(void) {
  char *error;
  int (*real_rand)(void);

  real_rand = dlsym(RTLD_NEXT, "rand");
  if ((error = dlerror()) != NULL) {
    fputs(error, stderr);
    return 0;
  }

  return real_rand();
}
