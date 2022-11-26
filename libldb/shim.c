#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <syscall.h>
#include <unistd.h>
#include <bits/pthreadtypes.h>
#include <dlfcn.h>

#include "common.h"

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

static inline int get_tidx() {
  // find reusable slot
  for (int i = 0; i < ldb_shared->ldb_max_idx; ++i) {
    if (ldb_shared->ldb_thread_infos[i].fsbase == NULL) {
      ldb_shared->ldb_nthread++;
      return i;
    }
  }

  // new slot
  ldb_shared->ldb_max_idx++;
  ldb_shared->ldb_nthread++;

  return (ldb_shared->ldb_max_idx - 1);
}

static inline void put_tidx(int tidx) {
  memset(&ldb_shared->ldb_thread_infos[tidx], 0, sizeof(ldb_thread_info_t));

  // This is the last slot
  if (tidx == ldb_shared->ldb_max_idx - 1) {
    ldb_shared->ldb_max_idx--;
  }
  ldb_shared->ldb_nthread--;
}

static inline uint64_t timespec_diff_ns(struct timespec t1, struct timespec t2) {
  return (t1.tv_sec - t2.tv_sec) * 1000000000 + (t1.tv_nsec - t2.tv_nsec);
}

static void event_record_mutex(pthread_mutex_t *mutex) {
  if (unlikely(!ldb_shared)) {
    ldb_shared = attach_shared_memory();
  }

  struct timespec now;
  int tinfo_idx = get_thread_info_idx();
  ldb_thread_info_t *tinfo = &ldb_shared->ldb_thread_infos[tinfo_idx];

  clock_gettime(CLOCK_MONOTONIC, &now);

  uint64_t wait_time = timespec_diff_ns(tinfo->ts_lock, tinfo->ts_wait);
  uint64_t lock_time = timespec_diff_ns(now, tinfo->ts_lock);

  if (wait_time >= LDB_MUTEX_EVENT_THRESH_NS || lock_time >= LDB_MUTEX_EVENT_THRESH_NS) {
    event_record(tinfo->ebuf, LDB_EVENT_MUTEX_WAIT, tinfo->ts_wait, tinfo->id,
        (uintptr_t)mutex, 0, 0);
    event_record(tinfo->ebuf, LDB_EVENT_MUTEX_LOCK, tinfo->ts_lock, tinfo->id,
        (uintptr_t)mutex, 0, 0);
    event_record(tinfo->ebuf, LDB_EVENT_MUTEX_UNLOCK, now, tinfo->id,
        (uintptr_t)mutex, 0, 0);
  }
}

/* pthread-related functions */
void *__ldb_thread_start(void *arg) {
  void *ret;
  int tidx;
  pthread_param_t real_thread_params;

  memcpy(&real_thread_params, arg, sizeof(pthread_param_t));

  free(arg);

  // initialize canary
  setup_canary();

  // initialize stack
  char *rbp = get_fs_rbp(); // this is the rbp of thread main

  // set ngen to 0
  *((uint64_t *)(rbp + 16)) = 0;
  // set canary and tag
  *((uint64_t *)(rbp + 8)) = (uint64_t)LDB_CANARY << 32;
  // set old RBP
  *((uint64_t *)rbp) = 0;

  printf("New interposed thread is starting... thread ID = %ld\n", syscall(SYS_gettid));
  printf("ngen = %lu, tls rbp = %p, real rbp = %p\n", get_ngen(), get_fs_rbp(), get_rbp());

  // attach shared memory
  if (unlikely(!ldb_shared)) {
    ldb_shared = attach_shared_memory();
  }

  // allocate & initialize event buffer
  ldb_event_buffer_t *ebuf = (ldb_event_buffer_t *)malloc(sizeof(ldb_event_buffer_t));
  memset(ebuf, 0, sizeof(ldb_event_buffer_t));
  ebuf->events = (ldb_event_entry *)malloc(sizeof(ldb_event_entry) * LDB_EVENT_BUF_SIZE);
  if (ebuf->events == 0) {
    fprintf(stderr, "\tmalloc() failed\n");
  }

  // start tracking
  pthread_spin_lock(&(ldb_shared->ldb_tlock));
  tidx = get_tidx();
  ldb_shared->ldb_thread_infos[tidx].id = syscall(SYS_gettid);
  ldb_shared->ldb_thread_infos[tidx].fsbase = (char **)(rdfsbase());
  ldb_shared->ldb_thread_infos[tidx].stackbase = rbp;
  ldb_shared->ldb_thread_infos[tidx].ebuf = ebuf;
  pthread_spin_unlock(&(ldb_shared->ldb_tlock));

  clock_gettime(CLOCK_MONOTONIC, &ldb_shared->ldb_thread_infos[tidx].ts_wait);
  clock_gettime(CLOCK_MONOTONIC, &ldb_shared->ldb_thread_infos[tidx].ts_lock);

  register_thread_info(tidx);

  // execute real thread
  ret = real_thread_params.worker_func(real_thread_params.param);

  // stop tracking
  pthread_spin_lock(&(ldb_shared->ldb_tlock));
  put_tidx(tidx);
  pthread_spin_unlock(&(ldb_shared->ldb_tlock));

  printf("Application thread is exitting... %lu data point ignored\n", ebuf->nignored);

  free(ebuf->events);
  free(ebuf);

  return ret;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg) {
    char *error;
    static int (*real_pthread_create)(pthread_t *thread, const pthread_attr_t *attr,
        void *(*start_routine) (void *), void *arg);

    if (unlikely(!real_pthread_create)) {
      real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
      if( (error = dlerror()) != NULL) {
          fputs(error, stderr);
          return -1;
      }
    }

    pthread_param_t *worker_params;

    worker_params = malloc(sizeof(pthread_param_t));

    worker_params->worker_func  = start_routine;
    worker_params->param        = arg;

    /* Call the real pthread_create function and return the value like a normal
        call to pthread_create*/
    return real_pthread_create(thread, attr, &__ldb_thread_start, worker_params);
}

int pthread_join(pthread_t thread, void **retval) {
  char *error;
  static int (*real_pthread_join)(pthread_t, void **);
  int ret;

  if (unlikely(!real_pthread_join)) {
    real_pthread_join = dlsym(RTLD_NEXT, "pthread_join");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return -1;
    }
  }

  // pthread_t -> tid mapping should be stored at pthread_create
  event_record_now(LDB_EVENT_JOIN_WAIT, (uint64_t)thread, 0, 0);
  ret = real_pthread_join(thread, retval);
  if (likely(ret == 0)) {
    event_record_now(LDB_EVENT_JOIN_JOINED, (uint64_t)thread, 0, 0);
  }

  return ret;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
  char *error;
  static int (*real_pthread_mutex_lock)(pthread_mutex_t *m);
  int ret;
  int thread_info_idx = get_thread_info_idx();

  if (unlikely(!real_pthread_mutex_lock)) {
    real_pthread_mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return -1;
    }
  }
  if (likely(ldb_shared)) {
    clock_gettime(CLOCK_MONOTONIC, &ldb_shared->ldb_thread_infos[thread_info_idx].ts_wait);
  }

  ret = real_pthread_mutex_lock(mutex);

  if (likely(ldb_shared && ret == 0)) {
    clock_gettime(CLOCK_MONOTONIC, &ldb_shared->ldb_thread_infos[thread_info_idx].ts_lock);
  }

  return ret;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
  char *error;
  static int (*real_pthread_mutex_unlock)(pthread_mutex_t *m);
  int ret;

  if (unlikely(!real_pthread_mutex_unlock)) {
    real_pthread_mutex_unlock = dlsym(RTLD_NEXT, "pthread_mutex_unlock");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return -1;
    }
  }

  ret = real_pthread_mutex_unlock(mutex);

  if (likely(ret == 0)) {
    event_record_mutex(mutex);
  }

  return ret;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
  char *error;
  static int (*real_pthread_mutex_trylock)(pthread_mutex_t *m);
  int ret;
  int thread_info_idx = get_thread_info_idx();

  if (unlikely(!real_pthread_mutex_trylock)) {
    real_pthread_mutex_trylock = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return -1;
    }
  }

  if (likely(ldb_shared)) {
    clock_gettime(CLOCK_MONOTONIC, &ldb_shared->ldb_thread_infos[thread_info_idx].ts_wait);
  }

  ret = real_pthread_mutex_trylock(mutex);

  if (likely(ldb_shared) && ret == 0) {
    clock_gettime(CLOCK_MONOTONIC, &ldb_shared->ldb_thread_infos[thread_info_idx].ts_lock);
  }

  return ret;
}

int pthread_spin_lock(pthread_spinlock_t *lock) {
  char *error;
  static int (*real_pthread_spin_lock)(pthread_spinlock_t *);

  if (unlikely(!real_pthread_spin_lock)) {
    real_pthread_spin_lock = dlsym(RTLD_NEXT, "pthread_spin_lock");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return -1;
    }
  }

  return real_pthread_spin_lock(lock);
}

int pthread_cond_broadcast(pthread_cond_t *cond) {
  char *error;
  static int (*real_pthread_cond_broadcast)(pthread_cond_t *);

  if (unlikely(!real_pthread_cond_broadcast)) {
    real_pthread_cond_broadcast = dlsym(RTLD_NEXT, "pthread_cond_broadcast");
    if ((error = dlerror()) != NULL) {
       fputs(error, stderr);
       return -1;
    }
  }

  return real_pthread_cond_broadcast(cond);
}

int pthread_cond_signal(pthread_cond_t *cond) {
  char *error;
  static int (*real_pthread_cond_signal)(pthread_cond_t *);

  if (unlikely(!real_pthread_cond_signal)) {
    real_pthread_cond_signal = dlsym(RTLD_NEXT, "pthread_cond_signal");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return -1;
    }
  }

  return real_pthread_cond_signal(cond);
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
  char *error;
  static int (*real_pthread_cond_wait)(pthread_cond_t *, pthread_mutex_t *);

  if (unlikely(!real_pthread_cond_wait)) {
    real_pthread_cond_wait = dlsym(RTLD_NEXT, "pthread_cond_wait");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return -1;
    }
  }

  return real_pthread_cond_wait(cond, mutex);
}

int pthread_cond_timedwait(pthread_cond_t *cond,
                           pthread_mutex_t *mutex,
                           const struct timespec *abstime) {
  char *error;
  static int (*real_pthread_cond_timedwait)(pthread_cond_t *, pthread_mutex_t *,
      const struct timespec *);

  if (unlikely(!real_pthread_cond_timedwait)) {
    real_pthread_cond_timedwait = dlsym(RTLD_NEXT, "pthread_cond_timedwait");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return -1;
    }
  }

  return real_pthread_cond_timedwait(cond, mutex, abstime);
}

/* memory-related functions */
void *memset(void *str, int c, size_t n) {
  char *error;
  static void *(*real_memset)(void *, int, size_t);

  if (unlikely(!real_memset)) {
    real_memset = dlsym(RTLD_NEXT, "memset");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return NULL;
    }
  }

  return real_memset(str, c, n);
}

void *memcpy(void *dest, const void *src, size_t len) {
  char *error;
  static void *(*real_memcpy)(void *, const void *, size_t);

  if (unlikely(!real_memcpy)) {
    real_memcpy = dlsym(RTLD_NEXT, "memcpy");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return NULL;
    }
  }

  return real_memcpy(dest, src, len);
}

void *malloc(size_t size) {
  char *error;
  static void *(*real_malloc)(size_t);

  if (unlikely(!real_malloc)) {
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return NULL;
    }
  }

  return real_malloc(size);
}

void free(void *ptr) {
  char *error;
  static void (*real_free)(void *);

  if (unlikely(!real_free)) {
    real_free = dlsym(RTLD_NEXT, "free");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return;
    }
  }

  return real_free(ptr); 
}

/* other useful functions */
int rand(void) {
  char *error;
  static int (*real_rand)(void);

  if (unlikely(!real_rand)) {
    real_rand = dlsym(RTLD_NEXT, "rand");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return 0;
    }
  }

  return real_rand();
}
