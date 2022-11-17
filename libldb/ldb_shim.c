#define _GNU_SOURCE
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

#include "ldb.h"
#include "ldb_tag.h"

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

/* pthread-related functions */
void *__ldb_thread_start(void *arg) {
  void *ret;
  int tidx;
  pthread_param_t real_thread_params;

  memcpy(&real_thread_params, arg, sizeof(pthread_param_t));

  free(arg);

  // clear tag
  __ldb_clear_tag();

  // initialize stack
  char *rbp = get_rbp(); // this is the rbp of thread main

  // set ngen to 0
  *((uint64_t *)(rbp + 16)) = 0;
  // set canary and tag
  *((uint64_t *)(rbp + 8)) = (uint64_t)LDB_CANARY << 32;
  // set old RBP
  *((uint64_t *)rbp) = 0;

  printf("New interposed thread is starting... thread ID = %ld\n", syscall(SYS_gettid));
  printf("ngen = %lu, tls rbp = %p, real rbp = %p\n", get_ngen(), get_rbp(), get_real_rbp());

  // attach shared memory
  if (ldb_shared == NULL) {
    int shmid = shmget(SHM_KEY, sizeof(ldb_shmseg), 0666);
    ldb_shared = shmat(shmid, NULL, 0);
  }

  // start tracking
  pthread_spin_lock(&(ldb_shared->ldb_tlock));
  tidx = __ldb_get_tidx();
  ldb_shared->ldb_thread_info[tidx].id = syscall(SYS_gettid);
  ldb_shared->ldb_thread_info[tidx].fsbase = (char **)(rdfsbase());
  ldb_shared->ldb_thread_info[tidx].stackbase = rbp;
  pthread_spin_unlock(&(ldb_shared->ldb_tlock));

  // execute real thread
  ret = real_thread_params.worker_func(real_thread_params.param);

  // stop tracking
  pthread_spin_lock(&(ldb_shared->ldb_tlock));
  __ldb_put_tidx(tidx);
  pthread_spin_unlock(&(ldb_shared->ldb_tlock));

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
          return 0;
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

int pthread_mutex_lock(pthread_mutex_t *mutex) {
  char *error;
  static int (*real_pthread_mutex_lock)(pthread_mutex_t *m);

  if (unlikely(!real_pthread_mutex_lock)) {
    real_pthread_mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return 0;
    }
  }

  return real_pthread_mutex_lock(mutex);
}

int pthread_spin_lock(pthread_spinlock_t *lock) {
  char *error;
  static int (*real_pthread_spin_lock)(pthread_spinlock_t *);

  if (unlikely(!real_pthread_spin_lock)) {
    real_pthread_spin_lock = dlsym(RTLD_NEXT, "pthread_spin_lock");
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      return 0;
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
       return 0;
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
			return 0;
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
      return 0;
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
			return 0;
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
