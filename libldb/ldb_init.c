#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include "ldb.h"

#define CYCLES_PER_US 2992
#define LDB_MAX_CALLDEPTH 1024
#define LDB_REPORT_BUF_SIZE 2048
#define LDB_REPORT_THRESH 256
#define LDB_REPORT_OUTPUT "ldb.data"

#define barrier()       asm volatile("" ::: "memory")

ldb_shmseg *ldb_shared;

struct LDBEvent {
  struct timespec ts;
  uint32_t thread_id;
  uint64_t tag;
  uint64_t ngen;
  uint64_t latency;
  char *rip;
  uint64_t elapsed;
};

static int eventTail = 0;
static int eventHead = 0;
static pthread_mutex_t mEvent = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cvEvent = PTHREAD_COND_INITIALIZER;
static struct LDBEvent events[LDB_REPORT_BUF_SIZE];

static inline int recordSize() {
  int i = eventTail - eventHead;
  return (LDB_REPORT_BUF_SIZE + (i % LDB_REPORT_BUF_SIZE)) % LDB_REPORT_BUF_SIZE;
}

static void record(struct timespec ts_, pthread_t tid_, uint64_t tag_,
    uint64_t ngen_, uint64_t latency_, char *rip_, uint64_t elapsed_) {

  // If queue becomes full, ignore datapoint.
  if ((eventTail + 1) % LDB_REPORT_BUF_SIZE == eventHead) {
    fprintf(stderr, "Warning: data point was ignored\n");
    return;
  }

  struct LDBEvent *event = &events[eventTail];

  event->ts = ts_;
  event->thread_id = (uint32_t)tid_;
  event->tag = tag_;
  event->ngen = ngen_;
  event->latency = latency_;
  event->rip = rip_;
  event->elapsed = elapsed_;

  pthread_mutex_lock(&mEvent);
  eventTail = (eventTail + 1) % LDB_REPORT_BUF_SIZE;
  if (recordSize() > LDB_REPORT_THRESH) {
    pthread_cond_broadcast(&cvEvent);
  }
  pthread_mutex_unlock(&mEvent);
}

// Helper functions
static inline __attribute__((always_inline)) uint64_t rdtsc(void)
{
  uint32_t a, d;
  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return ((uint64_t)a) | (((uint64_t)d) << 32);
}

static inline __attribute__((always_inline)) void cpu_relax(void)
{
  asm volatile("pause");
}

static inline __attribute__((always_inline)) void __time_delay_us(uint64_t us)
{
  uint64_t cycles = us * CYCLES_PER_US;
  unsigned long start = rdtsc();

  while (rdtsc() - start < cycles)
    cpu_relax();
}

static inline __attribute__((always_inline)) char *get_rbp() {
  char *rbp;

  asm volatile ("movq %%rbp, %0 \n\t" : "=r"(rbp) :: "memory");

  return rbp;
}

void *monitor_main(void *arg) {
  // stats to collect
  uint64_t **ldb_tag;
  uint64_t **ldb_ngen;
  char ***ldb_rip;
  uint64_t **ldb_latency;
  int *ldb_cnt;
  struct timespec last_ts;
  struct timespec start_ts;

  // temporary variables
  uint64_t temp_tag[LDB_MAX_CALLDEPTH];
  uint64_t temp_ngen[LDB_MAX_CALLDEPTH];
  char *temp_rip[LDB_MAX_CALLDEPTH];

  struct timespec now;
  uint64_t elapsed;

  uint64_t elapsed_from_start;
  uint64_t nupdate = 0;

  // allocate memory for bookkeeping
  ldb_tag = (uint64_t **)malloc(LDB_MAX_NTHREAD * sizeof(uint64_t *));
  ldb_ngen = (uint64_t **)malloc(LDB_MAX_NTHREAD * sizeof(uint64_t *));
  ldb_rip = (char ***)malloc(LDB_MAX_NTHREAD * sizeof(char **));
  ldb_latency = (uint64_t **)malloc(LDB_MAX_NTHREAD * sizeof(uint64_t *));
  ldb_cnt = (int *)malloc(LDB_MAX_NTHREAD * sizeof(int));

  for (int i = 0; i < LDB_MAX_CALLDEPTH; ++i) {
    ldb_tag[i] = (uint64_t *)malloc(LDB_MAX_CALLDEPTH * sizeof(uint64_t));
    ldb_ngen[i] = (uint64_t *)malloc(LDB_MAX_CALLDEPTH * sizeof(uint64_t));
    ldb_rip[i] = (char **)malloc(LDB_MAX_CALLDEPTH * sizeof(char *));
    ldb_latency[i] = (uint64_t *)malloc(LDB_MAX_CALLDEPTH * sizeof(uint64_t));
  }

  memset(ldb_cnt, 0, sizeof(int) * LDB_MAX_NTHREAD);

  clock_gettime(CLOCK_MONOTONIC, &start_ts);
  last_ts = start_ts;

  printf("Monitor starts\n");
  
  // Currently busy-running
  while (1) {
    barrier();
    clock_gettime(CLOCK_MONOTONIC, &now);
    barrier();
    elapsed = (now.tv_sec - last_ts.tv_sec) * 1000000000 + (now.tv_nsec - last_ts.tv_nsec);
    elapsed_from_start = (now.tv_sec - start_ts.tv_sec) * 1000000000 + (now.tv_nsec - start_ts.tv_nsec);

    for (int tidx = 0; tidx < ldb_shared->ldb_max_idx; ++tidx) {
      // Skip if fsbase is invalid
      if (ldb_shared->ldb_thread_info[tidx].fsbase == NULL)
        continue;

      pthread_t thread_id = ldb_shared->ldb_thread_info[tidx].id;
      char ***fsbase = &(ldb_shared->ldb_thread_info[tidx].fsbase);
      int lidx = 0;
      char *prbp = NULL;
      char *rbp = *(*fsbase - 1);
      // use initial rbp as sequence lock
      char *slock = rbp;
      uint64_t slock2 = *(uint64_t *)(*fsbase - 2);
      uint64_t ngen;
      uint64_t tag;
      char *rip;

      // check for valid RBP
      if (rbp < (char *)0x100000000000) {
        continue;
      }

      // traversing stack frames
      while (rbp != NULL && rbp > prbp) {
        // invalid RBP
        if (rbp >= (char *)0x800000000000) {
          break;
        }

        tag = *((uint64_t *)(rbp + 8));
        ngen = *((uint64_t *)(rbp + 16));
        rip = (char *)(*((uint64_t *)(rbp + 24)));

        //printf("[%d] rbp = %p, canary = %lu, ngen = %lu, rip = %p\n", lidx, rbp, canary, ngen, rip);

        // invalid generation number or rip
        if (ngen > slock2 || rip == NULL) {
          prbp = rbp;
          rbp = (char *)(*((uint64_t *)rbp));
          continue;
        }

        temp_tag[lidx] = tag;
        temp_ngen[lidx] = ngen;
        temp_rip[lidx] = rip;

        // check whether stack has been modified
        if (*fsbase == NULL ||
            slock != *(*fsbase - 1) ||
            slock2 != *(uint64_t *)(*fsbase - 2)) {
          lidx = 0;
          break;
        }

        // rbp: go up!
        prbp = rbp;
        rbp = (char *)(*((uint64_t *)rbp));
        lidx++;
      }

      // No data collected
      if (lidx == 0)
        continue;

      // Update latency
      int gidx = 0;
      while (gidx < ldb_cnt[tidx] && lidx > 0) {
        if (ldb_ngen[tidx][gidx] != temp_ngen[lidx-1])
          break;
        ldb_latency[tidx][gidx] += elapsed;
        gidx++;
        lidx--;
      }

      // Record data collected
      for (int i = gidx; i < ldb_cnt[tidx]; ++i) {
        //printf("%lu\n", ldb_latency[tidx][i]);
        record(now, thread_id, ldb_tag[tidx][i], ldb_ngen[tidx][i], ldb_latency[tidx][i],
            ldb_rip[tidx][i], elapsed);
      }

      // Add new nodes
      while (lidx > 0) {
        ldb_tag[tidx][gidx] = temp_tag[lidx - 1];
        ldb_ngen[tidx][gidx] = temp_ngen[lidx - 1];
        ldb_latency[tidx][gidx] = 0;
        ldb_rip[tidx][gidx] = temp_rip[lidx - 1];
        gidx++;
        lidx--;
      }
      ldb_cnt[tidx] = gidx;
    } // for

    nupdate++;
    last_ts = now;
  } // while true

  return NULL;
}

void *logger_main(void *arg) {
  FILE *ldb_fout = fopen(LDB_REPORT_OUTPUT, "w");

  while (1) {
    while (eventHead != eventTail) {
      struct LDBEvent *event = &events[eventHead];
      fprintf(ldb_fout, "%lu.%09lu,%u,%lu,%lu,%lu,%p,%lu\n",
          event->ts.tv_sec, event->ts.tv_nsec, event->thread_id, event->tag,
          event->ngen, event->latency, event->rip, event->elapsed);

      eventHead = (eventHead + 1) % LDB_REPORT_BUF_SIZE;
    }

    fflush(ldb_fout);

    pthread_mutex_lock(&mEvent);
    while (eventHead == eventTail) {
      pthread_cond_wait(&cvEvent, &mEvent);
    }
    pthread_mutex_unlock(&mEvent);
  }

  fclose(ldb_fout);
  return NULL;
}

// This is the main function instrumented
void __ldbInit(void) {
  // attach shared memory
  key_t shm_key = ftok("ldb", 65);
  int shmid = shmget(shm_key, sizeof(ldb_shmseg), 0644|IPC_CREAT);

  ldb_shared = shmat(shmid, NULL, 0);

  memset(ldb_shared, 0, sizeof(ldb_thread_info_t) * LDB_MAX_NTHREAD);

  // Set main thread's fsbase
  ldb_shared->ldb_thread_info[0].id = syscall(SYS_gettid);
  ldb_shared->ldb_thread_info[0].fsbase = (char **)(rdfsbase());
  ldb_shared->ldb_nthread = 1;
  ldb_shared->ldb_max_idx = 1;

  pthread_spin_init(&ldb_shared->ldb_tlock, PTHREAD_PROCESS_SHARED);

  // Launch monitoring thread
  pthread_t mid;
  pthread_create(&mid, NULL, &monitor_main, NULL);

  // Launch logger thread
  pthread_t lid;
  pthread_create(&lid, NULL, &logger_main, NULL);
}

void __ldbExit(void) {
  // Remove main thread's fsbase
  ldb_shared->ldb_thread_info[0].fsbase = NULL;

  // Join monitor and destroy spin lock?
}
