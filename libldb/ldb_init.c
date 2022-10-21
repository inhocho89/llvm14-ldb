#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <time.h>

#include "ldb.h"

#define CYCLES_PER_US 2992
#define LDB_MAX_CALLDEPTH 1024
#define LDB_REPORT_BUF_SIZE 1024
#define LDB_REPORT_OUTPUT "ldb.data"

ldb_shmseg *ldb_shared;

struct LDBEvent {
  uint64_t timestamp;
  uint32_t thread_id;
  uint64_t ngen;
  uint64_t latency;
  char *rip;
};

FILE *ldb_fout = NULL;
int nextIndex = 0;
static struct LDBEvent events[LDB_REPORT_BUF_SIZE];

static void printRecord() {
  if (ldb_fout == NULL)
    ldb_fout = fopen(LDB_REPORT_OUTPUT, "w");

  for (int i = 0; i < LDB_REPORT_BUF_SIZE; ++i) {
    struct LDBEvent *event = &events[i];
    fprintf(ldb_fout, "%lu,%u,%lu,%lf,%p\n",
        event->timestamp, event->thread_id, event->ngen,
        1.0 * event->latency / CYCLES_PER_US, event->rip);
  }

  fflush(ldb_fout);
}

static void record(uint64_t timestamp_, pthread_t tid_, uint64_t ngen_,
    uint64_t latency_, char *rip_) {
  struct LDBEvent *event = &events[nextIndex];

  event->timestamp = timestamp_;
  event->thread_id = (uint32_t)tid_;
  event->ngen = ngen_;
  event->latency = latency_;
  event->rip = rip_;

  nextIndex = (nextIndex + 1) % LDB_REPORT_BUF_SIZE;
  if (nextIndex == 0)
    printRecord();
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
  uint64_t **ldb_ngen;
  char ***ldb_rip;
  uint64_t **ldb_latency;
  int *ldb_cnt;
  uint64_t last_tsc = rdtsc();

  // temporary variables
  uint64_t temp_ngen[LDB_MAX_CALLDEPTH];
  char *temp_rip[LDB_MAX_CALLDEPTH];

  // allocate memory for bookkeeping
  ldb_ngen = (uint64_t **)malloc(LDB_MAX_NTHREAD * sizeof(uint64_t *));
  ldb_rip = (char ***)malloc(LDB_MAX_NTHREAD * sizeof(char **));
  ldb_latency = (uint64_t **)malloc(LDB_MAX_NTHREAD * sizeof(uint64_t *));
  ldb_cnt = (int *)malloc(LDB_MAX_NTHREAD * sizeof(int));

  for (int i = 0; i < LDB_MAX_CALLDEPTH; ++i) {
    ldb_ngen[i] = (uint64_t *)malloc(LDB_MAX_CALLDEPTH * sizeof(uint64_t));
    ldb_rip[i] = (char **)malloc(LDB_MAX_CALLDEPTH * sizeof(char *));
    ldb_latency[i] = (uint64_t *)malloc(LDB_MAX_CALLDEPTH * sizeof(uint64_t));
  }

  memset(ldb_cnt, 0, sizeof(int) * LDB_MAX_NTHREAD);

  // initialize output
  remove(LDB_REPORT_OUTPUT);

  printf("Monitor starts\n");
  
  // Currently busy-running
  while (1) {
    unsigned long now = rdtsc();
    unsigned long elapsed = now - last_tsc;

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
      uint64_t ngen = 99;
      char *rip;

      // for some reason
      if (rbp == (char *)0x1) {
        continue;
      }

      // traversing stack frames
      while (rbp != NULL && ngen > 1) {
        if (rbp < prbp) {
          lidx = 0;
          break;
        }
        if (rbp == (char *)(*((uint64_t *)rbp))) {
          lidx--;
          break;
        }

        ngen = *((uint64_t *)(rbp + 16));
        rip = (char *)(*((uint64_t *)(rbp + 24)));

        //printf("[%d] rbp = %p, canary = %lu, ngen = %lu, rip = %p\n", lidx, rbp, canary, ngen, rip);

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
        record(now, thread_id, ldb_ngen[tidx][i], ldb_latency[tidx][i], ldb_rip[tidx][i]);
      }

      // Add new nodes
      while (lidx > 0) {
        ldb_ngen[tidx][gidx] = temp_ngen[lidx - 1];
        ldb_latency[tidx][gidx] = 0;
        ldb_rip[tidx][gidx] = temp_rip[lidx - 1];
        gidx++;
        lidx--;
      }

      ldb_cnt[tidx] = gidx;
    } // for
    last_tsc = now;
  } // while true

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
  ldb_shared->ldb_thread_info[0].id = pthread_self();
  ldb_shared->ldb_thread_info[0].fsbase = (char **)(rdfsbase());
  ldb_shared->ldb_nthread = 1;
  ldb_shared->ldb_max_idx = 1;

  pthread_spin_init(&ldb_shared->ldb_tlock, PTHREAD_PROCESS_SHARED);

  // Launch monitoring thread
  pthread_t mid;
  pthread_create(&mid, NULL, &monitor_main, NULL);
}

void __ldbExit(void) {
  // Remove main thread's fsbase
  ldb_shared->ldb_thread_info[0].fsbase = NULL;

  // Join monitor and destroy spin lock?
}
