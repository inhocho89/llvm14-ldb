#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include "ldb.h"
#include "ldb_tag.h"

#define CYCLES_PER_US 2992
#define LDB_MAX_CALLDEPTH 1024
#define LDB_EVENT_BUF_SIZE 200000
#define LDB_EVENT_THRESH 100000
#define LDB_EVENT_MIN_INT 10
#define LDB_EVENT_OUTPUT "ldb.data"

#define barrier()       asm volatile("" ::: "memory")

static ldb_shmseg *ldb_shared;
static pthread_t monitor_th;
static pthread_t logger_th;
static bool running;
static int nWakeup;

typedef struct {
  struct timespec ts;
  pid_t thread_id;
  uint32_t tag;
  uint64_t ngen;
  uint64_t latency;
  char *rip;
  uint64_t elapsed;
} LDBEvent;

static int eventTail = 0;
static int eventHead = 0;
static uint64_t lastWrite;
static pthread_mutex_t mEvent = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cvEvent = PTHREAD_COND_INITIALIZER;
static LDBEvent *events;

static inline int recordSize() {
  int i = eventTail - eventHead;
  return (LDB_EVENT_BUF_SIZE + (i % LDB_EVENT_BUF_SIZE)) % LDB_EVENT_BUF_SIZE;
}

static void record(struct timespec ts_, pid_t tid_, uint32_t tag_,
    uint64_t ngen_, uint64_t latency_, char *rip_, uint64_t elapsed_) {

  // If queue becomes full, ignore datapoint.
  if ((eventTail + 1) % LDB_EVENT_BUF_SIZE == eventHead) {
    fprintf(stderr, "Warning: data point was ignored\n");
    return;
  }

  LDBEvent *event = &events[eventTail];

  event->ts = ts_;
  event->thread_id = tid_;
  event->tag = tag_;
  event->ngen = ngen_;
  event->latency = latency_;
  event->rip = rip_;
  event->elapsed = elapsed_;

  pthread_mutex_lock(&mEvent);
  eventTail = (eventTail + 1) % LDB_EVENT_BUF_SIZE;
  if (recordSize() >= LDB_EVENT_THRESH ||
      ts_.tv_sec - lastWrite >= LDB_EVENT_MIN_INT) {
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

static inline bool is_stack_modified(char ***fsbase, char *slock,
    uint64_t slock2) {
  return (*fsbase == NULL || slock != *(*fsbase - 1) ||
        slock2 != *(uint64_t *)(*fsbase - 2));
}

void *monitor_main(void *arg) {
  // stats to collect
  uint32_t **ldb_tag;
  uint64_t **ldb_ngen;
  char ***ldb_rip;
  uint64_t **ldb_latency;
  int *ldb_cnt;

  struct timespec last_ts;
  struct timespec start_ts;

  // temporary variables
  uint32_t temp_tag[LDB_MAX_CALLDEPTH];
  uint64_t temp_ngen[LDB_MAX_CALLDEPTH];
  char *temp_rip[LDB_MAX_CALLDEPTH];

  struct timespec now;
  uint64_t elapsed;

  uint64_t elapsed_from_start;
  uint64_t nupdate = 0;

  // allocate memory for bookkeeping
  ldb_tag = (uint32_t **)malloc(LDB_MAX_NTHREAD * sizeof(uint32_t *));
  ldb_ngen = (uint64_t **)malloc(LDB_MAX_NTHREAD * sizeof(uint64_t *));
  ldb_rip = (char ***)malloc(LDB_MAX_NTHREAD * sizeof(char **));
  ldb_latency = (uint64_t **)malloc(LDB_MAX_NTHREAD * sizeof(uint64_t *));
  ldb_cnt = (int *)malloc(LDB_MAX_NTHREAD * sizeof(int));

  for (int i = 0; i < LDB_MAX_NTHREAD; ++i) {
    ldb_tag[i] = (uint32_t *)malloc(LDB_MAX_CALLDEPTH * sizeof(uint32_t));
    ldb_ngen[i] = (uint64_t *)malloc(LDB_MAX_CALLDEPTH * sizeof(uint64_t));
    ldb_rip[i] = (char **)malloc(LDB_MAX_CALLDEPTH * sizeof(char *));
    ldb_latency[i] = (uint64_t *)malloc(LDB_MAX_CALLDEPTH * sizeof(uint64_t));
  }

  memset(ldb_cnt, 0, sizeof(int) * LDB_MAX_NTHREAD);

  clock_gettime(CLOCK_MONOTONIC, &start_ts);
  last_ts = start_ts;

  lastWrite = start_ts.tv_sec;

  printf("Monitor thread starts\n");
  
  // Currently busy-running
  while (running) {
    barrier();
    clock_gettime(CLOCK_MONOTONIC, &now);
    barrier();
    elapsed = (now.tv_sec - last_ts.tv_sec) * 1000000000 + (now.tv_nsec - last_ts.tv_nsec);
    elapsed_from_start = (now.tv_sec - start_ts.tv_sec) * 1000000000 + (now.tv_nsec - start_ts.tv_nsec);

    for (int tidx = 0; tidx < ldb_shared->ldb_max_idx; ++tidx) {
      // Skip if fsbase is invalid
      if (ldb_shared->ldb_thread_info[tidx].fsbase == NULL)
        continue;

      pid_t thread_id = ldb_shared->ldb_thread_info[tidx].id;
      char ***fsbase = &(ldb_shared->ldb_thread_info[tidx].fsbase);
      int lidx = 0;
      char *prbp = NULL;
      char *rbp = *(*fsbase - 1);
      // use initial rbp as sequence lock
      char *slock = rbp;
      uint64_t slock2 = *(uint64_t *)(*fsbase - 2);
      uint64_t ngen = 99;
      uint64_t canary_and_tag;
      uint32_t tag;
      uint32_t canary;
      char *rip;
      bool skip_record = false;
      
      if (rbp <= (char *)0x700000000000 || rbp >= (char *)0x800000000000) {
        continue;
      }

      // traversing stack frames
      while (rbp != NULL && ngen > 0) {
        // Invalid RBP with Heuristic threshold
        // Probably dynamic loading...
        if (rbp <= (char *)0x700000000000 || rbp >= (char *)0x800000000000) {
          //printf("\tInvalid rbp = %p, ngen=%d\n", rbp, ngen);
          break;
        }

        // check whether stack has been modified
        if (is_stack_modified(fsbase, slock, slock2)) {
          lidx = 0;
          break;
        }

        barrier();

        canary_and_tag = *((uint64_t *)(rbp + 8));
        canary = (uint32_t)(canary_and_tag >> 32);
        tag = (uint32_t)(canary_and_tag & 0xffffffff);
        ngen = *((uint64_t *)(rbp + 16));
        rip = (char *)(*((uint64_t *)(rbp + 24)));

        //printf("[%d:%d] prbp=%p, rbp=%p, nextrbp=%p, ngen=%lu (thread_ngen=%lu), rip=%p, tag=%u, canary=%u\n",
        //    tidx, lidx, prbp,rbp, (char *)(*((uint64_t *)rbp)), ngen, slock2, rip, tag, canary);

        // check for the final stack frame
        if (canary == LDB_CANARY &&
            tag == 0 &&
            ngen == 0 &&
            (char *)(*((uint64_t *)rbp)) == NULL) {
          temp_tag[lidx] = tag;
          temp_ngen[lidx] = ngen;
          temp_rip[lidx] = rip;
          prbp = rbp;
          rbp = NULL;
          lidx++;
          break;
        }

        // If RIP is dynamically loaded one, skip (we cannot trace anyway)
        if (rip > (char *)0x500000) {
          if (is_stack_modified(fsbase, slock, slock2)) {
            lidx = 0;
            break;
          }
          barrier();
          prbp = rbp;
          rbp = (char *)(*((uint64_t *)rbp));
          continue;
        }

        // invalid stack frame. halting
        if (ngen > slock2 || ngen == 0 || rip == NULL || canary != LDB_CANARY) {
          //printf("\tInvalid stack frame: ngen=%lu, rip=%p, canary=%u\n", ngen, rip, canary);
//          skip_record = true;
          break;
        }

        temp_tag[lidx] = tag;
        temp_ngen[lidx] = ngen;
        temp_rip[lidx] = rip;

        // check whether stack has been modified
        if (is_stack_modified(fsbase, slock, slock2)) {
          lidx = 0;
          //printf("\tstack mod\n");
          break;
        }

        barrier();

        // rbp: go up!
        prbp = rbp;
        rbp = (char *)(*((uint64_t *)rbp));
        lidx++;
      }

      // No data collected or the stack could not reach the top
      if (lidx == 0 || rbp != NULL || ngen != 0)
        continue;

      // Update latency
      int gidx = 0;
      while (gidx < ldb_cnt[tidx] && ldb_ngen[tidx][gidx] != temp_ngen[lidx-1])
        gidx++;

      skip_record = (gidx >= ldb_cnt[tidx]);

      while (gidx < ldb_cnt[tidx] && lidx > 0) {
        if (ldb_ngen[tidx][gidx] != temp_ngen[lidx-1])
          break;
        ldb_latency[tidx][gidx] += elapsed;
        gidx++;
        lidx--;
      }

      if (gidx > LDB_MAX_CALLDEPTH) {
        printf("[WARNING] gidx overflow: %d\n", gidx);
      }

      // handle dynamic loading
      if (skip_record) {
        gidx = ldb_cnt[tidx];
      }

      // Record data collected
      for (int i = gidx; i < ldb_cnt[tidx]; ++i) {
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
      if (gidx > LDB_MAX_CALLDEPTH) {
        printf("[WARNING] gidx overflow: %d\n", gidx);
      }
      ldb_cnt[tidx] = gidx;
    } // for

    nupdate++;
    last_ts = now;
  } // while true

  for (int i = 0; i < LDB_MAX_NTHREAD; i++) {
    free(ldb_tag[i]);
    free(ldb_ngen[i]);
    free(ldb_rip[i]);
    free(ldb_latency[i]);
  }

  free(ldb_tag);
  free(ldb_ngen);
  free(ldb_rip);
  free(ldb_latency);
  free(ldb_cnt);

  printf("Monitoring thread exiting...\n");

  return NULL;
}

void *logger_main(void *arg) {
  FILE *ldb_fout = fopen(LDB_EVENT_OUTPUT, "w");
  int eventHead_;
  int eventTail_;
  struct timespec now_;

  printf("Logger thread starts\n");

  pthread_mutex_lock(&mEvent);
  while (running) {
    while (running && recordSize() < LDB_EVENT_THRESH &&
        now_.tv_sec - lastWrite < LDB_EVENT_MIN_INT) {
      pthread_cond_wait(&cvEvent, &mEvent);
      clock_gettime(CLOCK_MONOTONIC, &now_);
    }
    nWakeup++;
    eventHead_ = eventHead;
    eventTail_ = eventTail;
    pthread_mutex_unlock(&mEvent);

    while (eventHead_ != eventTail_) {
      LDBEvent *event = &events[eventHead_];
      fprintf(ldb_fout, "%lu.%09lu,%u,%u,%lu,%lu,%p,%lu\n",
          event->ts.tv_sec, event->ts.tv_nsec, event->thread_id, event->tag,
          event->ngen, event->latency, event->rip, event->elapsed);

      eventHead_ = (eventHead_ + 1) % LDB_EVENT_BUF_SIZE;
    }

    fflush(ldb_fout);
    pthread_mutex_lock(&mEvent);
    eventHead = eventHead_;
    lastWrite = now_.tv_sec;
  } 
  pthread_mutex_unlock(&mEvent);

  fclose(ldb_fout);

  printf("logger thread exiting... waken up %d times\n", nWakeup);
  return NULL;
}

// This is the main function instrumented
void __ldbInit(void) {
  // clear tag
  __ldb_clear_tag();

  // initialize stack
  char *rbp = get_rbp(); // this is rbp of __ldbInit()
  rbp = (char *)(*((uint64_t *)rbp)); // this is rbp of main()

  *((uint64_t *)(rbp + 16)) = 0;
  *((uint64_t *)(rbp + 8)) = (uint64_t)LDB_CANARY << 32;
  *((uint64_t *)rbp) = 0;

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

  // allocate event buffer
  events = (LDBEvent *)malloc(LDB_EVENT_BUF_SIZE * sizeof(LDBEvent));

  nWakeup = 0;
  running = true;

  // Launch monitoring thread
  pthread_create(&monitor_th, NULL, &monitor_main, NULL);

  // Launch logger thread
  pthread_create(&logger_th, NULL, &logger_main, NULL);
}

void __ldbExit(void) {
  void *ret;
  // Remove main thread's fsbase
  ldb_shared->ldb_thread_info[0].fsbase = NULL;

  // Join monitor and destroy spin lock?
  printf("Main app is exiting...\n");
  running = false;

  pthread_join(monitor_th, &ret);
  pthread_cond_broadcast(&cvEvent);
  pthread_join(logger_th, &ret);

  free(events);
}
