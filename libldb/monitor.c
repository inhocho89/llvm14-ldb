#define _GNU_SOURCE
#include <time.h>
#include "common.h"

#define LDB_MONITOR_PERIOD 1

extern ldb_shmseg *ldb_shared;
extern bool running;

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
  char ***ldb_rbp;
  uint64_t **ldb_latency;
  int *ldb_cnt;

  // temporary variables
  uint32_t temp_tag[LDB_MAX_CALLDEPTH];
  uint64_t temp_ngen[LDB_MAX_CALLDEPTH];
  char *temp_rip[LDB_MAX_CALLDEPTH];
  char *temp_rbp[LDB_MAX_CALLDEPTH];

  struct timespec scan_start;
  struct timespec scan_finish;
  uint64_t scan_delay;

  cpu_set_t cpuset;

  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

  // allocate memory for bookkeeping
  ldb_tag = (uint32_t **)malloc(LDB_MAX_NTHREAD * sizeof(uint32_t *));
  ldb_ngen = (uint64_t **)malloc(LDB_MAX_NTHREAD * sizeof(uint64_t *));
  ldb_rip = (char ***)malloc(LDB_MAX_NTHREAD * sizeof(char **));
  ldb_rbp = (char ***)malloc(LDB_MAX_NTHREAD * sizeof(char **));
  ldb_latency = (uint64_t **)malloc(LDB_MAX_NTHREAD * sizeof(uint64_t *));
  ldb_cnt = (int *)malloc(LDB_MAX_NTHREAD * sizeof(int));

  for (int i = 0; i < LDB_MAX_NTHREAD; ++i) {
    ldb_tag[i] = (uint32_t *)malloc(LDB_MAX_CALLDEPTH * sizeof(uint32_t));
    ldb_ngen[i] = (uint64_t *)malloc(LDB_MAX_CALLDEPTH * sizeof(uint64_t));
    ldb_rip[i] = (char **)malloc(LDB_MAX_CALLDEPTH * sizeof(char *));
    ldb_rbp[i] = (char **)malloc(LDB_MAX_CALLDEPTH * sizeof(char *));
    ldb_latency[i] = (uint64_t *)malloc(LDB_MAX_CALLDEPTH * sizeof(uint64_t));
  }

  memset(ldb_cnt, 0, sizeof(int) * LDB_MAX_NTHREAD);

  ldb_event_buffer_t *ebuf = ldb_shared->ldb_thread_infos[get_thread_info_idx()].ebuf;

  printf("Monitor thread starts\n");
  
  // Currently busy-running
  while (running) {
#if LDB_MONITOR_PERIOD > 0
    barrier();
    clock_gettime(CLOCK_MONOTONIC_RAW, &scan_start);
    barrier();
#endif
    for (int tidx = 0; tidx < ldb_shared->ldb_max_idx; ++tidx) {
      // Skip if fsbase is invalid
      if (ldb_shared->ldb_thread_infos[tidx].fsbase == NULL) {
        continue;
      }

      pid_t thread_id = ldb_shared->ldb_thread_infos[tidx].id;
      char ***fsbase = &(ldb_shared->ldb_thread_infos[tidx].fsbase);
      char *stack_base = ldb_shared->ldb_thread_infos[tidx].stackbase;
      struct timespec *last_ts = &ldb_shared->ldb_thread_infos[tidx].ts_scan;
      struct timespec now;
      uint64_t elapsed;
      int lidx = 0;
      char *rbp = *(*fsbase - 1);
      uint64_t slock2 = *(uint64_t *)(*fsbase - 2);
      char *prbp = rbp - 8;
      // use initial rbp as sequence lock
      char *slock = rbp;
      uint64_t ngen = 99;
      uint64_t canary_and_tag;
      uint32_t tag;
      uint32_t canary;
      char *rip;

      barrier();
      clock_gettime(CLOCK_MONOTONIC_RAW, &now);
      barrier();
      elapsed = (now.tv_sec - last_ts->tv_sec) * 1000000000 + (now.tv_nsec - last_ts->tv_nsec);

      // Heuristic check if rbp is not valid, skip this iteration
      if (rbp <= (char *)0x7f0000000000 || rbp > stack_base) {
        continue;
      }

      // traversing stack frames
      while (rbp != NULL) {
        // check whether RBP is valid
        if (rbp <= prbp || rbp > stack_base) {
          break;
        }

        // check whether stack has been modified and fetch data
        barrier();
        if (is_stack_modified(fsbase, slock, slock2)) {
          lidx = 0;
          break;
        }

        canary_and_tag = *((uint64_t *)(rbp + 8));
        canary = (uint32_t)(canary_and_tag >> 32);
        tag = (uint32_t)(canary_and_tag & 0xffffffff);
        ngen = *((uint64_t *)(rbp + 16));
        rip = (char *)(*((uint64_t *)(rbp + 24)));

        // check if stack frame is valid
        if (canary != LDB_CANARY) {
          break;
        }

        // all check passed!
        // store frame info to locals
        temp_tag[lidx] = tag;
        temp_ngen[lidx] = ngen;
        temp_rip[lidx] = rip;
        temp_rbp[lidx] = rbp;

        // go up for next frame
        barrier();
        if(is_stack_modified(fsbase, slock, slock2)) {
          lidx = 0;
          break;
        }

        prbp = rbp;
        rbp = (char *)(*((uint64_t *)rbp));
        lidx++;
      }

      // No data collected
      if (lidx == 0) {
        continue;
      }

      // Update latency
      int gidx = 0;

      while (gidx < ldb_cnt[tidx] && ldb_rbp[tidx][gidx] > temp_rbp[lidx-1]) {
        ldb_latency[tidx][gidx] += elapsed;
        gidx++;
      }

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

      // Record finished function call
      for (int i = gidx; i < ldb_cnt[tidx]; ++i) {
        event_record(ebuf, LDB_EVENT_STACK, now, thread_id, ldb_latency[tidx][i],
            (uintptr_t)ldb_rip[tidx][i], ldb_ngen[tidx][i]);
      }

      // Add new nodes
      while (lidx > 0) {
        ldb_tag[tidx][gidx] = temp_tag[lidx - 1];
        ldb_ngen[tidx][gidx] = temp_ngen[lidx - 1];
        ldb_latency[tidx][gidx] = 0;
        ldb_rip[tidx][gidx] = temp_rip[lidx - 1];
        ldb_rbp[tidx][gidx] = temp_rbp[lidx - 1];

        gidx++;
        lidx--;
      }

      if (gidx > LDB_MAX_CALLDEPTH) {
        printf("[WARNING] gidx overflow: %d\n", gidx);
      }

      ldb_cnt[tidx] = gidx;
      *last_ts = now;
    } // for
#if LDB_MONITOR_PERIOD > 0
    barrier();
    clock_gettime(CLOCK_MONOTONIC_RAW, &scan_finish);
    barrier();
    scan_delay = (scan_finish.tv_sec - scan_start.tv_sec) * 1000000;
    scan_delay += (scan_finish.tv_nsec - scan_start.tv_nsec);

    if (scan_delay < LDB_MONITOR_PERIOD * 1000) {
      __time_delay_ns(LDB_MONITOR_PERIOD * 1000 - scan_delay);
    }
#endif
  } // while true

  for (int i = 0; i < LDB_MAX_NTHREAD; i++) {
    free(ldb_tag[i]);
    free(ldb_ngen[i]);
    free(ldb_rip[i]);
    free(ldb_rbp[i]);
    free(ldb_latency[i]);
  }

  free(ldb_tag);
  free(ldb_ngen);
  free(ldb_rip);
  free(ldb_rbp);
  free(ldb_latency);
  free(ldb_cnt);

  printf("Monitoring thread exiting...\n");

  return NULL;
}
