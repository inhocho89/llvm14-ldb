#define _GNU_SOURCE
#include <time.h>
#include "common.h"

#define LDB_MONITOR_PERIOD 0

extern ldb_shmseg *ldb_shared;
extern bool running;

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

static void clock_get_now(struct timespec *ts) {
  barrier();
  clock_gettime(CLOCK_MONOTONIC_RAW, ts);
  barrier();
}

static uint64_t elapsed_ns(struct timespec *start, struct timespec *end) {
  return (end->tv_sec - start->tv_sec) * 1000000000 +
	 (end->tv_nsec - start->tv_nsec);
}

struct tls_shared_region {
  uint64_t gen;
  char pad[56];
  uint64_t rbp;
};

struct stack_sample {
  uint64_t rip;
  uint64_t rbp;
  uint64_t gen;
  struct timespec start_ts;
};

struct thread {
  ldb_event_buffer_t *ebuf;
  pid_t thread_id;
  bool last_ts_set;
  int cnt;
  uint64_t last_gen;
  uint64_t *stack_base;
  struct timespec last_ts; 
  struct tls_shared_region *tls;
  struct stack_sample samples[LDB_MAX_CALLDEPTH];
};

static int scan_stack(struct thread *th, uint64_t *rbp, struct stack_sample *sarr) {
  uint64_t *top = rbp - 1;
  int frames = 0;

  // Heuristic: If start rbp is not valid, skip this iteration
  if (rbp <= (uint64_t *)0x7f0000000000 || rbp > th->stack_base)
    return -1;

  while (rbp) {
    // check for invalid base pointers
    if (rbp <= top || rbp > th->stack_base) {
      return -1; 
    }

    uint64_t canary_and_tag = *(rbp + 1);
    uint32_t canary = (uint32_t)(canary_and_tag >> 32);
    if (canary != LDB_CANARY) {
      return -1;
    }
    sarr->gen = *(rbp + 2);
    sarr->rip = *(rbp + 3);
    sarr->rbp = (uint64_t)rbp;
    sarr++;
    frames++;

    if (frames > LDB_MAX_CALLDEPTH) {
      printf("[WARNING] max call depth exceeded\n");
      return -1;
    }

    rbp = (uint64_t *)*rbp;
  }

  return frames;
}

static void
emit_stack_samples(struct thread *th, struct stack_sample *samples,
		   int pos, struct timespec now) {
  uint64_t latency;
  int i;

  for (i = 0; i < th->cnt; i++) {
    struct stack_sample *s = &th->samples[i];
    if (pos >= 1 && s->gen == samples[--pos].gen) {
      if (pos >= 0 && s->rbp != samples[pos].rbp) {
        printf("oops rbp %lx %lx rip %lx %lx\n", s->rbp, samples[pos].rbp, s->rip, samples[pos].rip);
      }
      
      continue;
    }

    latency = elapsed_ns(&s->start_ts, &now);
    event_record(th->ebuf, LDB_EVENT_STACK, now, th->thread_id,
                 latency, s->rip, s->gen);
    //printf("gen %ld id %d rip %lx latency %ld\n", s->gen, th->thread_id, s->rip, latency);
  }
}

static void scan_thread(struct thread *th) {
  struct stack_sample tmp[LDB_MAX_CALLDEPTH];
  struct timespec now;
  int frames, i;

  // Skip if a modification wasn't detected (to avoid probe effects)
  uint64_t gen = ACCESS_ONCE(th->tls->gen);
  uint64_t rbp = ACCESS_ONCE(th->tls->rbp);
  if (gen == th->last_gen) {
    return;
  }

  // Get the current time
  clock_get_now(&now);

  // Scan the stack and gather frames 
  frames = scan_stack(th, (uint64_t *)rbp, tmp);
  uint64_t end_gen = ACCESS_ONCE(th->tls->gen);
  uint64_t end_rbp = ACCESS_ONCE(th->tls->rbp);
  if (frames < 0 || end_gen != gen || end_rbp != rbp) {
    if (!th->last_ts_set) {
      th->last_ts_set = true;
      th->last_ts = now;
    }
    return;
  }
  th->last_gen = gen;

  // Emit stack samples
  if (!th->last_ts_set)
    th->last_ts = now;
  emit_stack_samples(th, tmp, frames, th->last_ts);
  th->last_ts_set = false;

  // Store frames (in reverse so top is first) for next comparison
  for (i = 0; i < frames; i++) {
    //printf("i %d rbp %lx rip %lx\n", i, th->samples[i].rbp, th->samples[i].rip); 
    //printf("i %d rbp %lx rip %lx\n", i, tmp[frames - i - 1].rbp, tmp[frames - i - 1].rip);
    th->samples[i].rip = tmp[frames - i - 1].rip;
    th->samples[i].rbp = tmp[frames - i - 1].rbp;

    // don't update the time if the frame hasn't changed
    if (tmp[frames - i - 1].gen == th->samples[i].gen)
      continue;
    th->samples[i].gen = tmp[frames - i - 1].gen;
    th->samples[i].start_ts = now;
  }
  th->cnt = frames;
}

void *monitor_main(void *arg) {
  int i;
#if LDB_MONITOR_PERIOD > 0
  struct timespec scan_start;
  struct timespec scan_finish;
  uint64_t scan_delay;
#endif

  // Pin to core 0
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

  // allocate per-thread memory
  struct thread *threads = calloc(sizeof(*threads), LDB_MAX_NTHREAD);
  ldb_event_buffer_t *ebuf = ldb_shared->ldb_thread_infos[get_thread_info_idx()].ebuf;
  for (i = 0; i < LDB_MAX_NTHREAD; i++) {
    struct thread *th = &threads[i];
    th->ebuf = ebuf;
  }

  printf("Monitor v2 thread starts. monitoring period = %d us\n", LDB_MONITOR_PERIOD);
  while (running) {
#if LDB_MONITOR_PERIOD > 0
    clock_get_now(&scan_start);
#endif
    for (i = 0; i < LDB_MAX_NTHREAD; i++) {
      struct thread *th = &threads[i];
      if (ldb_shared->ldb_thread_infos[i].id == 0)
        continue;

      // initialize per-thread state
      th->thread_id = ldb_shared->ldb_thread_infos[i].id;
      uint64_t *tmp = (uint64_t *)ldb_shared->ldb_thread_infos[i].fsbase;
      th->tls = (struct tls_shared_region *)(tmp - 43);
      th->stack_base = (uint64_t *)ldb_shared->ldb_thread_infos[i].stackbase;

      // scan the thread's stack
      scan_thread(th);
    }
#if LDB_MONITOR_PERIOD > 0
    clock_get_now(&scan_finish);
    scan_delay = elapsed_ns(&scan_start, &scan_finish);
    if (scan_delay < LDB_MONITOR_PERIOD) {
      __time_delay_ns(LDB_MONITOR_PERIOD * 1000 - scan_delay);
    }
#endif
  }

  printf("Monitoring thread exiting...\n");

  return NULL;
}
