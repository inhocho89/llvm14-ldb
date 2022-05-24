#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#define WORKER_BUF_SIZE 3200
#define WORKER_STRIDE 64
#define WORKER_ITER_PER_US 2380
#define WORKER_US 1
#define CYCLES_PER_US 2992
#define NSAMPLE 1000
#define NEST_LEVEL 0

char buf[WORKER_BUF_SIZE];

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

__attribute__((noinline)) void nested_worker(int level) {
  if (level == 0) {
    __time_delay_us(WORKER_US);
//    for (uint64_t i = 0; i < WORKER_US * WORKER_ITER_PER_US; ++i) {
//	    volatile char c = buf[(WORKER_STRIDE * i) % WORKER_BUF_SIZE];
//    }
  } else {
    nested_worker(level-1);
  }
}

void *worker(void *arg)
{
  uint64_t start, end;
  double avg;
  double total;

  // pre-run
  for (int i = 0; i < 10; i++) {
    nested_worker(0);
  }

  start = rdtsc();
  for (int i = 0; i < NSAMPLE; i++) {
    nested_worker(NEST_LEVEL);
  }
  end = rdtsc();

  total = (double)(end - start)/CYCLES_PER_US;
  avg = total/NSAMPLE;
  printf("%d,%lf,%lf\n", NEST_LEVEL, total, avg);

  return NULL;
}

int main(int argc, char* argv[])
{
  pthread_t tid;
  int err = pthread_create(&tid, NULL, &worker, NULL);

  err = pthread_join(tid, NULL);

  return 0;
}
