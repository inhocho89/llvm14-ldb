#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "cpu.h"
#include "../../libldb/ldb_tag.h"

#define WORKER_US 10
#define NSAMPLE 10000
#define NEST_LEVEL 5
#define NPARA 10

__attribute__((noinline)) void nested_worker(int level) {
  int r = rand();
  if (level == 0) {
    if (r % 100 < 1) {
      __time_delay_us(10*WORKER_US);
    } else {
      __time_delay_us(WORKER_US);
    }
  } else {
    nested_worker(level-1);
  }
}

void *worker_main(void *arg) {
  srand(time(NULL));
  for (int i = 0; i < NSAMPLE; i++) {
    nested_worker(NEST_LEVEL);
  }

  return nullptr;
}

int main(int argc, char* argv[])
{
  pthread_t tid[NPARA];
  int err;

  for (int i = 0; i < NPARA; ++i) {
    err = pthread_create(&tid[i], nullptr, &worker_main, NULL);
  }

  for (int i = 0; i < NPARA; ++i) {
    err = pthread_join(tid[i], NULL);
  }

  return 0;
}
