#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>

#include "cpu.h"
#include "../../libldb/ldb_tag.h"

#define WORKER_US 10
#define NSAMPLE 10000
#define NEST_LEVEL 5

__attribute__((noinline)) void nested_worker(int level) {
  if (level == 0) {
    __time_delay_us(WORKER_US);
  } else {
    nested_worker(level-1);
  }
}

int main(int argc, char* argv[])
{

  for (int i = 0; i < NSAMPLE; i++) {
    __ldb_add_tag(i+1);
    nested_worker(NEST_LEVEL);
  }

  return 0;
}
