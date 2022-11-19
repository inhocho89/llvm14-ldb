#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "cpu.h"

extern "C" {
#include "ldb/tag.h"
}

#define WORKER_US 10
#define NSAMPLE 10000
#define NEST_LEVEL 5

__attribute__((noinline)) void nested_worker(int level) {
  if (level == 0) {
    __time_delay_us(WORKER_US);
//  usleep(0);
  } else {
    nested_worker(level-1);
  }
}

int main(int argc, char* argv[])
{
  for (int i = 0; i < NSAMPLE; i++) {
    ldb_tag_add(i+1);
    nested_worker(NEST_LEVEL);
    ldb_tag_clear();
  }

  return 0;
}
