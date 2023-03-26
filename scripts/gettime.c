#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char *argv[]) {
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  printf("%lu.%lu\n", ts.tv_sec, ts.tv_nsec);
}
