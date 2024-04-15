extern "C" {
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include "ldb/tag.h"
}

#include <atomic>
#include <algorithm>
#include <thread>
#include <mutex>
#include <numeric>
#include <vector>
#include <map>
#include <fstream>

#include <cstdint>
#include <errno.h>
#include <sys/time.h>

static unsigned int g_seed;

static inline void fast_srand(int seed) {
  g_seed = seed;
}

static inline int fast_rand(void) {
  g_seed = (214013*g_seed+2531011);
  return (g_seed>>16)&0x7FFF;
}

std::string generate_random_string() {
  // Generate a random length between 1 and 1000 characters
  int length = fast_rand() % 1000 + 1;

  // Generate a random string of the given length
  std::string random_string;
  const std::string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  for (int i = 0; i < length; ++i) {
    int index = fast_rand() % alphabet.length();
    random_string += alphabet[index];
  }

  return random_string;
}

std::mutex lock;
std::map<int, std::string> db;
static std::atomic<bool> stop;

void __attribute__ ((noinline)) snapshot() {
  std::ofstream out("snapshot.txt");
  std::lock_guard<std::mutex> g(lock);
  for (const auto& kv : db) {
    out << kv.first << " = " << kv.second << std::endl;
  }
  out.close();
}

void background_thread() {
  while (!stop) {
    snapshot();
    usleep(10000); // sleep ten millisecond
  }
}

void __attribute__ ((noinline)) request_handler(int req_id, int key, std::string& value) {
    ldb_tag_set(req_id); // [optional] request tagging
    std::lock_guard<std::mutex> g(lock);
    db[key] = value;
    ldb_tag_clear(); // [optional] request tagging
}

static constexpr size_t kRounds = 200000;
static constexpr size_t dbSize = 10000;

int main(int argc, char *argv[]) {
  time_t t;
  fast_srand((int) time(&t));
  stop = false;

  std::thread bg_thread(background_thread);

  std::vector<double> samples;
  samples.reserve(kRounds);

  for (int i = 0; i < kRounds; i++) {
    int key = fast_rand() % dbSize;
    std::string value = generate_random_string();
    request_handler(i+1, key, value);
  }

  stop = true;
  bg_thread.join();

  return 0;
}

