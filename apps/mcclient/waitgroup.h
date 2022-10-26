#ifndef WAITGROUP_
#define WAITGROUP_

#include <condition_variable>
#include <mutex>
#include <atomic>
#include <thread>

class WaitGroup {
 public:
  void Add(int i = 1);
  void Done();
  void Wait();

 private:
  std::mutex mu_;
  std::atomic<int> counter_;
  std::condition_variable cv_;
};

#endif // WAITGROUP_
