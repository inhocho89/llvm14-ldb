#include "waitgroup.h"

void WaitGroup::Add(int i) {
  counter_ += i;
}

void WaitGroup::Done() {
  counter_--;
  cv_.notify_all();
}

void WaitGroup::Wait() {
  std::unique_lock<std::mutex> l(mu_);
  cv_.wait(l, [&] { return counter_ <= 0; });
}
