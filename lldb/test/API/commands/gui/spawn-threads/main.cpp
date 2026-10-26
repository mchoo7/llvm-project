#include <atomic>
#include <iostream>
#include <thread>
#include <vector>

#include "pseudo_barrier.h"

pseudo_barrier_t barrier_inside;
std::atomic<int> threads_started{0};

void thread_func() {
  ++threads_started;
  pseudo_barrier_wait(barrier_inside);
}

void test_thread() {
  std::vector<std::thread> thrs;
  for (int i = 0; i < 5; i++) {
    thrs.push_back(std::thread(thread_func)); // break here
    // Thread creation can return before the new thread runs and reports its
    // debugger birth event. Wait for it before the next breakpoint, where the
    // GUI test expects the new thread to be listed.
    while (threads_started.load() != i + 1)
      std::this_thread::yield();
  }

  pseudo_barrier_wait(barrier_inside); // break before join
  for (auto &t : thrs)
    t.join();
}

int main() {
  pseudo_barrier_init(barrier_inside, 6);
  test_thread();
  return 0;
}
