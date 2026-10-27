#include <atomic>
#include <cstdio>
#include <thread>

std::atomic<unsigned> ready{0};
std::atomic<bool> start{false};

void thread_func(unsigned index) {
  ++ready;
  while (!start.load())
    std::this_thread::yield();
  printf("thread %u\n", index); // Set break point at this line.
}

int main() {
  start = false; // And that line.
  std::thread thread1(thread_func, 1);
  std::thread thread2(thread_func, 2);
  std::thread thread3(thread_func, 3);
  while (ready.load() != 3)
    std::this_thread::yield();
  start = true;
  thread1.join();
  thread2.join();
  thread3.join();
}
