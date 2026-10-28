#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static unsigned int g_timeout = 1000000;

extern int usleep(unsigned int);

int function_to_call() {

  while (1) {
    int result = usleep(g_timeout);
    // A successful retry need not clear errno from an interrupted sleep.
    if (result != -1 || errno != EINTR)
      break;
  }

  pthread_exit((void *)10);

  return 20; // Prevent warning
}

int exit_process() { _exit(0); }

void *exiting_thread_func(void *unused) {
  function_to_call(); // Break here and cause the thread to exit
  return NULL;
}

int main() {
  void *exit_ptr;
  pthread_t exiting_thread;

  pthread_create(&exiting_thread, NULL, exiting_thread_func, NULL);

  pthread_join(exiting_thread, &exit_ptr);
  int ret_val = (int)exit_ptr; // Stop after joining the expression thread
  return ret_val;        // Break here to make sure the thread exited.
}
