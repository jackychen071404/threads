#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/time.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include "threads.h"
#include "ec440projects.h"
#define MAX_THREADS 128
#define STACK_SIZE 32767
#define JB_RBX 0
#define JB_RBP 1
#define JB_R12 2
#define JB_R13 3
#define JB_R14 4
#define JB_R15 5
#define JB_RSP 6
#define JB_PC 7
/*typedef enum {
  THREAD_RUN,
  THREAD_READY,
  THREAD_EXIT
} thread_state;

typedef struct {
  int id;
  thread_state state;
  void *stack_ptr;
  //unsigned int registers[8];
  jmp_buf env;
  } TCB;*/
int current_tid = 0;
TCB threads_table[MAX_THREADS];
jmp_buf main_env;
int no_threads = 1;

pthread_t pthread_self(void) {
  return current_tid;
}

void alarm_handler(int signum) {
  //printf("Timer fired! Signal number: %d\n", signum);
  schedule();
}

void pthread_exit(void *value_ptr) {
  printf("Thread exited\n");
  threads_table[current_tid].state = THREAD_EXIT;
  free(threads_table[current_tid].stack_ptr); //free dynamic memory
  schedule();
  exit(0);
}

void exec_start_routine(void *(*start_routine)(void *), void *arg) {
  void *return_val = start_routine(arg); //execute start_routine with arg
  pthread_exit(return_val); //call pthread_exit with the return value
}

int initialized = 0;
void timer_setup() {
  struct itimerval timer;
  timer.it_value.tv_sec = 0;
  timer.it_value.tv_usec = 50000; //50000
  timer.it_interval.tv_sec = 0;
  timer.it_interval.tv_usec = 50000; //50000

  if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
    perror("setitimer failure");
    exit(EXIT_FAILURE);
  } else {
    //printf("Timer setup complete.\n");
  }
}

void signal_handler() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa)); //zero out the memory of struct sa
  sa.sa_handler = alarm_handler;
  sa.sa_flags = SA_NODEFER; //re-entry signal handling

  if (sigaction(SIGALRM, &sa, NULL) == -1) {
        perror("sigaction error");
        exit(EXIT_FAILURE);
    }  else {
    //printf("Signal handler setup complete.\n");
  }

  sigset_t sigset;
  sigprocmask(SIG_BLOCK, NULL, &sigset); // check the current signal mask
  if (sigismember(&sigset, SIGALRM)) {
    printf("SIGALRM is blocked!\n");
  } else {
    printf("SIGALRM is not blocked.\n");
  }
}

/*void set_main_context(jmp_buf env, void **stack_ptr, void *start_thunk, void *start_routine, void *arg) {
    env->__jmpbuf[2] = (unsigned long int)start_routine;
    env->__jmpbuf[3] = (unsigned long int)arg;
}*/

/*void set_thread_context(jmp_buf env, void **stack_ptr, void *start_thunk, void *start_routine, void *arg) {
    env[0].__jmpbuf[6] = ptr_mangle((unsigned long int)stack_ptr);  //set JB_RSP (stack pointer) with the mangled value
    env[0].__jmpbuf[7] = ptr_mangle((unsigned long int)start_thunk); //set the JB_PC (program counter) to point to start_thunk
    env[0].__jmpbuf[2] = (unsigned long int)start_routine;
    env[0].__jmpbuf[3] = (unsigned long int)arg;
}*/

void init_threads(void *(*start_routine) (void *), void *arg) {
  int i;
  for (i = 0; i < MAX_THREADS; i++) {
    threads_table[i].id = -1; // unused thread
    threads_table[i].state = THREAD_EXIT;
  }
  if (setjmp(threads_table[0].env) == 0) {
    //printf("successful setjmp to threads %d\n", 0);
  }
  threads_table[0].id = 0; // unused thread
  threads_table[0].state = THREAD_READY;
  signal_handler();
  timer_setup();
  initialized = 1;
}
//if main thread, isrunning (at end)
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg) {
  if (!initialized) {
    init_threads(start_routine, arg);
  }
  int i = 0;
  for (i = 0; i < MAX_THREADS; i++) {
    if (threads_table[i].id == -1) {
      break;
    }
  }
  if (setjmp(threads_table[i].env) == 0) {
    printf("successful setjmp to threads %d\n", i);
  }
  no_threads++;
  threads_table[i].id = i;
  *thread = i; //store ID of thread in location reference (arg *thread)
  threads_table[i].state = THREAD_READY;
  //current_tid = i;

  threads_table[i].stack_ptr = malloc(STACK_SIZE);
  void *stack_top = threads_table[i].stack_ptr + STACK_SIZE;
  stack_top -= 8; //move stack pointer down
  unsigned long int *new_stack_top = (unsigned long int *)stack_top;
  *new_stack_top = (unsigned long int)pthread_exit;

  threads_table[i].env->__jmpbuf[JB_RSP] = ptr_mangle((unsigned long int)new_stack_top);  //set JB_RSP (stack pointer) with the mangled value
  threads_table[i].env->__jmpbuf[JB_PC] = ptr_mangle((unsigned long int)start_thunk); //set the JB_PC (program counter) to point to start_thunk
  threads_table[i].env->__jmpbuf[JB_R12] = (unsigned long int)start_routine;
  threads_table[i].env->__jmpbuf[JB_R13] = (unsigned long int)arg;
  if (threads_table[0].state == THREAD_RUN) current_tid = 0;
  //longjmp(threads_table[i].env, 1);
  return current_tid;
}

void schedule() {
  int prev_tid = current_tid; //check before schedule new tid
  //int future_tid = threads_table[current_tid+1].id;
  if (prev_tid != -1 && threads_table[prev_tid].state == THREAD_RUN) {
    threads_table[prev_tid].state = THREAD_READY;
  }
  //printf("Current thread: %d\n", current_tid);

  int future_tid = threads_table[current_tid+1].id;
  int i;
  for (i = 0; i < MAX_THREADS; i++) {
    if (threads_table[i].state == THREAD_READY) {
      int next_tid = (current_tid + 1) % no_threads;
      while (threads_table[next_tid].state== THREAD_EXIT) {
        next_tid = (next_tid + 1) % no_threads;
}
      future_tid = next_tid;
        }
  }

  threads_table[future_tid].state = THREAD_READY;
  //printf("Next thread is %d\n", future_tid);
  //printf("Number of threads: %d\n", no_threads);

  if (threads_table[future_tid].state == THREAD_READY) {
    threads_table[future_tid].state = THREAD_RUN;
    current_tid = future_tid;
  }
  if (setjmp(threads_table[prev_tid].env) == 0) {
    //printf("wheres the longjmp? To thread %d\n", future_tid);
    //printf("wheres the initialze %d\n", initialized);
    longjmp(threads_table[future_tid].env, 1); // Switch to the future thread's context
    return;
  }
  //longjmp(threads_table[future_tid].env, 1); // Switch to the future thread's context
}
