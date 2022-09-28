#include <sys/mman.h>
#include <stdio.h>

#include <base/log.h>
#include <runtime/preempt.h>

#include "defs.h"
#include "runtime/thread.h"

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

#define PAGE_SIZE 4096
#define PAGE_ALIGN(addr) (void *)((uint64_t)(addr) & ~(PAGE_SIZE - 1))

void *swap_start;
const uint64_t swap_len = 4 * MB;
uint64_t cache_off = 0;

uint64_t stat_time;
int stat_cnt;

extern __thread uint64_t last_tsc;
extern __noreturn void schedule();
extern void enter_schedule(thread_t *);

static inline void *do_mremap(void *old_addr, void *new_addr) {
  uint64_t start_t = rdtsc();
  void *ret = mremap(old_addr, PAGE_SIZE, PAGE_SIZE,
             MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, new_addr);
  stat_time += rdtsc() - start_t;
  stat_cnt++;
  return ret;
}

void pf_handle_routine(thread_t *fault_thread) {
  thread_t *self = thread_self();
  for(;;) {
    void *fault_addr = fault_thread->fault_addr;
    if(fault_addr) {
      // log_info("%p: handling pf @%p for %p", thread_self(), fault_thread->fault_addr, fault_thread);
      fault_addr = (void *)((uint64_t)fault_addr & ~(PAGE_SIZE - 1));
      uint64_t cur_off = cache_off;
      cache_off += PAGE_SIZE;
      if (cache_off >= swap_len) {
        cache_off = 0;
      }
      // fill page with random, but unique content
      memset(swap_start + cur_off, 'A' + (cur_off % 26), PAGE_SIZE);
      void *new_addr = do_mremap(swap_start + cur_off, fault_addr);
      BUG_ON(new_addr == MAP_FAILED);
      // log_debug("mapped page %p", fault_addr);
      fault_thread->fault_addr = NULL;
    }
    // make self runnable **until next PF**
    
    /* check for softirqs */
    softirq_run(RUNTIME_SOFTIRQ_BUDGET);

    preempt_disable();
    assert(self->state == THREAD_STATE_RUNNING);
    self->state = THREAD_STATE_SLEEPING;
    store_release(&self->stack_busy, true);
    // should be put here, or racing condition might occur!
    if(fault_addr) {
      thread_ready(fault_thread);
    }
    enter_schedule(self);
  }
}

void return_from_ebpf_kthread(void)
{
	thread_t *myth = thread_self();
  struct kthread *k = myk();

  assert_preempt_disabled();
  assert(myth->return_from_kernel);
  assert(myth->fault_addr);
  // log_debug("%p pf @%p, ip=%p", myth, myth->fault_addr, (void *)myth->tf.rip);
  // print_trampoline(myth);

	assert(myth->state == THREAD_STATE_RUNNING);
	myth->state = THREAD_STATE_SLEEPING;

  __sync_fetch_and_add(&STAT(SWITCH_COUNT_EBPF), 1);
  
  // spawn and schedule swap routine thread
  if(unlikely(myth->pf_handle_thread == NULL)) {
    thread_t *pf_handle_thread = thread_create((thread_fn_t)pf_handle_routine, myth);
    BUG_ON(pf_handle_thread == NULL);
    pf_handle_thread->typ = THREAD_TYPE_SWAP;
    log_debug("spawned thread %p for swap routine", pf_handle_thread);
    myth->pf_handle_thread = pf_handle_thread;
  }
  thread_ready(myth->pf_handle_thread);

  last_tsc = rdtsc();
  spin_lock(&k->lock);
  schedule();
}

int swap_init_thread()
{
  // nothing to do really
  return 0;
}

int swap_init()
{
  swap_start = mmap(NULL, swap_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  BUG_ON(swap_start == MAP_FAILED);
  log_debug("Swap region returned by mmap: %p\n", swap_start);
  return 0;
}