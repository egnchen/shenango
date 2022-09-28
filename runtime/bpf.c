#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "base/thread.h"
#include "bpf/libbpf_legacy.h"
#include "defs.h"
#include "bpf_defs.h"
#include <base/log.h>
#include <runtime/thread.h>

static struct bpf_link *blink;
static struct bpf_program *bprog;
static struct bpf_object *bobj;
static struct bpf_map *thread_ctx_map;
static struct bpf_map *process_ctx_map;

extern __thread thread_t *__self;
extern __thread void *runtime_stack;
// extern void thread_finish_yield_kthread(void);
extern void return_from_ebpf_kthread(void);

/**
 * register current process to bpf map
 */
int bpf_init_thread() {
  struct thread_bpf_ctx ctx = {
    .current_thread_ptr = &__self,
    .preempt_cnt_ptr = &preempt_cnt,
    .runtime_stack = runtime_stack,
    .runtime_fn = return_from_ebpf_kthread,
  };
  __u64 key = ((__u64)getpid() << 32) | gettid();
  BUG_ON(bpf_map__update_elem(thread_ctx_map, &key, sizeof(key), &ctx, sizeof(ctx), BPF_ANY));
	log_info("eBPF registered %llu -> %p", key, ctx.current_thread_ptr);
  return 0;
}

int bpf_init() {
  bobj = bpf_object__open_file("runtime/kern.bpf.o", NULL);
  BUG_ON(libbpf_get_error(bobj));
  BUG_ON(bpf_object__load(bobj));
  
  bprog = bpf_object__find_program_by_name(bobj, "handle_userspace_pf_mmfault");
  BUG_ON(!bprog);

  blink = bpf_program__attach(bprog);
  BUG_ON(!blink);
  BUG_ON(libbpf_get_error(blink));

  thread_ctx_map = bpf_object__find_map_by_name(bobj, "thread_ctx_map");
  process_ctx_map = bpf_object__find_map_by_name(bobj, "process_ctx_map");
  BUG_ON(!thread_ctx_map || !process_ctx_map);

  // do per-process preparation
  struct process_bpf_ctx ctx;
  uint64_t key = getpid();
  ctx.cache_start = swap_start;
  ctx.cache_len = swap_len;
  BUG_ON(bpf_map__update_elem(process_ctx_map, &key, sizeof(key), &ctx, sizeof(ctx), BPF_ANY));
  log_info("eBPF registered process %lu", key);
  log_debug("eBPF will ignore %p(length %lx)", ctx.cache_start, ctx.cache_len);
  
  log_info("Successfully installed bpf program");
  return 0;
}