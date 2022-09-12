#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "base/thread.h"
#include "defs.h"
#include "bpf_defs.h"
#include <base/log.h>
#include <runtime/thread.h>

static struct bpf_link *blink;
static struct bpf_program *bprog;
static struct bpf_object *bobj;
static struct bpf_map *default_ctx_map;

extern __thread thread_t *__self;
extern __thread void *runtime_stack;
extern void thread_finish_yield_kthread(void);

/**
 * register current process to bpf map
 */
int bpf_init_thread() {
  struct thread_bpf_ctx ctx = {
    .current_thread_ptr = &__self,
    .runtime_stack = runtime_stack,
    .runtime_fn = thread_finish_yield_kthread
  };
  __u64 key = ((__u64)getpid() << 32) | gettid();
  if(bpf_map__update_elem(default_ctx_map, &key, sizeof(key), &ctx, sizeof(ctx), BPF_ANY)) {
    fprintf(stderr, "ERROR: cannot update default_ctx map\n");
    return -1;
  }
	printf("Registered %llu -> %p\n", key, ctx.current_thread_ptr);
  return 0;
}

int bpf_init() {
  bobj = bpf_object__open_file("runtime/kern.bpf.o", NULL);
  if (libbpf_get_error(bobj)) {
    fprintf(stderr, "ERROR: opening BPF object file failed\n");
    return -1;
  }

  bprog = bpf_object__find_program_by_name(bobj, "handle_userspace_pf");
  if (!bprog) {
    fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
    return -1;
  }

  /* load BPF program */
  if (bpf_object__load(bobj)) {
    fprintf(stderr, "ERROR: loading BPF object file failed\n");
    return -1;
  }

  blink = bpf_program__attach(bprog);
  if (libbpf_get_error(blink)) {
    fprintf(stderr, "ERROR: bpf_program__attach failed\n");
    blink = NULL;
    return -1;
  }

  default_ctx_map = bpf_object__find_map_by_name(bobj, "default_ctx");
  if(!default_ctx_map) {
    fprintf(stderr, "ERROR: failed to get default context map\n");
    return -1;
  }
  log_info("Successfully installed bpf program");
  
  return 0;
}