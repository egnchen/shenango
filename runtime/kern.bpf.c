#include <vmlinux.h>
#include "bpf_defs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define assert(expr) do { \
  if(!(expr)) { \
    bpf_printk("Assertion \"%s\"(%s:%d) failed.", #expr, __FUNCTION__, __LINE__); \
    return 0; \
  } \
} while(0);

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, struct thread_bpf_ctx);
} thread_ctx_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, struct process_bpf_ctx);
} process_ctx_map SEC(".maps");

static inline int return_to_userspace_handler(struct pt_regs *ctx, __u64 id, unsigned long address,
  struct thread_bpf_ctx *thread_ctx, struct pt_regs *local_ctx, struct pt_regs *regs)
{
  struct thread *th = NULL;
  struct thread_tf tf;
  unsigned int preempt_cnt;
  unsigned int thread_type;

  assert(thread_ctx->current_thread_ptr);
  assert(bpf_probe_read_user(&th, sizeof(struct thread *), thread_ctx->current_thread_ptr) == 0);
  assert(th);
  
  // only hook when preemption is enabled
  // this will avoid hooking libOS code
  assert(bpf_probe_read_user(&preempt_cnt, sizeof(preempt_cnt), thread_ctx->preempt_cnt_ptr) == 0);
  if((preempt_cnt & ~(1u << 31)) != 0) {
    bpf_printk("preemption not enabled, ignored.");
    return 0;
  }

  // don't hook on swap threads
  assert(bpf_probe_read_user(&thread_type, sizeof(thread_type), &th->typ) == 0);
  if(thread_type == THREAD_TYPE_SWAP) {
    bpf_printk("swap thread detected, ignored.");
    return 0;
  }
  
  // don't hook on swap routine
  
  // save current thread context to trampoline & write to userspace
  tf.rdi = local_ctx->di;
  tf.rsi = local_ctx->si;
  tf.rdx = local_ctx->dx;
  tf.rcx = local_ctx->cx;
  tf.r8 = local_ctx->r8;
  tf.r9 = local_ctx->r9;
  tf.r10 = local_ctx->r10;
  tf.r11 = local_ctx->r11;

  tf.rbx = local_ctx->bx;
  tf.rbp = local_ctx->bp;
  tf.r12 = local_ctx->r12;
  tf.r13 = local_ctx->r13;
  tf.r14 = local_ctx->r14;
  tf.r15 = local_ctx->r15;

  tf.rax = local_ctx->ax;
  tf.rip = local_ctx->ip;
  tf.rsp = local_ctx->sp;

  // bpf_printk("Page fault triggered:\n\tip 0x%lx addr 0x%lx th 0x%lx", local_ctx.ip, address, th);
  // bpf_printk("New rip will be %llx", tf.rip);

  // disable preemption
  preempt_cnt += 1;
  assert(bpf_probe_write_user(thread_ctx->preempt_cnt_ptr, &preempt_cnt, sizeof(preempt_cnt)) == 0);

  // save user thread context
  assert(bpf_probe_write_user(&th->tf, &tf, sizeof(struct thread_tf)) == 0);
  
  // set return-from-kernel flag
  const unsigned int return_from_kernel = 1;
  assert(bpf_probe_write_user(&th->return_from_kernel, &return_from_kernel, sizeof(return_from_kernel)) == 0);

  // set fault address
  assert(bpf_probe_write_user(&th->fault_addr, &address, sizeof(address)) == 0);
  
  bpf_printk("Before override, ip %lx, sp %lx, bp %lx", local_ctx->ip, local_ctx->sp, local_ctx->bp);
  // jump to runtime function and runtime stack
  local_ctx->sp = (unsigned long)thread_ctx->runtime_stack;
  local_ctx->ip = (unsigned long)thread_ctx->runtime_fn;
  local_ctx->bp = 0UL; // just in case base pointers are enabled
  assert(bpf_override_regs(regs, local_ctx) == 0);
  
  // we're done
  bpf_printk("After override,  ip %lx, sp %lx, bp %lx", local_ctx->ip, local_ctx->sp, local_ctx->bp);
  bpf_override_return(ctx, 0);
  return 0;
}

SEC("kprobe/handle_mm_fault")
int handle_userspace_pf_mmfault(struct pt_regs *ctx)
{
  struct vm_area_struct *vma = PT_REGS_PARM1(ctx);
  unsigned long address = PT_REGS_PARM2(ctx);
  unsigned int flags = PT_REGS_PARM3(ctx);
  struct pt_regs *regs = PT_REGS_PARM4(ctx);
  struct pt_regs local_ctx;

  __u64 id = bpf_get_current_pid_tgid();
  struct thread_bpf_ctx *thread_ctx = bpf_map_lookup_elem(&thread_ctx_map, &id);
  if(!thread_ctx) {
    // not registered
    return 0;
  }

  assert(vma);

  const struct vm_operations_struct *ops = NULL;
  assert(bpf_probe_read_kernel(&ops, sizeof(ops), &vma->vm_ops) == 0);

  assert(regs);
  assert(bpf_probe_read_kernel(&local_ctx, sizeof(struct pt_regs), regs) == 0);

  bpf_printk("encountered page fault %lx, ip %lx, sp %lx", address, local_ctx.ip, local_ctx.sp);
  if(ops == NULL) {
    // this is an anonymous page
    return return_to_userspace_handler(ctx, id, address, thread_ctx, &local_ctx, regs);
  }
  return 0;
}

SEC("kprobe/handle_page_fault_ebpf")
int handle_userspace_pf(struct pt_regs *ctx)
{
  // parameters
  struct pt_regs *regs = PT_REGS_PARM1(ctx);
  unsigned long address = PT_REGS_PARM3(ctx);
  struct pt_regs local_ctx;

  __u64 id = bpf_get_current_pid_tgid();
  struct thread_bpf_ctx *thread_ctx = bpf_map_lookup_elem(&thread_ctx_map, &id);
  if(!thread_ctx) {
    return 0;
  }
  assert(regs);
  assert(bpf_probe_read_kernel(&local_ctx, sizeof(struct pt_regs), regs) == 0);
  return return_to_userspace_handler(ctx, id, address, thread_ctx, &local_ctx, regs);
}
