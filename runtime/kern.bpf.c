#include <vmlinux.h>
#include "bpf_defs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, struct thread_bpf_ctx);
} default_ctx SEC(".maps");

#define CHECK(exp, msg) if(!(exp)) { bpf_printk(msg "\n"); return 0; }

SEC("kprobe/handle_page_fault_ebpf")
int handle_userspace_pf(struct pt_regs *ctx) {
  // parameters
  struct pt_regs *regs = PT_REGS_PARM1(ctx);
  unsigned long error_code = PT_REGS_PARM2(ctx);
  unsigned long address = PT_REGS_PARM3(ctx);

  __u64 id = bpf_get_current_pid_tgid();
  struct thread_bpf_ctx *thread_ctx = bpf_map_lookup_elem(&default_ctx, &id);
  struct thread *th = NULL;
  struct thread_tf tf;
  struct pt_regs local_ctx;
  if(!thread_ctx) {
    return 0;
  }
  bpf_printk("Handling page fault for id %llu @ %p\n", id, address);
  
  CHECK(thread_ctx->current_thread_ptr, "Current thread pointer is null");
  CHECK(!bpf_probe_read_user(&th, sizeof(struct thread *), thread_ctx->current_thread_ptr),
    "Failed to read current thread pointer");

  // save current thread context to trampoline & write to userspace
  CHECK(regs, "No registers available");
  CHECK(!bpf_probe_read_kernel(&local_ctx, sizeof(struct pt_regs), regs),
    "Failed to read kernel registers");
  tf.rdi = local_ctx.di;
  tf.rsi = local_ctx.si;
  tf.rdx = local_ctx.dx;
  tf.rcx = local_ctx.cx;
  tf.r8 = local_ctx.r8;
  tf.r9 = local_ctx.r9;
  tf.r10 = local_ctx.r10;
  tf.r11 = local_ctx.r11;

  tf.rbx = local_ctx.bx;
  tf.rbp = local_ctx.bp;
  tf.r12 = local_ctx.r12;
  tf.r13 = local_ctx.r13;
  tf.r14 = local_ctx.r14;
  tf.r15 = local_ctx.r15;

  tf.rax = local_ctx.ax;
  tf.rip = local_ctx.ip;
  tf.rsp = local_ctx.sp;

  CHECK(th, "Invalid thread context");
  CHECK(!bpf_probe_write_user(&th->tf, &tf, sizeof(struct thread_tf)),
    "Failed to save user thread context");

  // jump to runtime function and runtime stack
  local_ctx.sp = thread_ctx->runtime_stack;
  local_ctx.ip = thread_ctx->runtime_fn;
  CHECK(bpf_override_regs(regs, &local_ctx) == 0, "Failed to override kernel trapframe");
  bpf_printk("Overriding return, going back to %p, stack %p\n", local_ctx.ip, local_ctx.sp);
  bpf_override_return(ctx, 0);
  
  return 0;
}
