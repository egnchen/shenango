/* definitions for bpf part */
#pragma once

// most of this are copied from defs.h
// TODO maintain one unified copy
#ifndef SHENANGO_RUNTIME_GLOBAL_DEFS
/**
 * struct list_node - an entry in a doubly-linked list
 * @next: next entry (self if empty)
 * @prev: previous entry (self if empty)
 *
 * This is used as an entry in a linked list.
 * Example:
 *	struct child {
 *		const char *name;
 *		// Linked list of all us children.
 *		struct list_node list;
 *	};
 */
struct list_node
{
	struct list_node *next, *prev;
};

struct thread;

typedef unsigned long long uint64_t;

struct thread_tf {
	/* argument registers, can be clobbered by callee */
	uint64_t rdi; /* first argument */
	uint64_t rsi;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;

	/* callee-saved registers */
	uint64_t rbx;
	uint64_t rbp;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;

	/* special-purpose registers */
	uint64_t rax;	/* holds return value */
	uint64_t rip;	/* instruction pointer */
	uint64_t rsp;	/* stack pointer */
};

#define ARG0(tf)        ((tf)->rdi)
#define ARG1(tf)        ((tf)->rsi)
#define ARG2(tf)        ((tf)->rdx)
#define ARG3(tf)        ((tf)->rcx)
#define ARG4(tf)        ((tf)->r8)
#define ARG5(tf)        ((tf)->r9)

/*
 * Thread support
 */

enum {
	THREAD_STATE_RUNNING = 0,
	THREAD_STATE_RUNNABLE,
	THREAD_STATE_SLEEPING,
};

enum {
	THREAD_TYPE_DEFAULT = 0,
	THREAD_TYPE_MAIN = 1,
	THREAD_TYPE_SWAP = 2,
};

struct stack;

struct thread {
	struct thread_tf	tf;
	struct list_node	link;
	struct stack		*stack;
	unsigned int		typ;
	unsigned int		return_from_kernel;
	unsigned int		state;
	unsigned int		stack_busy;
	struct thread *		pf_handle_thread;
	void *				fault_addr;
};
#endif

struct thread_bpf_ctx {
	struct thread **current_thread_ptr;
	unsigned int *preempt_cnt_ptr;
	void *runtime_stack;
	void *runtime_fn;
};

// per-process bpf configuration
struct process_bpf_ctx {
	// cache region
	// pages within this range will be handled by kernel whatsoever
	void *cache_start;
	uint64_t cache_len;
};