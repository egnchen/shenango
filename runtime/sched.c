/*
 * sched.c - a scheduler for user-level threads
 */

#include <stdlib.h>
#include <sched.h>

#include <base/stddef.h>
#include <base/lock.h>
#include <base/list.h>
#include <base/cpu.h>
#include <base/hash.h>
#include <base/limits.h>
#include <base/tcache.h>
#include <base/slab.h>
#include <base/log.h>
#include <runtime/thread.h>

#include "defs.h"

/* the currently running thread, or NULL if in runtime code */
__thread thread_t *__self;
/* a pointer to the top of the per-kernel-thread (TLS) runtime stack */
static __thread void *runtime_stack;

/* fast allocation of struct thread */
static struct slab thread_slab;
static struct tcache *thread_tcache;
static __thread struct tcache_perthread thread_pt;

struct runqueue {
	spinlock_t		lock;
	struct list_head	runnable;
};

/* an array of cache-optimal runqueue pointers for each possible core */
static struct runqueue *core_to_q[NCPU];
/* an array of all the runqueues (for work-stealing) */
static struct runqueue *qs[NCPU];
/* the total number of runqueues (i.e. the size of @qs) */
static int nr_qs;

/**
 * call_thread - runs a thread, popping its trap frame
 * @th: the thread to run
 *
 * This function restores the state of the thread and switches from the runtime
 * stack to the thread's stack. Runtime state is not saved.
 */
static __noreturn void call_thread(thread_t *th)
{
	__self = th;
	assert(th->state == THREAD_STATE_RUNNABLE);
	th->state = THREAD_STATE_RUNNING;
	__pop_tf(&th->tf);
}

/**
 * call_runtime - saves the current trap frame and calls a function in the
 *                runtime
 * @fn: the runtime function to call
 * @arg: an argument to pass to the runtime function
 *
 * WARNING: Only threads can call this function.
 *
 * This function saves state of the running thread and switches to the runtime
 * stack, making it safe to run the thread elsewhere.
 */
static void call_runtime(runtime_fn_t fn, unsigned long arg)
{
	assert(thread_self() != NULL);
	__call_runtime(&thread_self()->tf, fn, runtime_stack, arg);
}

/**
 * call_runtime_nosave - calls a function in the runtime without saving the
 *			 trap frame
 * @fn: the runtime function to call
 * @arg: an argument to pass to the runtime function
 */
static __noreturn void call_runtime_nosave(runtime_fn_t fn, unsigned long arg)
{
	struct thread_tf tf;
	tf.rbp = (uint64_t)0; /* just in case base pointers are enabled */
	tf.rip = (uint64_t)fn;
	tf.rsp = (uint64_t)runtime_stack;
	__pop_tf(&tf);
}

static inline struct runqueue *get_my_runqueue(void)
{
	int cpu = sched_getcpu();
	if (unlikely(cpu < 0))
		BUG();
	return core_to_q[cpu];
}

/* the main scheduler routine, decides what to run next */
static __noinline void schedule(void)
{
	thread_t *th;
	struct runqueue *r;
	int i;

	__self = NULL;

again:
	/* first try this core's local runqueue */
	r = get_my_runqueue();
	spin_lock(&r->lock);
	th = list_pop(&r->runnable, thread_t, link);
	spin_unlock(&r->lock);
	if (th)
		call_thread(th);

	/* then try a random victim */
	r = qs[rand_city() % nr_qs];
	if (spin_try_lock(&r->lock)) {
		th = list_pop(&r->runnable, thread_t, link);
		spin_unlock(&r->lock);
		if (th)
			call_thread(th);
	}

	/* then try every runqueue */
	for (i = 0; i < nr_qs; i++) {
		r = qs[i];
		if (spin_try_lock(&r->lock)) {
			th = list_pop(&r->runnable, thread_t, link);
			spin_unlock(&r->lock);
			if (th)
				call_thread(th);
		}
	}

	goto again;
}

static void thread_finish_park_and_unlock(unsigned long data)
{
	thread_t *myth = thread_self();
	spinlock_t *lock = (spinlock_t *)data;

	assert(myth->state == THREAD_STATE_RUNNING);
	myth->state = THREAD_STATE_SLEEPING;
	spin_unlock(lock);

	schedule();
}

/**
 * thread_park_and_unlock - puts a thread to sleep and unlocks when finished
 * @lock: this lock will be released when the thread state is fully saved
 */
void thread_park_and_unlock(spinlock_t *lock)
{
	/* this will switch from the thread stack to the runtime stack */
	call_runtime(thread_finish_park_and_unlock, (unsigned long)lock);
}

/**
 * thread_ready - marks a thread as a runnable
 * @th: the thread to mark runnable
 *
 * This function can only be called when @th is sleeping.
 */
void thread_ready(thread_t *th)
{
	struct runqueue *r = get_my_runqueue();

	assert(th->state == THREAD_STATE_SLEEPING);
	th->state = THREAD_STATE_RUNNABLE;

	spin_lock(&r->lock);
	list_add_tail(&r->runnable, &th->link);
	spin_unlock(&r->lock);
}

static void thread_finish_yield(unsigned long data)
{
	thread_t *myth = thread_self();

	assert(myth->state == THREAD_STATE_RUNNING);
	myth->state = THREAD_STATE_SLEEPING;
	thread_ready(myth);

	schedule();
}

/**
 * thread_yield - yields the currently running thread
 *
 * Yielding will give other threads a chance to run.
 */
void thread_yield(void)
{
	/* this will switch from the thread stack to the runtime stack */
	call_runtime(thread_finish_yield, 0);
}

static int __thread_spawn(thread_fn_t fn, void *arg, bool main)
{
	struct thread *th;
	struct stack *s;

	th = tcache_alloc(&thread_pt);
	if (unlikely(!th))
		return -ENOMEM;

	s = stack_alloc();
	if (unlikely(!s)) {
		tcache_free(&thread_pt, th);
		return -ENOMEM;
	}

	th->tf.rdi = (uint64_t)arg;
	th->tf.rbp = (uint64_t)0; /* just in case base pointers are enabled */
	th->tf.rip = (uint64_t)fn;
	th->tf.rsp = stack_init_to_rsp(s, thread_exit);

	th->stack = s;
	th->state = THREAD_STATE_SLEEPING;
	th->main_thread = main;
	thread_ready(th);

	return 0;
}

/**
 * thread_spawn - creates a new thread
 * @fn: a function pointer to the starting method of the thread
 * @arg: an argument passed to @fn
 *
 * Returns 0 if successful, otherwise -ENOMEM if out of memory.
 */
int thread_spawn(thread_fn_t fn, void *arg)
{
	return __thread_spawn(fn, arg, false);
}

/**
 * thread_spawn_main - creates the main thread
 * @fn: a function pointer to the starting method of the thread
 * @arg: an argument passed to @fn
 *
 * WARNING: Only can be called once.
 *
 * Returns 0 if successful, otherwise -ENOMEM if out of memory.
 */
int thread_spawn_main(thread_fn_t fn, void *arg)
{
	static bool called = false;
	BUG_ON(called);
	called = true;
	return __thread_spawn(fn, arg, true);
}

static void thread_finish_exit(unsigned long data)
{
	struct thread *th = thread_self();

	/* if the main thread dies, kill the whole program */
	if (unlikely(th->main_thread))
		init_shutdown(EXIT_SUCCESS);
	stack_free(th->stack);
	tcache_free(&thread_pt, th);

	schedule();
}

/**
 * thread_exit - terminates a thread
 */
void thread_exit(void)
{
	/* can't free the stack we're currently using, so switch */
	call_runtime_nosave(thread_finish_exit, 0);
}

/**
 * sched_start - used only to enter the runtime the first time
 */
void sched_start(void)
{
	call_runtime_nosave((runtime_fn_t)schedule, 0);
}

static void runtime_top_of_stack(void)
{
	panic("a runtime function returned to the top of the stack");
}

/**
 * sched_init_thread - initializes per-thread state for the scheduler
 *
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int sched_init_thread(void)
{
	struct stack *s;

	tcache_init_perthread(thread_tcache, &thread_pt);

	s = stack_alloc();
	if (!s)
		return -ENOMEM;

	runtime_stack = (void *)stack_init_to_rsp(s, runtime_top_of_stack); 
	return 0;
}

static struct runqueue *create_runqueue(void)
{
	struct runqueue *r;

	r = malloc(sizeof(*r));
	if (!r)
		return NULL;

	spin_lock_init(&r->lock);
	list_head_init(&r->runnable);
	qs[nr_qs++] = r;
	return r;
}

/**
 * sched_init - initializes the scheduler subsystem
 *
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int sched_init(void)
{
	struct runqueue *r;
	int ret, i, pos;

	/*
	 * set up allocation routines for threads
	 */
	ret = slab_create(&thread_slab, "runtime_threads",
			  sizeof(struct thread), 0);
	if (ret)
		return ret;

	thread_tcache = slab_create_tcache(&thread_slab,
					   TCACHE_DEFAULT_MAG_SIZE);
	if (!thread_tcache) {
		slab_destroy(&thread_slab);
		return -ENOMEM;
	}

	/*
	 * create runqueues based on CPU topology
	 * STRATEGY: create a runqueue for each hyperthread pair
	 */
	for (i = 0; i < cpu_count; i++) {
		unsigned long *siblings = cpu_info_tbl[i].thread_siblings_mask;
		int first = bitmap_find_next_set(siblings, NCPU, 0);

		/* only create a runqueue for the first occurrence */
		if (i != first) {
			BUG_ON(!core_to_q[i]);
			continue;
		}

		r = create_runqueue();
		if (!r)
			return -ENOMEM;

		bitmap_for_each_set(siblings, NCPU, pos)
			core_to_q[pos] = r;
	}

	return 0;
}
