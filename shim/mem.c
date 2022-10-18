
#include <dlfcn.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <runtime/preempt.h>
#include <base/log.h>
#include <bits/sched.h>

// #define WRITE_LOG(expr) do { \
// 	char buf[64]; \
// 	int cpu = sched_getcpu(); \
// 	buf[0] = '0' + (cpu / 10); \
// 	buf[1] = '0' + (cpu % 10); \
// 	buf[2] = ' '; \
// 	strcpy(&buf[3], expr); \
// 	write(1, buf, strlen(buf)); \
// } while(0)

#define WRITE_LOG(expr)

#define HOOK3(fnname, retType, argType1, argType2, argType3)                   \
	retType fnname(argType1 __a1, argType2 __a2, argType3 __a3)            \
	{                                                                      \
		static retType (*real_##fnname)(argType1, argType2, argType3); \
		if (unlikely(!real_##fnname)) {                                \
			real_##fnname = dlsym(RTLD_NEXT, #fnname);             \
		}                                                              \
		WRITE_LOG(#fnname " called\n");	\
		preempt_disable();                                             \
		retType __t = real_##fnname(__a1, __a2, __a3);                 \
		preempt_enable();                                              \
		return __t;                                                    \
	}

#define HOOK2(fnname, retType, argType1, argType2)                             \
	retType fnname(argType1 __a1, argType2 __a2)                           \
	{                                                                      \
		static retType (*real_##fnname)(argType1, argType2);           \
		if (unlikely(!real_##fnname)) {                                \
			real_##fnname = dlsym(RTLD_NEXT, #fnname);             \
		}                                                              \
		WRITE_LOG(#fnname " called\n");	\
		preempt_disable();                                             \
		retType __t = real_##fnname(__a1, __a2);                       \
		preempt_enable();                                              \
		return __t;                                                    \
	}

#define HOOK1(fnname, retType, argType1)                                       \
	retType fnname(argType1 __a1)                                          \
	{                                                                      \
		static retType (*real_##fnname)(argType1);                     \
		if (unlikely(!real_##fnname)) {                                \
			real_##fnname = dlsym(RTLD_NEXT, #fnname);             \
		}                                                              \
		WRITE_LOG(#fnname " called\n");	\
		preempt_disable();                                             \
		retType __t = real_##fnname(__a1);                             \
		preempt_enable();                                              \
		return __t;                                                    \
	}

#define HOOK1_NORET(fnname, argType1)                                          \
	void fnname(argType1 __a1)                                             \
	{                                                                      \
		static void (*real_##fnname)(argType1);                        \
		if (unlikely(!real_##fnname)) {                                \
			real_##fnname = dlsym(RTLD_NEXT, #fnname);             \
		}                                                              \
		WRITE_LOG(#fnname " called\n");	\
		preempt_disable();                                             \
		real_##fnname(__a1);                                           \
		preempt_enable();                                              \
	}

#define HOOK1_PREEMPT(fnname, retType, argType1)                                       \
	retType fnname(argType1 __a1)                                          \
	{                                                                      \
		static retType (*real_##fnname)(argType1);                     \
		if (unlikely(!real_##fnname)) {                                \
			real_##fnname = dlsym(RTLD_NEXT, #fnname);             \
		}                                                              \
		WRITE_LOG(#fnname " called(preemptable)\n");	\
		retType __t = real_##fnname(__a1);                             \
		return __t;                                                    \
	}

HOOK1_PREEMPT(malloc, void *, size_t);
HOOK1_NORET(free, void *);
HOOK2(realloc, void *, void *, size_t);
HOOK1_NORET(cfree, void *);
HOOK2(memalign, void *, size_t, size_t);
HOOK2(aligned_alloc, void *, size_t, size_t);
HOOK1(valloc, void *, size_t);
HOOK1(pvalloc, void *, size_t);
HOOK3(posix_memalign, int, void **, size_t, size_t);

HOOK1_NORET(__libc_free, void *);
HOOK2(__libc_realloc, void *, void *, size_t);
HOOK2(__libc_calloc, void *, size_t, size_t);
HOOK1_NORET(__libc_cfree, void *);
HOOK2(__libc_memalign, void *, size_t, size_t);
HOOK1(__libc_valloc, void *, size_t);
HOOK1(__libc_pvalloc, void *, size_t);
HOOK3(__posix_memalign, int, void **, size_t, size_t);

static void *dummy_calloc(size_t a, size_t b) { return NULL; }

void *calloc(size_t a, size_t b)
{
	static void *(*real_calloc)(size_t, size_t);
	if (unlikely(!real_calloc)) {
		// Ensure that dlsym's call to calloc doesn't loop infinitely
		real_calloc = dummy_calloc;
		barrier();
		real_calloc = dlsym(RTLD_NEXT, "calloc");
	}
	preempt_enable();
	void *ptr = real_calloc(a, b);
	preempt_disable();
	return ptr;
}
