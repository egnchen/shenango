#include <sys/mman.h>
#include <stdio.h>

#include <base/log.h>
#include <runtime/preempt.h>
#include <fcntl.h>

#include "asm/atomic.h"
#include "defs.h"
#include "runtime/net.h"
#include "runtime/thread.h"
#include "runtime/tcp.h"
#include "runtime/sync.h"

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

#define PAGE_SIZE 4096
#define PAGE_ALIGN(addr) (void *)((uint64_t)(addr) & ~(PAGE_SIZE - 1))

void *swap_start;
const uint64_t swap_len = 4 * MB;
uint64_t cache_off = 0;

char *memigd_buffer;

uint64_t stat_time;
int stat_cnt;

extern __thread uint64_t last_tsc;
extern __noreturn void schedule();
extern void enter_schedule(thread_t *);

static tcpconn_t *conn;

enum {
    OpInit = 0,
    OpShutdown = 1,
    OpReadObject = 2,
    OpWriteObject = 3,
    OpRemoveObject = 4,
    OpConstruct = 5,
    OpDeconstruct = 6,
    OpCompute = 7,
};

static const uint8_t kHashTableDSType = 1;
static const uint8_t kDSID = 1;
static __thread uint8_t buf[PAGE_SIZE];
static __thread uint8_t tcp_buf[PAGE_SIZE * 2];
static uint8_t init_complete = 0;

// shenango
static inline void tcp_read_until(tcpconn_t *c, void *buf,
                                        size_t expect) {
  size_t real = tcp_read(c, (uint8_t *)buf, expect);
  if (unlikely(real != expect)) {
    // Slow path.
    do {
      real +=
          tcp_read(c, (uint8_t *)buf + real, expect - real);
    } while (real < expect);
  }
}

static inline void tcp_write_until(tcpconn_t *c, const void *buf,
                                         size_t expect) {
  size_t real = tcp_write(c, (const uint8_t *)buf, expect);
  if (unlikely(real != expect)) {
    // Slow path.
    do {
      real += tcp_write(c, (const uint8_t *)buf + real,
                        expect - real);
    } while (real < expect);
  }
}

static int construct_remote_hashtable(uint32_t remote_num_entries_shift, uint32_t remote_data_size)
{
  log_debug("in %s", __FUNCTION__);
  uint8_t req[4 + 2 * sizeof(uint32_t)];
  req[0] = OpConstruct;
  req[1] = kHashTableDSType;
  req[2] = kDSID;
  req[3] = 2 * sizeof(uint32_t);
  ((uint32_t *)(req + 4))[0] = remote_num_entries_shift;
  ((uint32_t *)(req + 4))[1] = remote_data_size;
  tcp_write_until(conn, req, sizeof(req));
  uint8_t ack = 0;
  tcp_read_until(conn, &ack, sizeof(ack));
  BUG_ON(ack != 1);
  log_info("Initialized remote hashtable");
  return 0;
}

static int read_object(uint64_t obj_id, void *buf, uint32_t buf_len)
{
  log_debug("in %s", __FUNCTION__);
  uint8_t req[3 + sizeof(uint64_t)];
  req[0] = OpReadObject;
  req[1] = kDSID;
  req[2] = sizeof(uint64_t);
  *((uint64_t *)(req + 3)) = obj_id;
  tcp_write_until(conn, req, sizeof(req));
  uint16_t data_len = 0;
  tcp_read_until(conn, &data_len, sizeof(data_len));
  // log_info("read object 0x%lx, len=%d", obj_id, data_len);
  if(data_len) {
    tcp_read_until(conn, buf, data_len);
  }
  if(data_len != PAGE_SIZE) {
    // log_info("Not found in remote, filling with 'A'...");
    memset(buf, 'A', PAGE_SIZE);
  }
  return 0;
}

static int write_object(uint64_t obj_id)
{
  log_debug("in %s", __FUNCTION__);
  // use tcp_buf
  tcp_buf[0] = OpWriteObject;
  tcp_buf[1] = kDSID;
  tcp_buf[2] = sizeof(obj_id);
  *((uint16_t *)(tcp_buf + 3)) = PAGE_SIZE;
  *((uint64_t *)(tcp_buf + 5)) = obj_id;
  __builtin_memcpy(tcp_buf + 13, buf, PAGE_SIZE);
  log_info("Writing object...");
  tcp_write_until(conn, tcp_buf, 13 + PAGE_SIZE);
  uint8_t ack;
  tcp_read_until(conn, &ack, sizeof(ack));
  BUG_ON(ack != 1);
  log_info("write object success");
  return 0;
}

static inline void *do_mremap(void *old_addr, void *new_addr) {
  uint64_t start_t = rdtsc();
  void *ret = mremap(old_addr, PAGE_SIZE, PAGE_SIZE,
             MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, new_addr);
  stat_time += rdtsc() - start_t;
  stat_cnt++;
  return ret;
}

static inline int do_munmap(void *addr, int length) {
  return munmap(addr, length);
}

void pf_handle_routine(thread_t *fault_thread) {
  thread_t *self = thread_self();
  for(;;) {
    assert(preempt_enabled());
    if(load_acquire(&init_complete) == 0) {
      // log_info("Waiting for initialization to complete...");
      thread_yield();
      continue;
    }
    void *fault_addr = fault_thread->fault_addr;
    if(fault_addr) {
      // log_info("%p: handling pf @%p for %p", thread_self(), fault_thread->fault_addr, fault_thread);
      fault_addr = (void *)((uint64_t)fault_addr & ~(PAGE_SIZE - 1));
      uint64_t cur_off = cache_off;
      cache_off += PAGE_SIZE;
      if (cache_off >= swap_len) {
        cache_off = 0;
      }
      // fetch item from remote
      read_object((uint64_t)fault_addr, swap_start + cur_off, PAGE_SIZE);
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
    log_debug("spawned swap thread %p for %p", pf_handle_thread, myth);
    myth->pf_handle_thread = pf_handle_thread;
  }
  thread_ready(myth->pf_handle_thread);

  last_tsc = rdtsc();
  spin_lock(&k->lock);
  schedule();
}


static int str_to_ip(const char *str, uint32_t *addr)
{
	uint8_t a, b, c, d;
	if(sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) {
		return -EINVAL;
	}

	*addr = MAKE_IP_ADDR(a, b, c, d);
	return 0;
}

void do_swap_init_late(uint8_t *_arg)
{
  struct netaddr laddr, raddr;
  laddr.ip = netcfg.addr;
  laddr.port = 0;
  str_to_ip("192.168.100.57", &raddr.ip);
  raddr.port = 18080;
  
  assert(preempt_enabled());
  log_debug("Doing late swap init...");
  log_debug("Thread is %p", thread_self());
  if(tcp_dial(laddr, raddr, &conn)) {
    log_warn("Failed to setup connection with memory node.");
    BUG();
  }
  log_info("TCP connection established");

  // construct a 64MB(maximum) hopstoch hash table
  BUG_ON(construct_remote_hashtable(16, PAGE_SIZE * 256));

  // do a little testing
  memset(buf, 'A', sizeof(buf));
  write_object(0x1234);
  memset(buf, 0, sizeof(buf));
  read_object(0x1234, buf, PAGE_SIZE);
  for(int i = 0; i < PAGE_SIZE; i++) {
    BUG_ON(buf[i] != 'A');
  }
  log_info("Remote swap test completed.");
  store_release(&init_complete, 1);
}

int swap_init_late(void)
{
  // create a user thread to do init stuff
  store_release(&init_complete, 0);
  thread_t *th = thread_create(do_swap_init_late, NULL);
  BUG_ON(th == NULL);
  th->typ = THREAD_TYPE_SWAP;
  thread_ready(th);
  return 0;
}

int swap_init_thread()
{
  // nothing to do really
  return 0;
}

int swap_init()
{
  // initialize mmap region for swap buffer
  swap_start = mmap(NULL, swap_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  BUG_ON(swap_start == MAP_FAILED);
  log_info("Swap region returned by mmap: %p", swap_start);

  // initialize memigd

  char buf[64];
  sprintf(buf, "insmod ./memigd/memigd.ko target_pid=%d", getpid());
  log_info("Inserting mod: %s", buf);
  BUG_ON(system(buf));

  // register ourselves
  // __pid_t pid = getpid();
  // FILE *pid_file = fopen("/sys/kernel/debug/memigd/pid", "w");
  // BUG_ON(pid_file == NULL);
  // fprintf(pid_file, "%d\n", pid);
  // log_info("Registered to memigd %d", pid);
  // fclose(pid_file);

  // create shared memory region
  int smem_fd = open("/sys/kernel/debug/memigd/buffer", O_RDONLY);
  log_info("smem_fd is %d", smem_fd);
  BUG_ON(smem_fd < 0);
  memigd_buffer = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, smem_fd, 0);
  BUG_ON(memigd_buffer == MAP_FAILED);
  log_info("Successfully created shared buffer");
  // test it
  log_info("Read from shared buffer: %s\n", memigd_buffer);

  return 0;
}