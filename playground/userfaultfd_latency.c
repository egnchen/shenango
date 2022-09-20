#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <linux/userfaultfd.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>

// inline uint64_t rdtsc(void)
// {
// 	uint32_t a, d;
// 	asm volatile("rdtsc" : "=a" (a), "=d" (d));
// 	return ((uint64_t)a) | (((uint64_t)d) << 32);
// }
// #define RDTSC_FREQ 2300000000
// static inline float rdtsc_to_us(uint64_t delta)
// {
// 	return (float)delta / (RDTSC_FREQ / 1000000);
// }
// static uint64_t last_tsc;

struct handler_args {
    long uffd;
    struct timeval last_tv;
    struct timeval stat_tv;
    int pf_cnt;
    void *start_address;
    uint64_t len;
};

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)
static int page_size;

struct timeval total_tv;
unsigned long pf_cnt;
unsigned long expected_pf_cnt;

static void *
fault_handler_thread(void *arg)
{
    struct handler_args *args = arg;
    long uffd = args->uffd;
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    static int fault_cnt = 0;     /* Number of faults so far handled */
    static char *page = NULL;
    struct uffdio_copy uffdio_copy;
    struct uffdio_zeropage uffdio_zeropage;
    ssize_t nread;

    /* Create a page that will be copied into the faulting region. */

    if (page == NULL) {
        page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED)
            errExit("mmap");
    }

    /* Loop, handling incoming events on the userfaultfd
        file descriptor. */

    for (;;) {

        /* See what poll() tells us about the userfaultfd. */

        struct pollfd pollfd;
        struct timeval tv;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        // printf("polling on %d\n", pollfd.fd);
        nready = poll(&pollfd, 1, -1);
        if (nready == -1)
            errExit("poll");

        /* Read an event from the userfaultfd. */
        nread = read(uffd, &msg, sizeof(msg));
        // take time
        gettimeofday(&tv, NULL);
        // printf("Latency: %lds %ldus\n", tv.tv_sec - args->last_tv.tv_sec, tv.tv_usec - args->last_tv.tv_usec);
        args->stat_tv.tv_sec += tv.tv_sec;
        args->stat_tv.tv_usec += tv.tv_usec;
        args->pf_cnt++;
        
        // printf("\nfault_handler_thread():\n");
        // printf("    poll() returns: nready = %d; "
        //         "POLLIN = %d; POLLERR = %d\n", nready,
        //         (pollfd.revents & POLLIN) != 0,
        //         (pollfd.revents & POLLERR) != 0);

        if (nread == 0) {
            printf("EOF on userfaultfd!\n");
            exit(EXIT_FAILURE);
        }

        if (nread == -1)
            errExit("read");

        /* We expect only one kind of event; verify that assumption. */

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            fprintf(stderr, "Unexpected event on userfaultfd\n");
            exit(EXIT_FAILURE);
        }

        /* Display info about the page-fault event. */

        // printf("    UFFD_EVENT_PAGEFAULT event from %d: ", pollfd.fd);
        // printf("flags = %llx; ", msg.arg.pagefault.flags);
        // printf("address = %llx\n", msg.arg.pagefault.address);

        /* Copy the page pointed to by 'page' into the faulting
            region. Vary the contents that are copied in, so that it
            is more obvious that each fault is handled separately. */

        memset(page, 'A' + fault_cnt % 20, page_size);
        fault_cnt++;

        uffdio_copy.src = (unsigned long) page;

        /* We need to handle page faults in units of pages(!).
            So, round faulting address down to page boundary. */

        // uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
        //                                     ~(page_size - 1);
        // uffdio_copy.len = page_size;
        // uffdio_copy.mode = 0;
        // uffdio_copy.copy = 0;
        // if(uffdio_copy.dst < args->start_address || uffdio_copy.dst >= args->start_address + args->len) {
        //     continue;
        // }
        uffdio_zeropage.range.start = (unsigned long) msg.arg.pagefault.address & ~(page_size - 1);
        uffdio_zeropage.range.len = page_size;
        // if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1) {
        if(ioctl(uffd, UFFDIO_ZEROPAGE, &uffdio_zeropage) == -1) {
            // if(errno == 17) {
            //     continue;
            // }
            // printf("%d\n", errno);
            errExit("ioctl-UFFDIO_ZEROPAGE");
        }

        // printf("        (uffdio_copy.copy returned %lld)\n",
        //         uffdio_copy.copy);
    }
}

char *register_userfault(int nr_pages, struct handler_args *args)
{
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    long uffd;
    char *addr;
    uint64_t map_len;
    pthread_t thr;

    page_size = sysconf(_SC_PAGE_SIZE);
    map_len = nr_pages * page_size;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if(uffd == -1) errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    /* Create a private anonymous mapping. The memory will be
        demand-zero paged--that is, not yet allocated. When we
        actually touch the memory, it will be allocated via
        the userfaultfd. */

    addr = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        errExit("mmap");

    printf("Address returned by mmap() = %p\n", addr);

    /* Register the memory range of the mapping we just created for
        handling by the userfaultfd object. In mode, we request to track
        missing pages (i.e., pages that have not yet been faulted in). */

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = map_len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");

    /* Create a thread that will process the userfaultfd events. */
    args->uffd = uffd;
    if (pthread_create(&thr, NULL, fault_handler_thread, (void *)args)) {
        errExit("pthread_create");
    }
    args->start_address = addr;
    args->len = map_len;
    return addr;
}

static int cnt;

void *test_userfaultfd_latency(void *_arg)
{
    struct handler_args *args = _arg;
    // now we trigger the page fault
    args->pf_cnt = 0;
    int l = 0xf;
    char *addr = args->start_address;
    while(l < args->len) {
        if(l % 4096 == 0xf) {
            gettimeofday(&args->last_tv, NULL);
            __sync_fetch_and_add(&total_tv.tv_sec, -args->last_tv.tv_sec);
            __sync_fetch_and_add(&total_tv.tv_usec, -args->last_tv.tv_usec);
            __sync_fetch_and_add(&expected_pf_cnt, 1);
        }
        char c = addr[l];
        cnt += c;
        l += 1024;
        // usleep(1000);
    }
    return NULL;
}

int main(int argc, const char *argv[])
{
    if(argc != 2) {
        fprintf(stderr, "Usage: <program> <thread count>\n");
        return -1;
    }
    int thread_count = atoi(argv[1]);
    if(thread_count <= 0) {
        return -1;
    }
    #define NR_THREADS 128
    pthread_t threads[NR_THREADS];
    pthread_t handler_thread;

    int pg_cnt = 10240;
    // map pages for us to do userfaultfd
    struct handler_args *args = malloc(sizeof(struct handler_args));
    char *addr = register_userfault(pg_cnt * thread_count, args);

    pthread_create(&handler_thread, NULL, fault_handler_thread, args);

    for(int i = 0; i < thread_count; i++) {
        struct handler_args *worker_args = malloc(sizeof(struct handler_args));
        worker_args->start_address = addr + i * thread_count;
        worker_args->len = page_size;
        pthread_create(&threads[i], 0, test_userfaultfd_latency, worker_args);
    }
    for(int i = 0; i < thread_count; i++) {
        printf("Waiting for %lu\n", threads[i]);
        pthread_join(threads[i], NULL);
    }
    
    printf("average latency: %.3fus\n", (float)(total_tv.tv_sec * 1000000 + total_tv.tv_usec) / pf_cnt);
    printf("expected %lu actual %lu", expected_pf_cnt, pf_cnt);
    // test_ebpf_latency(NULL);
    return 0;
}
