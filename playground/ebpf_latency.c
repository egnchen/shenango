#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#define NR_BUFFERS 10240
void *buffer;
inline uint64_t rdtsc(void)
{
	uint32_t a, d;
	asm volatile("rdtsc" : "=a" (a), "=d" (d));
	return ((uint64_t)a) | (((uint64_t)d) << 32);
}
#define RDTSC_FREQ 2300000000
static inline float rdtsc_to_us(uint64_t delta)
{
	return (float)delta / (RDTSC_FREQ / 1000000);
}

#define WRITE(expr) write(1, (expr), strlen(expr))
#define WRITE_NULL(expr) write(2, (expr), strlen(expr))

extern __thread volatile unsigned int preempt_cnt;
void *test_ebpf_latency(void *arg)
{
    // arg should be null
    printf("Mallocing...\n");
    char *buffer;

    // hack: disable preemption here
    if((preempt_cnt & ~(1 << 31)) == 0) {
        preempt_cnt += 1;
    }
    asm volatile("" ::: "memory");
    
    buffer = mmap(NULL, NR_BUFFERS * 4096, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    // asm volatile("" ::: "memory");
    if((preempt_cnt & ~(1<<31)) > 0) {
        preempt_cnt = 1 << 31;
    }
    
    printf("buffer is %p\n", buffer);
    
    // trigger page fault
    int l = 0xf;
    while(l < NR_BUFFERS * 4096) {
        *((char *)(buffer + l)) = 'a';
        l += 1024;
    }

    WRITE("access finished\n");

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
    WRITE("in main\n");
    pthread_t threads[NR_THREADS];
    for(int i = 0; i < thread_count; i++) {
        pthread_create(&threads[i], 0, test_ebpf_latency, NULL);
    }
    for(int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    sleep(100);
    
    // test_ebpf_latency(NULL);
    return 0;
}
