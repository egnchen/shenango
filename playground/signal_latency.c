#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/mman.h>

// produce a fake one using raise()

#define NR_PAGES 128
char *buffer;
int len;
int pid;
struct timespec start_ts;

unsigned long total_time_elapsed;
unsigned long signal_count;

static void handler(int sig, siginfo_t *si, void *unused)
{
    struct timespec t;
    unsigned long prev_t = (unsigned long)(si->si_value.sival_ptr);
    clock_gettime(CLOCK_REALTIME, &t);
    unsigned long now_t = (t.tv_sec - start_ts.tv_sec) * 1000000 + (t.tv_nsec - start_ts.tv_nsec) / 1e3;
    total_time_elapsed += now_t - prev_t;
    signal_count += 1;
}

void *test_signal_latency(void *arg)
{
    sigval_t val;
    // use sigqueue to emulate signal transmission when page fault triggered
    for(int i = 0; i < 10240; i++) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        unsigned long usec_val = (ts.tv_sec - start_ts.tv_sec) * 1000000 + (ts.tv_nsec - start_ts.tv_nsec) / 1e3;
        val.sival_ptr = usec_val;
        sigqueue(pid, SIGUSR1, val);
    }
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
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO; /* Important. */
    sigaction(SIGUSR1, &sa, NULL);

    pid = getpid();
    clock_gettime(CLOCK_REALTIME, &start_ts);
    #define NR_THREADS 128
    pthread_t threads[NR_THREADS];
    for(int i = 0; i < thread_count; i++) {
        pthread_create(&threads[i], 0, test_signal_latency, NULL);
    }
    for(int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("total time: %ldus count: %ld\n", total_time_elapsed, signal_count);
    printf("average: %.3f us\n", (float)total_time_elapsed / signal_count);
}