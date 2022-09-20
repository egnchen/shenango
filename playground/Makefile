.PHONY: all clean
CFLAGS = -O2 -g -Wall -Wno-unused-result
SHENANGO_LIBS = -Wl,--wrap=main ../shim/libshim.a ../libruntime.a ../libnet.a ../libbase.a ../libbpf/src/libbpf.a -T../base/base.ld -no-pie -ldl -lelf -lz -lpthread
all: ebpf_latency userfaultfd_latency signal_latency
CC = gcc
ebpf_latency: ebpf_latency.o
	$(CC) $^ -o $@ $(CFLAGS) $(SHENANGO_LIBS) 

userfaultfd_latency: userfaultfd_latency.o
	$(CC) $(CFLAGS) $^ -o $@ -pthread
signal_latency: signal_latency.o
	$(CC) $(CFLAGS) $^ -o $@ -pthread
clean:
	rm -f ebpf_latency userfaultfd_latency *.o
