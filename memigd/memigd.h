#pragma once

#define pr_fmt(fmt) "memigd: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>

struct cold_region {
    void *addr_start;
    unsigned long length;
};

struct userspace_output {
    uint64_t lock;
    struct cold_region out_regions[8];
};

void *smem_init(const char *fname, struct dentry *parent);
void smem_exit(void);

// debug intrinsics
#define LOG_CALL() pr_info("%s called\n", __FUNCTION__)