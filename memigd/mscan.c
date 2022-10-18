#include "memigd.h"
#include <linux/pid.h>
#include <linux/damon.h>
#include <asm-generic/bug.h>

struct damon_ctx *ctx;
static int target_pid __read_mostly;
module_param(target_pid, int, 0600);
struct pid *target_pidp = NULL;
struct damon_target *target;

struct dentry *debugfs_root;
struct dentry *param_pid;

struct userspace_output *output_buf;

static int damon_stop_safe(struct damon_ctx *ctx)
{
    bool need_stop;
    /* check if current context is running */
    mutex_lock(&ctx->kdamond_lock);
    need_stop = (bool)ctx->kdamond;
    mutex_unlock(&ctx->kdamond_lock);

    return need_stop ? damon_stop(&ctx, 1) : 0;
}

int debugfs_get_pid(void *data, u64 *val)
{
    *val = target_pid;
    return 0;
}

int debugfs_set_pid(void *data, u64 val)
{
    int ret = 0;
    target_pid = val;
    target_pidp = find_get_pid(target_pid);
    pr_info("Warning: debugfs interface triggered, deprecated.\n");
    if (!target_pidp) {
        target_pid = 0;
        target_pidp = NULL;
        pr_info("pid %d is invalid.\n", target_pid);
        return -EINVAL;
    }

    damon_stop_safe(ctx);
    pr_info("Stopped current monitor.\n");
    
    target->pid = target_pidp;
    // target->nr_regions = 1024;
    pr_info("Added pid %d, start monitoring...\n", target_pid);
    return damon_start(&ctx, 1, true);
}

DEFINE_SIMPLE_ATTRIBUTE(param_pid_ops, debugfs_get_pid, debugfs_set_pid, "%llu\n");

static int memigd_after_aggregation(struct damon_ctx *c)
{
    struct damon_target *t;
    damon_for_each_target(t, c) {
        pr_info("target %p, nr_regions = %d\n", t, t->nr_regions);
        struct damon_region *r;
        damon_for_each_region(r, t) {
            pr_info("region 0x%p(len=%d) accessed %d times", r->ar.start, r->ar.end - r->ar.start, r->nr_accesses);
        }
    }
    return 0;
}


static int __init memigd_init(void)
{
    int ret = 0;
    LOG_CALL();

    // debugfs interfaces
    debugfs_root = debugfs_create_dir("memigd", NULL);
    if (!debugfs_root) {
        return -ENOMEM;
    }
    pr_info("created root directory");
    param_pid = debugfs_create_file("pid", 0777, debugfs_root, NULL, &param_pid_ops);
    if (!param_pid) {
        ret = -ENOMEM;
        goto fail_debugfs;
    }
    pr_info("created pid file");
    output_buf = smem_init("buffer", debugfs_root);
    if (IS_ERR_OR_NULL(output_buf)) {
        ret = PTR_ERR(output_buf);
        goto fail_debugfs;
    }
    pr_info("created shared buffer");

    // damon interfaces
    ctx = damon_new_ctx();
    target = damon_new_target();
    if (!ctx || !target) {
        ret = -ENOMEM;
        goto fail_damon;
    }
    pr_info("created ctx and target");
    pr_info("pid to load is %d", target_pid);
    target_pidp = find_get_pid(target_pid);
    if (IS_ERR_OR_NULL(target_pidp)) {
        ret = -EINVAL;
        goto fail_damon;
    }
    target->pid = target_pidp;
    pr_info("loaded pid");
    // target->nr_regions = 1024;
    damon_add_target(ctx, target);
    if (ret = damon_select_ops(ctx, DAMON_OPS_FVADDR)) {
        goto fail_damon;
    }
    pr_info("ctx is 0x%p, ctx->ops is 0x%p\n", ctx, ctx->ops);
    ctx->callback.after_aggregation = memigd_after_aggregation;
    // ctx->ops = damon_registered_ops[DAMON_OPS_FVADDR];
    pr_info("init success, attaching to pid %d\n", target_pid);
    pr_info("ctx is 0x%p, ctx->ops is 0x%p\n", ctx, ctx->ops);
    ret = damon_start(&ctx, 1, true);
    pr_info("damon_start returned %d\n", ret);
    return ret;
fail_damon:
    if (target)
        damon_destroy_target(target);
    if (ctx)
        damon_destroy_ctx(ctx);
fail_debugfs:
    debugfs_remove_recursive(debugfs_root);
    return ret;
}

static void __exit memigd_exit(void)
{
    LOG_CALL();
    damon_stop_safe(ctx);
    damon_destroy_ctx(ctx);
    put_pid(target_pidp);
    smem_exit();
    debugfs_remove_recursive(debugfs_root);
}

module_init(memigd_init);
module_exit(memigd_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eugene Chen");
MODULE_DESCRIPTION("Memory scanner module for shenango");
