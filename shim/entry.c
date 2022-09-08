// #define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

#include <runtime/thread.h>

static int main_argc;
static char **main_argv;
static char **main_envp;
static int main_ret;
static char *cfg;

static int(*orig_main)(int, char **, char **);

static void runtime_entry(void *arg)
{
	main_ret = orig_main(main_argc, main_argv, main_envp);
}

int main_hook(int argc, char **argv, char **envp)
{
	int ret = 0;
	if (argc < 2) {
		fprintf(stderr, "Error: missing shenango config argument\n");
		return 0;
	}

	cfg = argv[1];
	argv[1] = argv[0];
	main_argc = argc - 1;
	main_argv = &argv[1];
	main_envp = envp;

	ret = runtime_init(cfg, runtime_entry, NULL);

	if (ret) {
		fprintf(stderr, "failed to start runtime\n");
	}
	return ret;
}

// replaces the original __libc_start_main
int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc,
    char **argv,
    int (*init)(int, char **, char **),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end)
{
	typeof(&__libc_start_main) orig_libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");

	if(orig_libc_start_main == NULL) {
		fprintf(stderr, "Could not find original entrance\n");
		return -1;
	}

	orig_main = main;
	return orig_libc_start_main(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}