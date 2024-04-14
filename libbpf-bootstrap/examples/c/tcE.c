// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include "tcE.skel.h"

// network interface hook
#define LO_IFINDEX 5

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tcE_hook, .ifindex = LO_IFINDEX,
			    .attach_point = BPF_TC_EGRESS);
                
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tcE_opts, .handle = 1, .priority = 1);
	struct tcE_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = tcE_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tcE_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	err = bpf_tc_hook_create(&tcE_hook);

	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	tcE_opts.prog_fd = bpf_program__fd(skel->progs.tc_egress1);
	err = bpf_tc_attach(&tcE_hook, &tcE_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

	while (!exiting) {
		//fprintf(stderr, ".");
		sleep(1);
	}

	tcE_opts.flags = tcE_opts.prog_fd = tcE_opts.prog_id = 0;
	err = bpf_tc_detach(&tcE_hook, &tcE_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	tcE_opts.flags = tcE_opts.prog_fd = tcE_opts.prog_id = 0;
	bpf_tc_detach(&tcE_hook, &tcE_opts);
	bpf_tc_hook_destroy(&tcE_hook);
	tcE_bpf__destroy(skel);
	return -err;
}