/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __AODDIAG_H
#define __AODDIAG_H

#define TASK_COMM_LEN   16
#define MAX_ENTRIES     2048
#define RINGBUF_PINNED "/sys/fs/bpf/aodrb"

union metrics {
	unsigned long long latency_ns;
	int retval;
};

struct event {
	int pid;
    int command;
	unsigned long long cmd_end_time_ns;
	unsigned long long mid;
	union metrics metric;
	char tool;
	char task[TASK_COMM_LEN];
};

#endif /* __AODDIAG_H */
