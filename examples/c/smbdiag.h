/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __SMBDIAG_H
#define __SMBDIAG_H

#define TASK_COMM_LEN	 16
#define MAX_SMB_COMMANDS	20
#define MAX_ENTRIES 2048

#define SMBSLOWER 0

union metrics {
	unsigned long long latency_ns;
	int retval;
};

struct partial_event {
	unsigned long long session_id;
	unsigned long long mid;	
	unsigned short smbcommand;
	union metrics metric;
	char is_compounded;
};

struct event {
	pid_t pid;
	unsigned long long cmd_end_time_ns;
	unsigned long long session_id;
	unsigned long long mid;
	unsigned short smbcommand;
	union metrics metric;
	char tool;
	char is_compounded;
	char task[TASK_COMM_LEN];
};

#endif /* __SMBDIAG_H */
