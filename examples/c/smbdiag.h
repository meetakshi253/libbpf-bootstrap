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
	__u64 session_id;
	__u64 mid;	
	__u16 smbcommand;
	union metrics metric;
	__u8 is_compounded;
};

struct event {
	pid_t pid;
	__u64 cmd_end_time_ns;
	__u64 session_id;
	__u64 mid;
	__u16 smbcommand;
	union metrics metric;
	__u8 tool;
	__u8 is_compounded;
	__u8 task[TASK_COMM_LEN];
};

#endif /* __SMBDIAG_H */
