/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SMBSLOWER_H
#define __SMBSLOWER_H

#define TASK_COMM_LEN   16
#define SMB2_FLAGS_ASYNC_COMMAND 0x00000002
#define NSEC_PER_USEC 1000

struct data {
    unsigned long long when_alloc;
    unsigned long long session_id;
    unsigned long long id;
    unsigned long long mid;
    unsigned short smbcommand;
    char is_compounded;
    char is_async;
    char task[TASK_COMM_LEN];
};

struct event {
    pid_t pid;
    unsigned long long when_release_us;
    unsigned long long delta_us;
    unsigned long long session_id;
    unsigned long long id;
    unsigned long long mid;
    unsigned short smbcommand;
    char is_compounded;
    char is_async;
    char task[TASK_COMM_LEN];
};

#endif /* __SMBSLOWER_H */
