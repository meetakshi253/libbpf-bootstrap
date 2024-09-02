/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SMBVFSSLOWER_H
#define __SMBVFSSLOWER_H

#define TASK_COMM_LEN   16
#define MAX_OP_TYPE_LENGTH  10
#define MAX_FUNCTION_LENGTH 30
#define NSEC_PER_USEC   1000

struct event {
    unsigned long pid;
    unsigned long long delta_us;
    unsigned long long when_release_us;
    char type[MAX_OP_TYPE_LENGTH];
    char function[MAX_FUNCTION_LENGTH];
    char task[TASK_COMM_LEN];
};

#endif /* __SMBVFSSLOWER_H */