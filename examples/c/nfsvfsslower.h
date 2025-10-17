#ifndef __NFSVFSSLOWER_H
#define __NFSVFSSLOWER_H

#define TASK_COMM_LEN       16
#define MAX_OP_TYPE_LENGTH  10
#define MAX_PATH_LENGTH	    150
#define NSEC_PER_USEC       1000

struct event {
    unsigned long pid;
    unsigned long long delta_us;
    unsigned long long when_release_us;
    unsigned short function;
    unsigned short retval;
    char type[MAX_OP_TYPE_LENGTH];
    char task[TASK_COMM_LEN];
    char path[MAX_PATH_LENGTH];
};

#endif /* __NFSVFSSLOWER_H */