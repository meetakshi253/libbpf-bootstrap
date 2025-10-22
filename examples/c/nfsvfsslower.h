#ifndef __NFSVFSSLOWER_H
#define __NFSVFSSLOWER_H

#define MAX_ERRNO	    4095
#define IS_ERR_VALUE(x)	    ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

#define TASK_COMM_LEN       16
#define MAX_PATH_LENGTH	    150
#define NSEC_PER_USEC       1000

struct event {
    unsigned long pid;
    unsigned long long delta_us;
    unsigned long long when_release_us;
    unsigned char function;
    int retval;
    char type;
    char task[TASK_COMM_LEN];
    char path[MAX_PATH_LENGTH];
};

#endif /* __NFSVFSSLOWER_H */