#ifndef __SMBVFSIOSNOOP_H
#define __SMBVFSIOSNOOP_H

#define MAX_ERRNO	    4095
#define IS_ERR_VALUE(x)	    ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

#define TASK_COMM_LEN	    16
#define MAX_OP_TYPE_LENGTH  10
#define MAX_FUNCTION_LENGTH 30
#define MAX_PATH_LENGTH	    33
#define MAX_ARGS_LENGTH	    150

struct event {
	int retval;
	pid_t pid;
	char args[MAX_ARGS_LENGTH];
	char type[MAX_OP_TYPE_LENGTH];
	char function[MAX_FUNCTION_LENGTH];
	char task[TASK_COMM_LEN];
};

#endif /* __SMBVFSIOSNOOP_H */
