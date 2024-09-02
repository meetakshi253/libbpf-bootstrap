#ifndef __SMBIOSNOOP_H
#define __SMBIOSNOOP_H

#define TASK_COMM_LEN	   16
#define MAX_SMB_BUFFER_LEN 50
#define MAX_ARGS_LENGTH   128

/* command codes in host endian */
#define SMB2_NEGOTIATE			   0x0000
#define SMB2_SESSION_SETUP		   0x0001
#define SMB2_LOGOFF			   0x0002 /* trivial request/resp */
#define SMB2_TREE_CONNECT		   0x0003
#define SMB2_TREE_DISCONNECT		   0x0004 /* trivial req/resp */
#define SMB2_CREATE			   0x0005
#define SMB2_CLOSE			   0x0006
#define SMB2_FLUSH			   0x0007 /* trivial resp */
#define SMB2_READ			   0x0008
#define SMB2_WRITE			   0x0009
#define SMB2_LOCK			   0x000A
#define SMB2_IOCTL			   0x000B
#define SMB2_CANCEL			   0x000C
#define SMB2_ECHO			   0x000D
#define SMB2_QUERY_DIRECTORY		   0x000E
#define SMB2_CHANGE_NOTIFY		   0x000F
#define SMB2_QUERY_INFO			   0x0010
#define SMB2_SET_INFO			   0x0011
#define SMB2_OPLOCK_BREAK		   0x0012
#define SMB2_SERVER_TO_CLIENT_NOTIFICATION 0x0013

struct event {
	pid_t pid;
	int server_retval;
	int num_rqst;
	unsigned long long connection_id;
	unsigned short smbcommand;
	unsigned long long session_id;
	char commandargs[MAX_ARGS_LENGTH];
	char task[TASK_COMM_LEN];
	__u8 Buffer[MAX_SMB_BUFFER_LEN];
	int namelen;
};

#endif /* __SMBIOSNOOP_H */