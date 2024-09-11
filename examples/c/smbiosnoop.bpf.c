// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinuxcifs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "smbiosnoop.h"

#define MAX_ENTRIES 8192

const volatile pid_t target_pid = 0;
const volatile __u32 target_cid = 0;
// ??eid

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_ARGS_LENGTH);
	__uint(max_entries, 1);
} tmp_storage_map1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_ARGS_LENGTH);
	__uint(max_entries, 1);
} tmp_storage_map2 SEC(".maps");

static inline int system_endianness()
{
	int n = 1;
	// 0 for little endian, 1 for big endian
	return (*(char *)&n == 1) ? 0 : 1;
}

static inline u8 le_to_sys8(u8 x)
{
	return x;
}

static inline u16 le_to_sys16(u16 x)
{
	// check system's endianness
	if (system_endianness() == 0) {
		return x;
	}
	// big endian
	return ((x >> 8) & 0xff) | // Move byte 1 to byte 0
	       ((x << 8) & 0xff00); // Move byte 0 to byte 1
}

static inline u32 le_to_sys32(u32 x)
{
	if (system_endianness() == 0) {
		return x;
	}
	// big endian
	return ((x >> 24) & 0xff) | ((x << 8) & 0xff0000) | ((x >> 8) & 0xff00) |
	       ((x << 24) & 0xff000000);
}

static inline u64 le_to_sys64(u64 x)
{
	if (system_endianness() == 0) {
		return x;
	}
	// big endian
	return ((x >> 56) & 0xff) | ((x << 40) & 0xff000000000000) | ((x << 24) & 0xff0000000000) |
	       ((x << 8) & 0xff00000000) | ((x >> 8) & 0xff000000) | ((x >> 24) & 0xff0000) |
	       ((x >> 40) & 0xff00) | ((x << 56) & 0xff00000000000000);
}

static inline void __get_negotiate_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_negotiate_req *nreq =
		(struct smb2_negotiate_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = {
		le_to_sys16(BPF_CORE_READ(nreq, SecurityMode)),
		le_to_sys16(BPF_CORE_READ(nreq, DialectCount)),
	};
	bpf_snprintf(argret, MAX_ARGS_LENGTH, "SecurityMode=0x%x|DialectCount=%d", argdata,
		     sizeof(argdata));
}

static inline void __get_session_setup_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_sess_setup_req *sreq =
		(struct smb2_sess_setup_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = {
		le_to_sys32(BPF_CORE_READ(sreq, Capabilities)),
		le_to_sys32(BPF_CORE_READ(sreq, Channel)),
		le_to_sys64(BPF_CORE_READ(sreq, PreviousSessionId)),
	};
	bpf_snprintf(argret, MAX_ARGS_LENGTH,
		     "Capabilities=0x%x|Channel=%d|PreviousSessionId=0x%llx", argdata,
		     sizeof(argdata));
}

static inline void __get_tree_connect_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_tree_connect_req *treq =
		(struct smb2_tree_connect_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = {
		le_to_sys16(BPF_CORE_READ(treq, Flags)),
	};
	bpf_snprintf(argret, MAX_ARGS_LENGTH, "Flags=0x%x", argdata, sizeof(argdata));
}

static inline void __get_create_details(struct smb_rqst *rqst, char *argret)
{
	char filename[MAX_PATH_LENGTH] = {};

	struct smb2_create_req *creq =
		(struct smb2_create_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);

	size_t off = le_to_sys16(BPF_CORE_READ(creq, NameOffset));
	size_t len = le_to_sys16(BPF_CORE_READ(creq, NameLength));

	if (len > MAX_PATH_LENGTH) {
		len = MAX_PATH_LENGTH;
	}

	bpf_printk("off: %d, len: %d\n", off, len);

	char *ptr;
	bpf_core_read(&ptr, sizeof(ptr), rqst + off);
	bpf_probe_read_kernel_str(&filename, len, ptr);

	bpf_printk("filename: %s\n", filename);

	u64 argdata[] = { le_to_sys8(BPF_CORE_READ(creq, RequestedOplockLevel)),
			  le_to_sys32(BPF_CORE_READ(creq, CreateOptions)),
			  le_to_sys32(BPF_CORE_READ(creq, CreateDisposition)), (u64)filename };
	bpf_snprintf(argret, MAX_ARGS_LENGTH,
		     "RequestedOplockLevel=0x%x|CreateOptions=0x%llx|Disposition=0x%x|File=%s",
		     argdata, sizeof(argdata));
}

static inline void __get_close_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_close_req *creq =
		(struct smb2_close_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = { le_to_sys16(BPF_CORE_READ(creq, Flags)),
			  BPF_CORE_READ(creq, PersistentFileId),
			  BPF_CORE_READ(creq, VolatileFileId) };
	bpf_snprintf(argret, MAX_ARGS_LENGTH,
		     "Flags=0x%x|PersistentFileId=0x%llx|VolatileFileId=0x%llx", argdata,
		     sizeof(argdata));
}

static inline void __get_flush_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_flush_req *freq =
		(struct smb2_flush_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = { BPF_CORE_READ(freq, PersistentFileId),
			  BPF_CORE_READ(freq, VolatileFileId) };
	bpf_snprintf(argret, MAX_ARGS_LENGTH, "PersistentFileId=0x%llx|VolatileFileId=0x%llx",
		     argdata, sizeof(argdata));
}

static inline void __get_read_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_read_req *rreq = (struct smb2_read_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = { le_to_sys32(BPF_CORE_READ(rreq, Length)),
			  le_to_sys64(BPF_CORE_READ(rreq, Offset)),
			  BPF_CORE_READ(rreq, PersistentFileId),
			  BPF_CORE_READ(rreq, VolatileFileId),
			  le_to_sys32(BPF_CORE_READ(rreq, Channel)) };
	bpf_snprintf(
		argret, MAX_ARGS_LENGTH,
		"Length=%d|Offset=%lld|PersistentFileId=0x%llx|VolatileFileId=0x%llx|Channel=0x%x",
		argdata, sizeof(argdata));
}

static inline void __get_write_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_write_req *wreq =
		(struct smb2_write_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = { le_to_sys32(BPF_CORE_READ(wreq, Length)),
			  le_to_sys64(BPF_CORE_READ(wreq, Offset)),
			  BPF_CORE_READ(wreq, PersistentFileId),
			  BPF_CORE_READ(wreq, VolatileFileId),
			  le_to_sys32(BPF_CORE_READ(wreq, Channel)) };
	bpf_snprintf(
		argret, MAX_ARGS_LENGTH,
		"Length=%d|Offset=%lld|PersistentFileId=0x%llx|VolatileFileId=0x%llx|Channel=0x%x",
		argdata, sizeof(argdata));
}

static inline void __get_lock_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_lock_req *lreq = (struct smb2_lock_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = { le_to_sys16(BPF_CORE_READ(lreq, LockCount)),
			  BPF_CORE_READ(lreq, PersistentFileId),
			  BPF_CORE_READ(lreq, VolatileFileId) };
	bpf_snprintf(argret, MAX_ARGS_LENGTH,
		     "LockCount=%d|PersistentFileId=0x%x|VolatileFileId=0x%llx", argdata,
		     sizeof(argdata));
}

static inline void __get_ioctl_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_ioctl_req *ireq =
		(struct smb2_ioctl_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = { le_to_sys32(BPF_CORE_READ(ireq, CtlCode)),
			  le_to_sys32(BPF_CORE_READ(ireq, InputCount)),
			  le_to_sys32(BPF_CORE_READ(ireq, Flags)),
			  BPF_CORE_READ(ireq, PersistentFileId),
			  BPF_CORE_READ(ireq, VolatileFileId) };
	bpf_snprintf(
		argret, MAX_ARGS_LENGTH,
		"CtlCode=0x%x|InputCount=%d|Flags=0x%x|PersistentFileId=0x%llx|VolatileFileId=0x%llx",
		argdata, sizeof(argdata));
}

static inline void __get_query_directory_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_query_directory_req *qreq =
		(struct smb2_query_directory_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = { BPF_CORE_READ(qreq, FileInformationClass), BPF_CORE_READ(qreq, Flags),
			  le_to_sys32(BPF_CORE_READ(qreq, FileIndex)),
			  BPF_CORE_READ(qreq, PersistentFileId),
			  BPF_CORE_READ(qreq, VolatileFileId) };
	bpf_snprintf(
		argret, MAX_ARGS_LENGTH,
		"FileInformationClass=0x%x|Flags=0x%x|FileIndex=%d|PersistentFileId=0x%llx|VolatileFileId=0x%llx",
		argdata, sizeof(argdata));
}

static inline void __get_change_notify_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_change_notify_req *creq =
		(struct smb2_change_notify_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = { le_to_sys32(BPF_CORE_READ(creq, CompletionFilter)),
			  le_to_sys16(BPF_CORE_READ(creq, Flags)),
			  BPF_CORE_READ(creq, PersistentFileId),
			  BPF_CORE_READ(creq, VolatileFileId) };
	bpf_snprintf(
		argret, MAX_ARGS_LENGTH,
		"CompletionFilter=0x%x|Flags=0x%x|PersistentFileId=0x%llx|VolatileFileId=0x%llx",
		argdata, sizeof(argdata));
}

static inline void __get_query_info_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_query_info_req *qreq =
		(struct smb2_query_info_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = { BPF_CORE_READ(qreq, InfoType), BPF_CORE_READ(qreq, FileInfoClass),
			  BPF_CORE_READ(qreq, PersistentFileId),
			  BPF_CORE_READ(qreq, VolatileFileId) };
	bpf_snprintf(
		argret, MAX_ARGS_LENGTH,
		"InfoType=0x%x|FileInfoClass=0x%x|PersistentFileId=0x%llx|VolatileFileId=0x%llx",
		argdata, sizeof(argdata));
}

static inline void __get_set_info_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_set_info_req *sreq =
		(struct smb2_set_info_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = { BPF_CORE_READ(sreq, InfoType), BPF_CORE_READ(sreq, FileInfoClass),
			  BPF_CORE_READ(sreq, PersistentFileId),
			  BPF_CORE_READ(sreq, VolatileFileId) };
	bpf_snprintf(
		argret, MAX_ARGS_LENGTH,
		"InfoType=0x%x|FileInfoClass=0x%x|PersistentFileId=0x%llx|VolatileFileId=0x%llx",
		argdata, sizeof(argdata));
}

static inline void __get_oplock_break_details(struct smb_rqst *rqst, char *argret)
{
	struct smb2_oplock_break *oreq =
		(struct smb2_oplock_break *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = { BPF_CORE_READ(oreq, OplockLevel), BPF_CORE_READ(oreq, PersistentFid),
			  BPF_CORE_READ(oreq, VolatileFid) };
	bpf_snprintf(argret, MAX_ARGS_LENGTH,
		     "OplockLevel=0x%x|PersistentFileId=0x%llx|VolatileFileId=0x%llx", argdata,
		     sizeof(argdata));
}

static inline void get_smb_command_details(u16 command, struct smb_rqst *rqst, char *argret)
{
	switch (command) {
	case SMB2_NEGOTIATE:
		__get_negotiate_details(rqst, argret);
		break;
	case SMB2_SESSION_SETUP:
		__get_session_setup_details(rqst, argret);
		break;
	case SMB2_TREE_CONNECT:
		__get_tree_connect_details(rqst, argret);
		break;
	case SMB2_CREATE:
		__get_create_details(rqst, argret);
		break;
	case SMB2_CLOSE:
		__get_close_details(rqst, argret);
		break;
	case SMB2_FLUSH:
		__get_flush_details(rqst, argret);
		break;
	case SMB2_READ:
		__get_read_details(rqst, argret);
		break;
	case SMB2_WRITE:
		__get_write_details(rqst, argret);
		break;
	case SMB2_LOCK:
		__get_lock_details(rqst, argret);
		break;
	case SMB2_IOCTL:
		__get_ioctl_details(rqst, argret);
		break;
	case SMB2_QUERY_DIRECTORY:
		__get_query_directory_details(rqst, argret);
		break;
	case SMB2_CHANGE_NOTIFY:
		__get_change_notify_details(rqst, argret);
		break;
	case SMB2_QUERY_INFO:
		__get_query_info_details(rqst, argret);
		break;
	case SMB2_SET_INFO:
		__get_set_info_details(rqst, argret);
		break;
	case SMB2_OPLOCK_BREAK:
		__get_oplock_break_details(rqst, argret);
		break;
	case SMB2_LOGOFF:
	case SMB2_TREE_DISCONNECT:
	case SMB2_CANCEL:
	case SMB2_ECHO:
	case SMB2_SERVER_TO_CLIENT_NOTIFICATION:
	default:
		__builtin_memcpy(argret, "No arguments", sizeof("No arguments"));
	}
}

static inline void unroll_smb_rqst(void *ctx, struct smb_rqst *rqst, struct TCP_Server_Info *server,
				   int num_reqs)
{
	struct event event = {};
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct smb2_hdr *shdr = (struct smb2_hdr *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u16 smbcommand = le_to_sys16(BPF_CORE_READ(shdr, Command));

	if (target_cid && target_cid != smbcommand) {
		return;
	}

	if (target_pid && target_pid != pid) {
		return;
	}

	event.session_id = BPF_CORE_READ(shdr, SessionId);
	event.smbcommand = smbcommand;
	event.connection_id = server->conn_id;
	event.server_retval = 0; // needs to be fixed
	event.num_rqst = num_reqs;
	event.pid = pid;
	bpf_get_current_comm(&event.task, sizeof(event.task));

	get_smb_command_details(smbcommand, rqst, event.commandargs);
	// if (map_value) {
	// 	res = bpf_probe_read_str(map_value, MAX_ARGS_LENGTH,
	// 				 get_smb_command_details(smbcommand, rqst));
	// 	if (res > 0) {
	// 		map_value[(res - 1) & (MAX_ARGS_LENGTH - 1)] = 0;
	// 	}
	// }
	// doesnt matter if you add the per-cpu map, the struct (w args) will still be on the stack
	// you can check out a way to have two perf streams emitting output?
	// or store the struct itself in the per-cpu map and the name with it. Maybe, access the map in userspace?
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

// static inline void check2(struct smb_rqst *rqst, struct TCP_Server_Info *server, int retval)
// {
// 	struct kvec *rq_iov;
// 	struct kvec *iov_base;
// 	bpf_core_read(&rq_iov, sizeof(rqst->rq_iov), &rqst->rq_iov);
// 	bpf_core_read(&iov_base, sizeof(rq_iov->iov_base), &rq_iov->iov_base);
// 	struct smb2_hdr shdr = {}; (struct smb2_hdr *)&iov_base;
// 	bpf_core_read(&shdr, sizeof(shdr), &rq_iov);
// 	// check if we can get mid, conn_id and session id
// 	unsigned long long mid = server->CurrentMid;
// 	unsigned long long conn_id = server->conn_id;
// 	unsigned long long session_id;
// 	bpf_printk("mid: %lld, conn_id: %lld, session_id: 0x%llx, retval: %d\n", mid, conn_id,
// 		   shdr.SessionId, retval);
// }

SEC("fentry/compound_send_recv")
int BPF_PROG(smb_network_req_fentry, unsigned int xid, struct cifs_ses *ses,
	     struct TCP_Server_Info *server, const int flags, const int num_rqst,
	     struct smb_rqst *rqst, int *resp_buf_type, struct kvec *resp_iov)
{
	int reqs = num_rqst;

	unroll_smb_rqst(ctx, &rqst[0], server, num_rqst);

	if (num_rqst >= 2) {
		unroll_smb_rqst(ctx, &rqst[1], server, num_rqst);
	}

	if (num_rqst == 3) {
		unroll_smb_rqst(ctx, &rqst[2], server, num_rqst);
	}
	// figure out retvals too: fexit into the same function, store by mid in a map
	return 0;
}

// SEC("fexit/compound_send_recv")
// int BPF_PROG(smb_network_req_fexit, unsigned int xid, struct cifs_ses *ses,
// 	     struct TCP_Server_Info *server, const int flags, const int num_rqst,
// 	     struct smb_rqst *rqst, int *resp_buf_type, struct kvec *resp_iov, int retval)
// {
// 	int reqs = num_rqst;

// 	check2(&rqst[0], server, retval);

// 	if (num_rqst >= 2) {
// 		check2(&rqst[1], server, retval);
// 	}

// 	if (num_rqst == 3) {
// 		check2(&rqst[2], server, retval);
// 	}
// 	// figure out retvals too: fexit into the same function, store by mid in a map
// 	return 0;
// }