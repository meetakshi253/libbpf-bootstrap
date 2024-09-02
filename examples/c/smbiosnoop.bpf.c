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

//eBPF verifier loves to complain about the stack limit, so we use a per_cpu_array to store the arguments for each smbcommand
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_ARGS_LENGTH);
	__uint(max_entries, 1);
} smbargs SEC(".maps");

static inline int system_endianness()
{
	int n = 1;
	// 0 for little endian, 1 for big endian
	return (*(char *)&n == 1) ? 0 : 1;
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
	char args[MAX_ARGS_LENGTH] = {};

	struct smb2_negotiate_req *nreq =
		(struct smb2_negotiate_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = {
		le_to_sys16(BPF_CORE_READ(nreq, SecurityMode)),
		le_to_sys16(BPF_CORE_READ(nreq, DialectCount)),
	};
	bpf_snprintf(argret, MAX_ARGS_LENGTH, "SecurityMode=0x%x, DialectCount=%d", argdata,
		     sizeof(argdata));
}

static inline void __get_session_setup_details(struct smb_rqst *rqst, char *argret)
{
	char args[MAX_ARGS_LENGTH] = {};

	struct smb2_sess_setup_req *sreq =
		(struct smb2_sess_setup_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = {
		le_to_sys32(BPF_CORE_READ(sreq, Capabilities)),
		le_to_sys16(BPF_CORE_READ(sreq, Channel)),
		le_to_sys64(BPF_CORE_READ(sreq, PreviousSessionId)),
	};
	bpf_snprintf(argret, MAX_ARGS_LENGTH,
		     "Capabilities=0x%x, Channel=%d, PreviousSessionId=0x%llx", argdata,
		     sizeof(argdata));
}

static inline void __get_tree_connect_details(struct smb_rqst *rqst, char *argret)
{
	char args[MAX_ARGS_LENGTH] = {};

	struct smb2_tree_connect_req *treq =
		(struct smb2_tree_connect_req *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u64 argdata[] = {
		le_to_sys16(BPF_CORE_READ(treq, Flags)),
	};
	bpf_snprintf(argret, MAX_ARGS_LENGTH, "Flags=0x%x", argdata, sizeof(argdata));
}

static inline void get_smb_command_details(u16 command, struct smb_rqst *rqst, char *argret)
{
	switch (command) {
	case SMB2_NEGOTIATE:
		__get_negotiate_details(rqst, argret);
	case SMB2_SESSION_SETUP:
		__get_session_setup_details(rqst, argret);
	case SMB2_LOGOFF:
		__builtin_memcpy(argret, "No arguments", sizeof("No arguments"));
	case SMB2_TREE_CONNECT:
		__get_tree_connect_details(rqst, argret);
	}
}

static inline void unroll_smb_rqst(void *ctx, struct smb_rqst *rqst)
{
	struct event event = {};
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct smb2_hdr *shdr = (struct smb2_hdr *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	u16 smbcommand = le_to_sys16(BPF_CORE_READ(shdr, Command));

	event.session_id = BPF_CORE_READ(shdr, SessionId);
	event.smbcommand = smbcommand;
	event.server_retval = 8;
	event.pid = pid;
	get_smb_command_details(smbcommand, rqst, &event.commandargs);
	bpf_get_current_comm(&event.task, sizeof(event.task));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

SEC("fentry/compound_send_recv")
int BPF_PROG(smb_network_req_fentry, unsigned int xid, struct cifs_ses *ses,
	     struct TCP_Server_Info *server, const int flags, const int num_rqst,
	     struct smb_rqst *rqst, int *resp_buf_type, struct kvec *resp_iov)
{
	int reqs = num_rqst;

	unroll_smb_rqst(ctx, &rqst[0]);

	if (num_rqst >= 2) {
		unroll_smb_rqst(ctx, &rqst[1]);
	}

	if (num_rqst == 3) {
		unroll_smb_rqst(ctx, &rqst[2]);
	}

	// struct event event = {};
	// u32 pid = bpf_get_current_pid_tgid() >> 32;
	// struct smb2_hdr *shdr = (struct smb2_hdr *)BPF_CORE_READ(rqst, rq_iov, iov_base);
	// u16 smbcommand = le_to_sys16(BPF_CORE_READ(shdr, Command));

	// // extract the args
	// // char *commandargs = get_smb_command_details(smbcommand, rqst);
	// // __builtin_memcpy(&event.commandargs, commandargs, sizeof(event.commandargs));

	// event.session_id = BPF_CORE_READ(shdr, SessionId); //this is also printing garbage value
	// event.smbcommand = smbcommand;
	// event.server_retval = 8;
	// event.pid = pid;
	// bpf_get_current_comm(&event.task, sizeof(event.task));
	return 0;
}