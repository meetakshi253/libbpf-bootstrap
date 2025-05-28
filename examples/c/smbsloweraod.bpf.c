// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinuxcifs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_endian_le.h"
#include "smbdiag.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u64 min_lat_ns = 0;
const volatile int wakeup_data_size = 256;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SMB_COMMANDS); /* SMB commands */
	__type(key, __u16); /* Command code */
	__type(value, __u8); /* Dummy value */
} denylist SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES * 4096);
	__type(key, struct mid_q_entry *);
	__type(value, struct partial_event);
} temp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENTRIES * 4096); // should always be a multiple of the page size
} rb SEC(".maps");

static __always_inline long get_flags()
{
    long sz;
    if (!wakeup_data_size)
        return 0;
    sz = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
    return sz >= wakeup_data_size ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

SEC("fexit/smb2_mid_entry_alloc")
int BPF_PROG(mid_alloc_fexit, struct smb2_hdr *shdr, struct TCP_Server_Info *server,
struct mid_q_entry *mid_struct)
{
	(void)server;
	struct partial_event e;
	__u16 cid;
	cid = __builtin_preserve_access_index(({shdr->Command; }));
	e.smbcommand = bpf_le16_to_cpu(cid);

	__u8 *blocked = bpf_map_lookup_elem(&denylist, &e.smbcommand);
	if (blocked) {
		bpf_printk("dropped command %d", e.smbcommand);
		return 0;
	}

	e.metric.latency_ns = bpf_ktime_get_ns();
	e.session_id = __builtin_preserve_access_index(({shdr->SessionId; }));
	e.mid = __builtin_preserve_access_index(({mid_struct->mid; }));
	if (__builtin_preserve_access_index(({shdr->NextCommand; })))
		e.is_compounded = 1;
	else
		e.is_compounded = 0;
	bpf_map_update_elem(&temp, &mid_struct, &e, BPF_NOEXIST);
	return 0;
}

SEC("fentry/__release_mid")
int BPF_PROG(mid_release_fentry, struct kref *refcount) {
	struct partial_event *pe;
	struct event *e;
	long flag = get_flags();

	/* reserve space in the ringbuffer first */
	e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!e) {
		bpf_printk("bpf_ringbuf_reserve failed");
		return 0;
	}

	const typeof(((struct mid_q_entry *)0)->refcount) *__mptr = (refcount);
	struct mid_q_entry *mid_struct =
		(struct mid_q_entry *)((char *)__mptr - offsetof(struct mid_q_entry, refcount));

	pe = bpf_map_lookup_elem(&temp, &mid_struct);
	if (!pe) {
		bpf_printk("no op %p", &mid_struct);
		bpf_ringbuf_discard(e, flag);
		return 0;
	}
	bpf_map_delete_elem(&temp, &mid_struct);
	
	e->cmd_end_time_ns = bpf_ktime_get_ns();
	e->metric.latency_ns = e->cmd_end_time_ns - pe->metric.latency_ns;

	if (e->metric.latency_ns < min_lat_ns) {
		bpf_printk("latency %lld is less than %lld", e->metric.latency_ns, min_lat_ns);
		bpf_ringbuf_discard(e, flag);
		return 0;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->session_id = bpf_le64_to_cpu(pe->session_id);
	e->mid = bpf_le64_to_cpu(pe->mid);
	e->smbcommand = pe->smbcommand;
	e->is_compounded = pe->is_compounded;
	e->tool = SMBSLOWER;
	bpf_get_current_comm(&e->task, sizeof(e->task));
	bpf_ringbuf_submit(e, flag);

	return 0;
}