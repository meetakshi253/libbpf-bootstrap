#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "nfsdiag.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u64 min_lat_ns = 0;
const volatile int wakeup_data_size = 256;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_NFS_COMMANDS); /* SMB commands */
	__type(key, __u16); /* Command code */
	__type(value, __u8); /* Dummy value */
} denylist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES * 4096);
	__type(key, struct rpc_task *); /* ptr to rpc_task */
	__type(value, struct nfs_partial_event);
} temp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENTRIES * 4096); // should always be a multiple of the page size
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} aodrb SEC(".maps");

static __always_inline long get_flags()
{
	long sz;
	if (!wakeup_data_size)
		return 0;
	sz = bpf_ringbuf_query(&aodrb, BPF_RB_AVAIL_DATA);
	return sz >= wakeup_data_size ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

SEC("fentry/nfs4_setup_sequence")
int BPF_PROG(nfs4_setup_sequence_entry, struct nfs_client *client, struct nfs4_sequence_args *args,
	     struct nfs4_sequence_res *res, struct rpc_task *task)
{
	(void)args;
	(void)res;
	struct nfs_partial_event e;
	__u32 cid;

	cid = BPF_CORE_READ(task, tk_msg.rpc_proc, p_statidx);
	bpf_printk("%d", cid);

	e.nfscommand = cid;
	__u8 *blocked = bpf_map_lookup_elem(&denylist, &e.nfscommand);
	if (blocked) {
		bpf_printk("blocked");
		return 0;
	}

	bpf_printk("enqueued %d", cid);

	e.metric.latency_ns = bpf_ktime_get_ns();
	bpf_map_update_elem(&temp, &task, &e, BPF_NOEXIST);
	return 0;
}

SEC("fentry/rpc_exit_task")
int BPF_PROG(rpc_done_entry, struct rpc_task *task)
{
	struct nfs_partial_event *pe;
	struct event *e;
	long flag = get_flags();

	int cid = BPF_CORE_READ(task, tk_msg.rpc_proc, p_statidx);
	bpf_printk("will try to dequeued %d", cid);

	/* reserve space in the ringbuffer first */
	e = bpf_ringbuf_reserve(&aodrb, sizeof(struct event), 0);
	if (!e) {
		bpf_printk("bpf_ringbuf_reserve failed");
		return 0;
	}

	pe = bpf_map_lookup_elem(&temp, &task);
	if (!pe) {
		bpf_printk("no op %p", &task);
		bpf_ringbuf_discard(e, get_flags());
		return 0;
	}
	bpf_map_delete_elem(&temp, &task);

	e->cmd_end_time_ns = bpf_ktime_get_ns();
	e->metric.latency_ns = e->cmd_end_time_ns - pe->metric.latency_ns;

	if (e->metric.latency_ns < min_lat_ns) {
		bpf_ringbuf_discard(e, get_flags());
		return 0;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->command = pe->nfscommand;
	e->mid = 0;
	e->tool = NFSSLOWER;
	bpf_get_current_comm(&e->task, sizeof(e->task));
	bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);

	return 0;
}
