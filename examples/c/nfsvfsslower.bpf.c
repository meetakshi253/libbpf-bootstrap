#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "nfsvfsslower.h"
#include "nfsvfsops.h"

#define MAX_ENTRIES 2048
#define STR(x) #x

const volatile __u64 min_lat_ns = 0;
const volatile pid_t target_pid = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} temp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENTRIES * 4096); // should always be a multiple of the page size
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nfsvfsrb SEC(".maps");

static inline int trace_all_vfs_entry(void *ctx)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    pid_t pid = pid_tid >> 32;

    if (target_pid && target_pid != pid) // filter for process id
        return 0;
    
    u64 start = bpf_ktime_get_ns();
    bpf_map_update_elem(&temp, &pid_tid, &start, BPF_ANY);
    return 0;
}

static inline int trace_all_vfs_exit(void *ctx, const char type[], int fn_name, const char path[], int retval)
{
    struct event *event;
    __u64 end_ns, delta_ns, *start_ns;
    u64 pid_tid = bpf_get_current_pid_tgid();

    start_ns = bpf_map_lookup_elem(&temp, &pid_tid);
    if (!start_ns) {
        return 0;
    }

    bpf_map_delete_elem(&temp, &pid_tid);

    event = bpf_ringbuf_reserve(&nfsvfsrb, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    end_ns = bpf_ktime_get_ns();
    delta_ns = end_ns - *start_ns;
    if (delta_ns <= min_lat_ns) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // let us see if we can extract the file names
    event->pid = pid_tid >> 32;
    event->delta_us = delta_ns / NSEC_PER_USEC;
    event->when_release_us = end_ns / NSEC_PER_USEC;
    event->function = fn_name;
    // event->retval = PT_REGS_RC(ctx);
    event->retval = retval;
    bpf_get_current_comm(&event->task, sizeof(event->task));
    __builtin_memcpy(&event->path, path, sizeof(event->path));
    __builtin_memcpy(&event->type, type, sizeof(event->type));

    bpf_printk("executed");

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* fentry and fexit the VFS File callbacks for NFS */
SEC("fentry/nfs_file_read")
int BPF_PROG(trace_file_read_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_file_write")
int BPF_PROG(trace_file_write_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_file_mmap")
int BPF_PROG(trace_file_mmap_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs4_file_open")
int BPF_PROG(trace_file_nfs4_file_open_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs4_file_flush")
int BPF_PROG(trace_file_nfs4_file_flush_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_file_release")
int BPF_PROG(trace_file_release_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_file_fsync")
int BPF_PROG(trace_file_fsync_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_lock")
int BPF_PROG(trace_file_lock_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_flock")
int BPF_PROG(trace_file_flock_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_file_splice_read")
int BPF_PROG(trace_file_file_splice_read_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/iter_file_splice_write")
int BPF_PROG(trace_file_iter_file_splice_write_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_check_flags")
int BPF_PROG(trace_file_check_flags_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs4_setlease")
int BPF_PROG(trace_file_nfs4_setlease_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fexit/nfs_file_read")
int BPF_PROG(trace_file_read_exit, struct kiocb *iocb, void *_, ssize_t retval) {
    // struct path file_path = BPF_CORE_READ(iocb, ki_filp, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(iocb, ki_filp, f_path.dentry, d_name.name));
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    return trace_all_vfs_exit(ctx, "FILE", nfs_file_read, path_buffer, retval);
}

SEC("fexit/nfs_file_write")
int BPF_PROG(trace_file_write_exit, struct kiocb *iocb, void *_, ssize_t retval) {
    // struct path file_path = BPF_CORE_READ(iocb, ki_filp, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(iocb, ki_filp, f_path.dentry, d_name.name));
    return trace_all_vfs_exit(ctx, "FILE", nfs_file_write, path_buffer, retval);
}

SEC("fexit/nfs_file_mmap")
int BPF_PROG(trace_file_mmap_exit, struct file *file, void *_, int retval) {
    // struct path file_path = BPF_CORE_READ(file, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(file, f_path.dentry, d_name.name));
    return trace_all_vfs_exit(ctx, "FILE", nfs_file_mmap, path_buffer, retval);
}

SEC("fexit/nfs4_file_open")
int BPF_PROG(trace_file_nfs4_file_open_exit, void *inode, struct file *filp, int retval) {
    // struct path file_path = BPF_CORE_READ(filp, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(filp, f_path.dentry, d_name.name));
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    return trace_all_vfs_exit(ctx, "FILE", nfs4_file_open, path_buffer, retval);
}

SEC("fexit/nfs4_file_flush")
int BPF_PROG(trace_file_nfs4_file_flush_exit, struct file *file, int id, int retval) {
    // struct path file_path = BPF_CORE_READ(file, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(file, f_path.dentry, d_name.name));
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    return trace_all_vfs_exit(ctx, "FILE", nfs4_file_flush, path_buffer, retval);
}

SEC("fexit/nfs_file_release")
int BPF_PROG(trace_file_release_exit, void *inode, struct file *filp, int retval) {
    // struct path file_path = BPF_CORE_READ(filp, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(filp, f_path.dentry, d_name.name));
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    return trace_all_vfs_exit(ctx, "FILE", nfs_file_release, path_buffer, retval);
}

SEC("fexit/nfs_file_fsync")
int BPF_PROG(trace_file_fsync_exit, struct file *file, loff_t start, loff_t end, int datasync, int retval) {
    // struct path file_path = BPF_CORE_READ(file, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(file, f_path.dentry, d_name.name));
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    return trace_all_vfs_exit(ctx, "FILE", nfs_file_fsync, path_buffer, retval);
}

SEC("fexit/nfs_lock")
int BPF_PROG(trace_file_lock_exit, struct file *filp, int cmd, struct file_lock *fl, int retval) {
    // struct path file_path = BPF_CORE_READ(filp, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(filp, f_path.dentry, d_name.name));
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    return trace_all_vfs_exit(ctx, "FILE", nfs_lock, path_buffer, retval);
}

SEC("fexit/nfs_flock")
int BPF_PROG(trace_file_flock_exit, struct file *filp, int cmd, struct file_lock *fl, int retval) {
    // struct path file_path = BPF_CORE_READ(filp, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(filp, f_path.dentry, d_name.name));
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    return trace_all_vfs_exit(ctx, "FILE", nfs_flock, path_buffer, retval);
}

SEC("fexit/nfs_file_splice_read")
int BPF_PROG(trace_file_file_splice_read_exit, struct file *in, loff_t *ppos, struct pipe_inode_info *pipe, size_t len, unsigned int flags, ssize_t retval) {
    // struct path file_path = BPF_CORE_READ(in, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(in, f_path.dentry, d_name.name));
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    return trace_all_vfs_exit(ctx, "FILE", nfs_file_splice_read, path_buffer, retval);
}

SEC("fexit/iter_file_splice_write")
int BPF_PROG(trace_file_iter_file_splice_write_exit, void *pipe, struct file *out, void *ppos, size_t len, ssize_t retval) {
    // struct path file_path = BPF_CORE_READ(out, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(out, f_path.dentry, d_name.name));
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    return trace_all_vfs_exit(ctx, "FILE", iter_file_splice_write, path_buffer, 0);
}

SEC("fexit/nfs_check_flags")
int BPF_PROG(trace_file_check_flags_exit) {
    return trace_all_vfs_exit(ctx, "FILE", nfs_check_flags, "", 0);
}

SEC("fexit/nfs4_setlease")
int BPF_PROG(trace_file_nfs4_setlease_exit, struct file *file, int arg, void **file__lease, void **priv, int retval) {
    // struct path file_path = BPF_CORE_READ(file, f_path);
    char path_buffer[MAX_PATH_LENGTH] = {};
    bpf_probe_read_kernel_str(&path_buffer, sizeof(path_buffer), BPF_CORE_READ(file, f_path.dentry, d_name.name));
    // long res = bpf_d_path(&file_path, path_buffer, sizeof(path_buffer));
    return trace_all_vfs_exit(ctx, "FILE", nfs4_setlease, path_buffer, retval);
}








