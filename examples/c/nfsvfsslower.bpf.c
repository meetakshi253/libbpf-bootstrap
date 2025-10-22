#include "vmlinuxnfs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "nfsvfsslower.h"
#include "nfsvfsops.h"

#define MAX_ENTRIES 2048
#define STR(x) #x

#define container_of_core(ptr, type, member) ({                         \
    void *__mptr = (void *)(ptr);                                       \
    (type *)((char *)__mptr - bpf_core_field_offset(type, member));     \
})

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

static inline int PTR_ERR(const void *ptr)
{
	return (int)ptr;
}

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

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

static inline int trace_all_vfs_exit(void *ctx, const char type, int fn_name, const struct file *filp, const struct inode *ino, int retval)
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

    if (type == FILE && filp != NULL) {
        bpf_probe_read_kernel_str(&event->path, sizeof(event->path), BPF_CORE_READ(filp, f_path.dentry, d_name.name));
    } else if (type == INODE && ino != NULL) {
        struct nfs_inode *nfs_inode_ptr;
        nfs_inode_ptr = container_of_core(ino, struct nfs_inode, vfs_inode);
        __u64 args[] = { BPF_CORE_READ(nfs_inode_ptr, fileid) };
        bpf_snprintf(event->path, sizeof(event->path), "%llu", args, sizeof(args));
    } else {
        event->path[0] = '\0';
    }

    event->pid = pid_tid >> 32;
    event->delta_us = delta_ns / NSEC_PER_USEC;
    event->when_release_us = end_ns / NSEC_PER_USEC;
    event->function = fn_name;
    event->type = type;
    event->retval = retval;
    bpf_get_current_comm(&event->task, sizeof(event->task));
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

SEC("fentry/nfs_llseek_dir")
int BPF_PROG(trace_file_llseek_dir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/generic_read_dir")
int BPF_PROG(trace_file_generic_read_dir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_readdir")
int BPF_PROG(trace_file_readdir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_opendir")
int BPF_PROG(trace_file_opendir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_closedir")
int BPF_PROG(trace_file_closedir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_fsync_dir")
    int BPF_PROG(trace_file_fsync_dir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fexit/nfs_file_read")
int BPF_PROG(trace_file_read_exit, struct kiocb *iocb, void *_, ssize_t retval) {
    struct file *filp = BPF_CORE_READ(iocb, ki_filp);
    return trace_all_vfs_exit(ctx, FILE, nfs_file_read, filp, NULL, retval);
}

SEC("fexit/nfs_file_write")
int BPF_PROG(trace_file_write_exit, struct kiocb *iocb, void *_, ssize_t retval) {
    struct file *filp = BPF_CORE_READ(iocb, ki_filp);
    return trace_all_vfs_exit(ctx, FILE, nfs_file_write, filp, NULL, retval);
}

SEC("fexit/nfs_file_mmap")
int BPF_PROG(trace_file_mmap_exit, struct file *file, void *_, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs_file_mmap, file, NULL, retval);
}

SEC("fexit/nfs4_file_open")
int BPF_PROG(trace_file_nfs4_file_open_exit, void *inode, struct file *filp, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs4_file_open, filp, NULL, retval);
}

SEC("fexit/nfs4_file_flush")
int BPF_PROG(trace_file_nfs4_file_flush_exit, struct file *file, int id, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs4_file_flush, file, NULL, retval);
}

SEC("fexit/nfs_file_release")
int BPF_PROG(trace_file_release_exit, void *inode, struct file *filp, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs_file_release, filp, NULL, retval);
}

SEC("fexit/nfs_file_fsync")
int BPF_PROG(trace_file_fsync_exit, struct file *file, loff_t start, loff_t end, int datasync, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs_file_fsync, file, NULL, retval);
}

SEC("fexit/nfs_lock")
int BPF_PROG(trace_file_lock_exit, struct file *filp, int cmd, struct file_lock *fl, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs_lock, filp, NULL, retval);
}

SEC("fexit/nfs_flock")
int BPF_PROG(trace_file_flock_exit, struct file *filp, int cmd, struct file_lock *fl, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs_flock, filp, NULL, retval);
}

SEC("fexit/nfs_file_splice_read")
int BPF_PROG(trace_file_file_splice_read_exit, struct file *in, loff_t *ppos, struct pipe_inode_info *pipe, size_t len, unsigned int flags, ssize_t retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs_file_splice_read, in, NULL, retval);
}

SEC("fexit/iter_file_splice_write")
int BPF_PROG(trace_file_iter_file_splice_write_exit, void *pipe, struct file *out, void *ppos, size_t len, ssize_t retval) {
    return trace_all_vfs_exit(ctx, FILE, iter_file_splice_write, out, NULL, retval);
}

SEC("fexit/nfs_check_flags")
int BPF_PROG(trace_file_check_flags_exit) {
    return trace_all_vfs_exit(ctx, FILE, nfs_check_flags, NULL, NULL, 0);
}

SEC("fexit/nfs4_setlease")
int BPF_PROG(trace_file_nfs4_setlease_exit, struct file *file, int arg, void **file__lease, void **priv, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs4_setlease, file, NULL, retval);
}

SEC("fexit/nfs_llseek_dir")
int BPF_PROG(trace_file_llseek_dir_exit, struct file *filp, loff_t offset, int whence, loff_t retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs_llseek_dir, filp, NULL, retval);
}

SEC("fexit/generic_read_dir")
int BPF_PROG(trace_file_generic_read_dir_exit, struct file *filp, void *buf, size_t siz, loff_t *ppos, ssize_t retval) {
    return trace_all_vfs_exit(ctx, FILE, generic_read_dir, filp, NULL, retval);
}

SEC("fexit/nfs_readdir")
int BPF_PROG(trace_file_readdir_exit, struct file *file, void *_, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs_readdir, file, NULL, retval);
}

SEC("fexit/nfs_opendir")
int BPF_PROG(trace_file_opendir_exit, struct inode *_, struct file *filp, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs_opendir, filp, NULL, retval);
}

SEC("fexit/nfs_closedir")
int BPF_PROG(trace_file_closedir_exit, struct inode *_, struct file *filp, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs_closedir, filp, NULL, retval);
}

SEC("fexit/nfs_fsync_dir")
int BPF_PROG(trace_file_fsync_dir_exit, struct file *filp, loff_t start, loff_t end, int _, int retval) {
    return trace_all_vfs_exit(ctx, FILE, nfs_fsync_dir, filp, NULL, retval);
}


/* fentry and fexit the VFS Inode callbacks for NFS */

SEC("fentry/nfs_permission") 
int BPF_PROG(trace_inode_permission_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_getattr")
int BPF_PROG(trace_inode_getattr_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_setattr")
int BPF_PROG(trace_inode_setattr_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs4_listxattr")
int BPF_PROG(trace_inode_nfs4_listxattr_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_create")
int BPF_PROG(trace_inode_create_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_lookup")
int BPF_PROG(trace_inode_lookup_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_atomic_open")
int BPF_PROG(trace_inode_atomic_open_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_link")
int BPF_PROG(trace_inode_link_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_unlink")
int BPF_PROG(trace_inode_unlink_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_symlink")
int BPF_PROG(trace_inode_symlink_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_mkdir")
int BPF_PROG(trace_inode_mkdir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_rmdir")
int BPF_PROG(trace_inode_rmdir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_mknod")
int BPF_PROG(trace_inode_mknod_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/nfs_rename")
int BPF_PROG(trace_inode_rename_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fexit/nfs_permission")
int BPF_PROG(trace_inode_permission_exit, void *idmap, struct inode *inode, int mask, int retval) {
    return trace_all_vfs_exit(ctx, INODE, nfs_permission, NULL, inode, retval);
}

SEC("fexit/nfs_getattr")
int BPF_PROG(trace_inode_getattr_exit, void *idmap, struct path *path, void *stat, u32 _, unsigned int __, int retval) {
    struct inode *inode_ptr = BPF_CORE_READ(path, dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_getattr, NULL, inode_ptr, retval);
}

SEC("fexit/nfs_setattr")
int BPF_PROG(trace_inode_setattr_exit, void *idmap, struct dentry *dentry, void *attr, int retval) {
    struct inode *inode_ptr = BPF_CORE_READ(dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_setattr, NULL, inode_ptr, retval);
}

SEC("fexit/nfs4_listxattr")
int BPF_PROG(trace_inode_nfs4_listxattr_exit, struct dentry *dentry, void *list, size_t size, int retval) {
    struct inode *inode_ptr = BPF_CORE_READ(dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs4_listxattr, NULL, inode_ptr, retval);
}

SEC("fexit/nfs_create")
int BPF_PROG(trace_inode_create_exit, void *idmap, struct inode *dir, struct dentry *dentry, umode_t _, bool __, int retval) {
    struct inode *child_inode = BPF_CORE_READ(dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_create, NULL, child_inode, retval);
}

SEC("fexit/nfs_lookup")
int BPF_PROG(trace_inode_lookup_exit, struct inode *dir, struct dentry *dentry, unsigned int _, struct dentry *retval) {
    struct inode *child_inode = BPF_CORE_READ(dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_lookup, NULL, child_inode, IS_ERR_OR_NULL(retval) ? PTR_ERR(retval) : 0);
}

SEC("fexit/nfs_atomic_open")
int BPF_PROG(trace_inode_atomic_open_exit, struct inode *dir, struct dentry *dentry, void *file, unsigned _, umode_t __, int retval) {
    struct inode *child_inode = BPF_CORE_READ(dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_atomic_open, NULL, child_inode, retval);
}

SEC("fexit/nfs_link")
int BPF_PROG(trace_inode_link_exit, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry, int retval) {
    struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_link, NULL, old_inode, retval);
}

SEC("fexit/nfs_unlink")
int BPF_PROG(trace_inode_unlink_exit, struct inode *dir, struct dentry *dentry, int retval) {
    struct inode *child_inode = BPF_CORE_READ(dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_unlink, NULL, child_inode, retval);
}

SEC("fexit/nfs_symlink")
int BPF_PROG(trace_inode_symlink_exit, void *idmap, struct inode *dir, struct dentry *dentry, void *symname, int retval) {
    struct inode *child_inode = BPF_CORE_READ(dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_symlink, NULL, child_inode, retval);
}

SEC("fexit/nfs_mkdir")
int BPF_PROG(trace_inode_mkdir_exit, void *idmap, struct inode *dir, struct dentry *dentry, umode_t _, int retval) {
    struct inode *child_inode = BPF_CORE_READ(dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_mkdir, NULL, child_inode, retval);
}

SEC("fexit/nfs_rmdir")
int BPF_PROG(trace_inode_rmdir_exit, struct inode *dir, struct dentry *dentry, int retval) {
    struct inode *child_inode = BPF_CORE_READ(dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_rmdir, NULL, child_inode, retval);
}

SEC("fexit/nfs_mknod")
int BPF_PROG(trace_inode_mknod_exit, void *idmap, struct inode *dir, struct dentry *dentry, umode_t _, dev_t __, int retval) {
    struct inode *child_inode = BPF_CORE_READ(dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_mknod, NULL, child_inode, retval);
}

SEC("fexit/nfs_rename")
int BPF_PROG(trace_inode_rename_exit, void *idmap, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int _, int retval) {
    struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
    return trace_all_vfs_exit(ctx, INODE, nfs_rename, NULL, old_inode, retval);
}





