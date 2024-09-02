#include "vmlinuxcifs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "smbvfsslower.h"
#include "smbvfsops.h"

#define MAX_ENTRIES 8192
#define STR(x) #x

const volatile __u64 min_lat_ns = 0;
const volatile pid_t target_pid = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u64);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static inline void copy_string(char destination[], const char source[]) {
	int i = 0;
	while(source[i]) {
		destination[i] = source[i];
		i++;
	}
	destination[i] = '\0';
}

static inline int trace_all_vfs_entry(void *ctx)
{
	u64 pid_tid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tid >> 32;

	if (target_pid && target_pid != pid) // filter for process id
		return 0;

	u64 start = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &pid_tid, &start, BPF_ANY);
	return 0;
}

static inline int trace_all_vfs_exit(void *ctx, const char type[], const char fn_name[])
{
	struct event event = {};
	__u64 end_ns, delta_ns, *start_ns;
	u64 pid_tid = bpf_get_current_pid_tgid();

	start_ns = bpf_map_lookup_elem(&starts, &pid_tid);
	if (!start_ns) {
		return 0;
	}

	bpf_map_delete_elem(&starts, &pid_tid);

	end_ns = bpf_ktime_get_ns();
	delta_ns = end_ns - *start_ns;
	if (delta_ns <= min_lat_ns)
		return 0;

	copy_string(event.type, type);
	copy_string(event.function, fn_name);
	event.pid = pid_tid >> 32;
	event.delta_us = delta_ns / NSEC_PER_USEC;
	event.when_release_us = end_ns / NSEC_PER_USEC;
	bpf_get_current_comm(&event.task, sizeof(event.task));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

/* fentry and fexit the VFS File callbacks for CIFS */
SEC("fentry/cifs_loose_read_iter")
int BPF_PROG(trace_file_loose_read_iter_entry) {
	return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_file_write_iter")
int BPF_PROG(trace_file_file_write_iter_entry) {
	return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_open")
int BPF_PROG(trace_file_open_entry) {
	return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_close")
int BPF_PROG(trace_file_close_entry) {
	return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_lock")
int BPF_PROG(trace_file_lock_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_flock")
int BPF_PROG(trace_file_flock_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_fsync")
int BPF_PROG(trace_file_fsync_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_flush")
int BPF_PROG(trace_file_flush_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_file_mmap")
int BPF_PROG(trace_file_file_mmap_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/filemap_splice_read")
int BPF_PROG(trace_file_filemap_splice_read_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/iter_file_splice_write")
int BPF_PROG(trace_file_iter_file_splice_write_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_llseek")
int BPF_PROG(trace_file_llseek_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_ioctl")
int BPF_PROG(trace_file_ioctl_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_copy_file_range")
int BPF_PROG(trace_file_copy_file_range_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_remap_file_range")
int BPF_PROG(trace_file_remap_file_range_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_setlease")
int BPF_PROG(trace_file_setlease_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_fallocate")
int BPF_PROG(trace_file_fallocate_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_strict_readv")
int BPF_PROG(trace_file_strict_readv_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_strict_writev")
int BPF_PROG(trace_file_strict_writev_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_strict_fsync")
int BPF_PROG(trace_file_strict_fsync_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_file_strict_mmap")
int BPF_PROG(trace_file_file_strict_mmap_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_direct_readv")
int BPF_PROG(trace_file_direct_readv_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_direct_writev")
int BPF_PROG(trace_file_direct_writev_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/copy_splice_read")
int BPF_PROG(trace_file_copy_splice_read_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_readdir")
int BPF_PROG(trace_file_readdir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_closedir")
int BPF_PROG(trace_file_closedir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/generic_read_dir")
int BPF_PROG(trace_file_generic_read_dir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/generic_file_llseek")
int BPF_PROG(trace_file_generic_file_llseek_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_dir_fsync")
int BPF_PROG(trace_file_dir_fsync_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fexit/cifs_loose_read_iter")
int BPF_PROG(trace_file_loose_read_iter_exit) {
	return trace_all_vfs_exit(ctx, "FILE", STR(cifs_loose_read_iter));
}

SEC("fexit/cifs_file_write_iter")
int BPF_PROG(trace_file_file_write_iter_exit) {
	return trace_all_vfs_exit(ctx, "FILE", STR(cifs_file_write_iter));
}

SEC("fexit/cifs_open")
int BPF_PROG(trace_file_open_exit) {
	return trace_all_vfs_exit(ctx, "FILE", STR(cifs_open));
}

SEC("fexit/cifs_close")
int BPF_PROG(trace_file_close_exit) {
	return trace_all_vfs_exit(ctx, "FILE", STR(cifs_open));
}

SEC("fexit/cifs_lock")
int BPF_PROG(trace_file_lock_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_lock));
}

SEC("fexit/cifs_flock")
int BPF_PROG(trace_file_flock_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_flock));
}

SEC("fexit/cifs_fsync")
int BPF_PROG(trace_file_fsync_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_fsync));
}

SEC("fexit/cifs_flush")
int BPF_PROG(trace_file_flush_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_flush));
}

SEC("fexit/cifs_file_mmap")
int BPF_PROG(trace_file_file_mmap_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_file_mmap));
}

SEC("fexit/filemap_splice_read")
int BPF_PROG(trace_file_filemap_splice_read_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(filemap_splice_read));
}

SEC("fexit/iter_file_splice_write")
int BPF_PROG(trace_file_iter_file_splice_write_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(iter_file_splice_write));
}

SEC("fexit/cifs_llseek")
int BPF_PROG(trace_file_llseek_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_llseek));
}

SEC("fexit/cifs_ioctl")
int BPF_PROG(trace_file_ioctl_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_ioctl));
}

SEC("fexit/cifs_copy_file_range")
int BPF_PROG(trace_file_copy_file_range_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_copy_file_range));
}

SEC("fexit/cifs_remap_file_range")
int BPF_PROG(trace_file_remap_file_range_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_remap_file_range));
}

SEC("fexit/cifs_setlease")
int BPF_PROG(trace_file_setlease_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_setlease));
}

SEC("fexit/cifs_fallocate")
int BPF_PROG(trace_file_fallocate_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_fallocate));
}

SEC("fexit/cifs_strict_readv")
int BPF_PROG(trace_file_strict_readv_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_strict_readv));
}

SEC("fexit/cifs_strict_writev")
int BPF_PROG(trace_file_strict_writev_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_strict_writev));
}

SEC("fexit/cifs_strict_fsync")
int BPF_PROG(trace_file_strict_fsync_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_strict_fsync));
}

SEC("fexit/cifs_file_strict_mmap")
int BPF_PROG(trace_file_file_strict_mmap_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_file_strict_mmap));
}

SEC("fexit/cifs_direct_readv")
int BPF_PROG(trace_file_direct_readv_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_direct_readv));
}

SEC("fexit/cifs_direct_writev")
int BPF_PROG(trace_file_direct_writev_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_direct_writev));
}

SEC("fexit/copy_splice_read")
int BPF_PROG(trace_file_copy_splice_read_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(copy_splice_read));
}

SEC("fexit/cifs_readdir")
int BPF_PROG(trace_file_readdir_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_readdir));
}

SEC("fexit/cifs_closedir")
int BPF_PROG(trace_file_closedir_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_closedir));
}

SEC("fexit/generic_read_dir")
int BPF_PROG(trace_file_generic_read_dir_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(generic_read_dir));
}

SEC("fexit/generic_file_llseek")
int BPF_PROG(trace_file_generic_file_llseek_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(generic_file_llseek));
}

SEC("fexit/cifs_dir_fsync")
int BPF_PROG(trace_file_dir_fsync_exit) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_dir_fsync));
}


/* fexit and fexit the VFS Inode callbacks for CIFS */
SEC("fentry/cifs_create")
int BPF_PROG(trace_inode_create_entry) {
	return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_atomic_open")
int BPF_PROG(trace_inode_atomic_open_entry) {
	return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_lookup")
int BPF_PROG(trace_inode_lookup_entry) {
	return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_getattr")
int BPF_PROG(trace_inode_getattr_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_unlink")
int BPF_PROG(trace_inode_unlink_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_hardlink")
int BPF_PROG(trace_inode_hardlink_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_mkdir")
int BPF_PROG(trace_inode_mkdir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_rmdir")
int BPF_PROG(trace_inode_rmdir_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_rename2")
int BPF_PROG(trace_inode_rename2_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_permission")
int BPF_PROG(trace_inode_permission_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_setattr")
int BPF_PROG(trace_inode_setattr_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_symlink")
int BPF_PROG(trace_inode_symlink_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_mknod")
int BPF_PROG(trace_inode_mknod_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_listxattr")
int BPF_PROG(trace_inode_listxattr_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_get_acl")
int BPF_PROG(trace_inode_get_acl_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_set_acl")
int BPF_PROG(trace_inode_set_acl_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_fiemap")
int BPF_PROG(trace_inode_fiemap_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_get_link")
int BPF_PROG(trace_inode_get_link_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fexit/cifs_create")
int BPF_PROG(trace_inode_create_exit) {
	return trace_all_vfs_exit(ctx, "INODE", STR(cifs_create));
}

SEC("fexit/cifs_atomic_open")
int BPF_PROG(trace_inode_atomic_open_exit) {
	return trace_all_vfs_exit(ctx, "INODE", STR(cifs_atomic_open));
}

SEC("fexit/cifs_lookup")
int BPF_PROG(trace_inode_lookup_exit) {
	return trace_all_vfs_exit(ctx, "INODE", STR(cifs_lookup));
}

SEC("fexit/cifs_getattr")
int BPF_PROG(trace_inode_getattr_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_getattr));
}

SEC("fexit/cifs_unlink")
int BPF_PROG(trace_inode_unlink_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_unlink));
}

SEC("fexit/cifs_hardlink")
int BPF_PROG(trace_inode_hardlink_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_hardlink));
}

SEC("fexit/cifs_mkdir")
int BPF_PROG(trace_inode_mkdir_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_mkdir));
}

SEC("fexit/cifs_rmdir")
int BPF_PROG(trace_inode_rmdir_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_rmdir));
}

SEC("fexit/cifs_rename2")
int BPF_PROG(trace_inode_rename2_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_rename2));
}

SEC("fexit/cifs_permission")
int BPF_PROG(trace_inode_permission_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_permission));
}

SEC("fexit/cifs_setattr")
int BPF_PROG(trace_inode_setattr_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_setattr));
}

SEC("fexit/cifs_symlink")
int BPF_PROG(trace_inode_symlink_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_symlink));
}

SEC("fexit/cifs_mknod")
int BPF_PROG(trace_inode_mknod_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_mknod));
}

SEC("fexit/cifs_listxattr")
int BPF_PROG(trace_inode_listxattr_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_listxattr));
}

SEC("fexit/cifs_get_acl")
int BPF_PROG(trace_inode_get_acl_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_get_acl));
}

SEC("fexit/cifs_set_acl")
int BPF_PROG(trace_inode_set_acl_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_set_acl));
}

SEC("fexit/cifs_fiemap")
int BPF_PROG(trace_inode_fiemap_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_fiemap));
}

SEC("fexit/cifs_get_link")
int BPF_PROG(trace_inode_get_link_exit) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_get_link));
}


/* fexit and fexit the VFS Super-block callbacks for CIFS */
SEC("fentry/cifs_statfs")
int BPF_PROG(trace_super_statfs_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_alloc_inode")
int BPF_PROG(trace_super_alloc_inode_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_write_inode")
int BPF_PROG(trace_super_write_inode_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_free_inode")
int BPF_PROG(trace_super_free_inode_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_drop_inode")
int BPF_PROG(trace_super_drop_inode_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_evict_inode")
int BPF_PROG(trace_super_evict_inode_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_show_devname")
int BPF_PROG(trace_super_show_devname_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_show_options")
int BPF_PROG(trace_super_show_options_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_umount_begin")
int BPF_PROG(trace_super_umount_begin_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_freeze")
int BPF_PROG(trace_super_freeze_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fexit/cifs_statfs")
int BPF_PROG(trace_super_statfs_exit) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_statfs));
}

SEC("fexit/cifs_alloc_inode")
int BPF_PROG(trace_super_alloc_inode_exit) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_alloc_inode));
}

SEC("fexit/cifs_write_inode")
int BPF_PROG(trace_super_write_inode_exit) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_write_inode));
}

SEC("fexit/cifs_free_inode")
int BPF_PROG(trace_super_free_inode_exit) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_free_inode));
}

SEC("fexit/cifs_drop_inode")
int BPF_PROG(trace_super_drop_inode_exit) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_drop_inode));
}

SEC("fexit/cifs_evict_inode")
int BPF_PROG(trace_super_evict_inode_exit) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_evict_inode));
}

SEC("fexit/cifs_show_devname")
int BPF_PROG(trace_super_show_devname_exit) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_show_devname));
}

SEC("fexit/cifs_show_options")
int BPF_PROG(trace_super_show_options_exit) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_show_options));
}

SEC("fexit/cifs_umount_begin")
int BPF_PROG(trace_super_umount_begin_exit) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_umount_begin));
}

SEC("fexit/cifs_freeze")
int BPF_PROG(trace_super_freeze_exit) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_freeze));
}


/* fexit and fexit the VFS Address-space callbacks for CIFS */
SEC("fentry/cifs_read_folio")
int BPF_PROG(trace_adspace_read_folio_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_readahead")
int BPF_PROG(trace_adspace_readahead_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_writepages")
int BPF_PROG(trace_adspace_writepages_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_write_begin")
int BPF_PROG(trace_adspace_write_begin_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_write_end")
int BPF_PROG(trace_adspace_write_end_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/netfs_dirty_folio")
int BPF_PROG(trace_adspace_dirty_folio_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_release_folio")
int BPF_PROG(trace_adspace_release_folio_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_direct_io")
int BPF_PROG(trace_adspace_direct_io_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_invalidate_folio")
int BPF_PROG(trace_adspace_invalidate_folio_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_launder_folio")
int BPF_PROG(trace_adspace_launder_folio_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/filemap_migrate_folio")
int BPF_PROG(trace_adspace_migrate_folio_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_swap_activate")
int BPF_PROG(trace_adspace_swap_activate_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fentry/cifs_swap_deactivate")
int BPF_PROG(trace_adspace_swap_deactivate_entry) {
    return trace_all_vfs_entry(ctx);
}

SEC("fexit/cifs_read_folio")
int BPF_PROG(trace_adspace_read_folio_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_read_folio));
}

SEC("fexit/cifs_readahead")
int BPF_PROG(trace_adspace_readahead_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_readahead));
}

SEC("fexit/cifs_writepages")
int BPF_PROG(trace_adspace_writepages_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_writepages));
}

SEC("fexit/cifs_write_begin")
int BPF_PROG(trace_adspace_write_begin_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_write_begin));
}

SEC("fexit/cifs_write_end")
int BPF_PROG(trace_adspace_write_end_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_write_end));
}

SEC("fexit/netfs_dirty_folio")
int BPF_PROG(trace_adspace_dirty_folio_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(netfs_dirty_folio));
}

SEC("fexit/cifs_release_folio")
int BPF_PROG(trace_adspace_release_folio_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_release_folio));
}

SEC("fexit/cifs_direct_io")
int BPF_PROG(trace_adspace_direct_io_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_direct_io));
}

SEC("fexit/cifs_invalidate_folio")
int BPF_PROG(trace_adspace_invalidate_folio_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_invalidate_folio));
}

SEC("fexit/cifs_launder_folio")
int BPF_PROG(trace_adspace_launder_folio_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_launder_folio));
}

SEC("fexit/filemap_migrate_folio")
int BPF_PROG(trace_adspace_migrate_folio_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(filemap_migrate_folio));
}

SEC("fexit/cifs_swap_activate")
int BPF_PROG(trace_adspace_swap_activate_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_swap_activate));
}

SEC("fexit/cifs_swap_deactivate")
int BPF_PROG(trace_adspace_swap_deactivate_exit) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_swap_deactivate));
}
