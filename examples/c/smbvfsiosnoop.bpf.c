#include "vmlinuxcifs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "smbvfsiosnoop.h"
#include "smbvfsops.h"

#define MAX_ENTRIES 8192
#define STR(x)	    #x

const volatile pid_t target_pid = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static inline int PTR_ERR(const void *ptr)
{
	return (int)ptr;
}

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

static inline int trace_all_vfs_fexit(void *ctx, const char type[], const char fn_name[],
				      const char argm[], int retval)
{
	struct event event = {};
	u64 pid_tgid = bpf_get_current_pid_tgid();

	event.retval = retval;
	event.pid = pid_tgid >> 32;
	bpf_get_current_comm(&event.task, sizeof(event.task));
	__builtin_memcpy(&event.args, argm, sizeof(event.args));
	__builtin_memcpy(&event.type, type, sizeof(event.type));
	__builtin_memcpy(&event.function, fn_name, sizeof(event.function));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

/* fexit VFS Superblock callbacks for CIFS */
SEC("fexit/cifs_statfs")
int BPF_PROG(trace_super_statfs_exit, struct dentry *dentry, struct kstatfs *buf, int retval)
{
	//can convert sb to tcon
	// display only dname and retval for now
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&filename, sizeof(filename), BPF_CORE_READ(dentry, d_iname));
	if (filename[0]) {
		__u64 argdata[] = { (u64)filename };
		bpf_snprintf(args, sizeof(args), "dname=%s", argdata, sizeof(argdata));
	}
	return trace_all_vfs_fexit(ctx, "SUPER", STR(cifs_statfs), args, retval);
}

SEC("fexit/cifs_alloc_inode")
int BPF_PROG(trace_super_alloc_inode_exit, struct super_block *sb, struct inode *inode)
{
	int retval = 1;
	if (inode == NULL) {
		retval = 0;
	}
	return trace_all_vfs_fexit(ctx, "SUPER", STR(cifs_alloc_inode), "", retval);
}

SEC("fexit/cifs_write_inode")
int BPF_PROG(trace_super_write_inode_exit, struct inode *inode, struct writeback_control *wbc,
	     int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino) };
	bpf_snprintf(args, sizeof(args), "inode=%llu", argdata, sizeof(argdata));
	bpf_printk("args: %s\n", args);
	return trace_all_vfs_fexit(ctx, "SUPER", STR(cifs_write_inode), args, retval);
}

SEC("fexit/cifs_free_inode")
int BPF_PROG(trace_super_free_inode_exit, struct inode *inode)
{
	char args[MAX_ARGS_LENGTH] = {};
	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino) };
	bpf_snprintf(args, sizeof(args), "inode=%llu", argdata, sizeof(argdata));
	bpf_printk("args: %s\n", args);
	return trace_all_vfs_fexit(ctx, "SUPER", STR(cifs_free_inode), args,
				   0); // for ops with void return type, return 0
}

SEC("fexit/cifs_drop_inode")
int BPF_PROG(trace_super_drop_inode_exit, struct inode *inode, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino) };
	bpf_snprintf(args, sizeof(args), "inode=%llu", argdata, sizeof(argdata));
	bpf_printk("args: %s\n", args);
	return trace_all_vfs_fexit(ctx, "SUPER", STR(cifs_drop_inode), args, retval);
}

SEC("fexit/cifs_evict_inode")
int BPF_PROG(trace_super_evict_inode_exit, struct inode *inode)
{
	char args[MAX_ARGS_LENGTH] = {};
	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino) };
	bpf_snprintf(args, sizeof(args), "inode=%llu", argdata, sizeof(argdata));
	bpf_printk("args: %s\n", args);
	return trace_all_vfs_fexit(ctx, "SUPER", STR(cifs_evict_inode), args,
				   0); // for ops with void return type, return 0
}

SEC("fexit/cifs_show_devname")
int BPF_PROG(trace_super_show_devname_exit, struct seq_file *m, struct dentry *root, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&filename, sizeof(filename), BPF_CORE_READ(root, d_iname));
	if (filename[0]) {
		__u64 argdata[] = { (u64)filename };
		bpf_snprintf(args, sizeof(args), "rootDname=%s", argdata, sizeof(argdata));
		bpf_printk("args: %s\n", args);
	}
	return trace_all_vfs_fexit(ctx, "SUPER", STR(cifs_show_devname), args, retval);
}

SEC("fexit/cifs_show_options")
int BPF_PROG(trace_super_show_options_exit, struct seq_file *s, struct dentry *root, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&filename, sizeof(filename), BPF_CORE_READ(root, d_iname));
	if (filename[0]) {
		__u64 argdata[] = { (u64)filename };
		bpf_snprintf(args, sizeof(args), "rootDname=%s", argdata, sizeof(argdata));
		bpf_printk("args: %s\n", args);
	}
	return trace_all_vfs_fexit(ctx, "SUPER", STR(cifs_show_options), args, retval);
}

SEC("fexit/cifs_umount_begin")
int BPF_PROG(trace_super_umount_begin_exit, struct super_block *sb)
{
	return trace_all_vfs_fexit(ctx, "SUPER", STR(cifs_umount_begin), "",
				   0); // for ops with void return type, return 0
}

SEC("fexit/cifs_freeze")
int BPF_PROG(trace_super_freeze_exit, struct super_block *sb, int retval)
{
	return trace_all_vfs_fexit(ctx, "SUPER", STR(cifs_freeze), "", retval);
}

/* fexit VFS File callbacks for CIFS */
SEC("fexit/cifs_loose_read_iter")
int BPF_PROG(trace_file_loose_read_iter_exit, struct kiocb *iocb, struct iov_iter *iter, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();

	struct file *file = iocb->ki_filp;
	struct inode *inode = BPF_CORE_READ(iocb, ki_filp, f_mapping, host);
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_file_write_iter), args, retval);
}

SEC("fexit/cifs_file_write_iter")
int BPF_PROG(trace_file_file_write_iter_exit, struct kiocb *iocb, struct iov_iter *from, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();

	struct file *file = iocb->ki_filp;
	struct inode *inode = BPF_CORE_READ(iocb, ki_filp, f_mapping, host);
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), from->count,
			    BPF_CORE_READ(cfile, oplock_level), (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|write_len=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_file_write_iter), args, retval);
}

SEC("fexit/cifs_open")
int BPF_PROG(trace_file_open_exit, struct inode *inode, struct file *file, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();

	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_open), args, retval);
}

SEC("fexit/cifs_close")
int BPF_PROG(trace_file_close_exit, struct inode *inode, struct file *file, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_open), args, retval);
}

SEC("fexit/cifs_lock")
int BPF_PROG(trace_file_lock_exit, struct file *file, int cmd, struct file_lock *flock, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = {
		BPF_CORE_READ(file, f_inode, i_ino), cmd,	   flock->fl_end, flock->fl_start,
		BPF_CORE_READ(cfile, oplock_level),  (u64)filename
	};

	bpf_snprintf(args, sizeof(args), "inode=%llu|cmd=0x%x|range=%lld:%lld|oplock=%llu|dname=%s",
		     argdata, sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_lock), args, retval);
}

SEC("fexit/cifs_flock")
int BPF_PROG(trace_file_flock_exit, struct file *file, int cmd, struct file_lock *flock, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = {
		BPF_CORE_READ(file, f_inode, i_ino), cmd,	   flock->fl_end, flock->fl_start,
		BPF_CORE_READ(cfile, oplock_level),  (u64)filename
	};

	bpf_snprintf(args, sizeof(args), "inode=%llu|cmd=0x%x|range=%lld:%lld|oplock=%llu|dname=%s",
		     argdata, sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_flock), args, retval);
}

SEC("fexit/cifs_fsync")
int BPF_PROG(trace_file_fsync_exit, struct file *file, loff_t start, loff_t end, int datasync,
	     int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), datasync,
			    BPF_CORE_READ(cfile, oplock_level), (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|datasync=0x%x|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_fsync), args, retval);
}

SEC("fexit/cifs_flush")
int BPF_PROG(trace_file_flush_exit, struct file *file, fl_owner_t id, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_flush), args, retval);
}

SEC("fexit/cifs_file_mmap")
int BPF_PROG(trace_file_file_mmap_exit, struct file *file, struct vm_area_struct *vma, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_file_mmap), args, retval);
}

SEC("fexit/filemap_splice_read")
int BPF_PROG(trace_file_filemap_splice_read_exit, struct file *file, loff_t *ppos,
	     struct pipe_inode_info *pipe, size_t len, unsigned int flags, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(filemap_splice_read), args, retval);
}

SEC("fexit/iter_file_splice_write")
int BPF_PROG(trace_file_iter_file_splice_write_exit, struct pipe_inode_info *pipe,
	     struct file *file, loff_t *ppos, size_t len, unsigned int flags, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(iter_file_splice_write), args, retval);
}

SEC("fexit/cifs_llseek")
int BPF_PROG(trace_file_llseek_exit, struct file *file, loff_t offset, int whence, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), whence,
			    BPF_CORE_READ(cfile, oplock_level), (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|whence=%d|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_llseek), args, retval);
}

SEC("fexit/cifs_ioctl")
int BPF_PROG(trace_file_ioctl_exit, struct file *file, unsigned int cmd, unsigned long arg,
	     int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), cmd,
			    BPF_CORE_READ(cfile, oplock_level), (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|ioctl=0x%x|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_ioctl), args, retval);
}

SEC("fexit/cifs_copy_file_range")
int BPF_PROG(trace_file_copy_file_range_exit, struct file *src_file, loff_t off,
	     struct file *dst_file, loff_t destoff, size_t len, unsigned int flags, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(dst_file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(src_file, f_inode, i_ino),
			    BPF_CORE_READ(dst_file, f_inode, i_ino), len, (u64)filename };

	bpf_snprintf(args, sizeof(args), "src_inode=%llu|dst_inode=%llu|len=%d|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_copy_file_range), args, retval);
}

SEC("fexit/cifs_remap_file_range")
int BPF_PROG(trace_file_remap_file_range_exit, struct file *src_file, loff_t off,
	     struct file *dst_file, loff_t destoff, loff_t len, unsigned int remap_flags,
	     int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(dst_file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(src_file, f_inode, i_ino),
			    BPF_CORE_READ(dst_file, f_inode, i_ino), len, (u64)filename };

	bpf_snprintf(args, sizeof(args), "src_inode=%llu|dst_inode=%llu|len=%d|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_remap_file_range), args, retval);
}

SEC("fexit/cifs_setlease")
int BPF_PROG(trace_file_setlease_exit, struct file *file, int arg, struct file_lock **lease,
	     void **priv, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_setlease), args, retval);
}

SEC("fexit/cifs_fallocate")
int BPF_PROG(trace_file_fallocate_exit, struct file *file, int mode, loff_t off, loff_t len,
	     int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), mode, off, len, (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|mode=0x%x|offset=%llu|len=%llu|dname=%s",
		     argdata, sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_fallocate), args, retval);
}

SEC("fexit/cifs_strict_readv")
int BPF_PROG(trace_file_strict_readv_exit, struct kiocb *iocb, struct iov_iter *to, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();

	struct file *file = iocb->ki_filp;
	struct inode *inode = BPF_CORE_READ(iocb, ki_filp, f_mapping, host);
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), to->count,
			    BPF_CORE_READ(cfile, oplock_level), (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|to=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_strict_readv), args, retval);
}

SEC("fexit/cifs_strict_writev")
int BPF_PROG(trace_file_strict_writev_exit, struct kiocb *iocb, struct iov_iter *from, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();

	struct file *file = iocb->ki_filp;
	struct inode *inode = BPF_CORE_READ(iocb, ki_filp, f_mapping, host);
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), from->count,
			    BPF_CORE_READ(cfile, oplock_level), (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|write_len=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_strict_writev), args, retval);
}

SEC("fexit/cifs_strict_fsync")
int BPF_PROG(trace_file_strict_fsync_exit, struct file *file, loff_t start, loff_t end,
	     int datasync, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), start,	       end, datasync,
			    BPF_CORE_READ(cfile, oplock_level),	 (u64)filename };

	bpf_snprintf(args, sizeof(args),
		     "inode=%llu|start=%llu|end=%llu|datasync=0x%x|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_strict_fsync), args, retval);
}

SEC("fexit/cifs_file_strict_mmap")
int BPF_PROG(trace_file_file_strict_mmap_exit, struct file *file, struct vm_area_struct *vma,
	     int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_file_strict_mmap), args, retval);
}

SEC("fexit/cifs_direct_readv")
int BPF_PROG(trace_file_direct_readv_exit, struct kiocb *iocb, struct iov_iter *to, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();

	struct file *file = iocb->ki_filp;
	struct inode *inode = BPF_CORE_READ(iocb, ki_filp, f_mapping, host);
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), to->count,
			    BPF_CORE_READ(cfile, oplock_level), (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|to=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_direct_readv), args, retval);
}

SEC("fexit/cifs_direct_writev")
int BPF_PROG(trace_file_direct_writev_exit, struct kiocb *iocb, struct iov_iter *from, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();

	struct file *file = iocb->ki_filp;
	struct inode *inode = BPF_CORE_READ(iocb, ki_filp, f_mapping, host);
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), from->count,
			    BPF_CORE_READ(cfile, oplock_level), (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|write_len=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_direct_writev), args, retval);
}

SEC("fexit/copy_splice_read")
int BPF_PROG(trace_file_copy_splice_read_exit, struct file *file, loff_t *ppos, void *pipe,
	     size_t len, unsigned int flags, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), len, flags,
			    BPF_CORE_READ(cfile, oplock_level), (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|len=%llu|flags=0x%x|oplock=%llu|dname=%s",
		     argdata, sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(copy_splice_read), args, retval);
}

SEC("fexit/cifs_readdir")
int BPF_PROG(trace_file_readdir_exit, struct file *file, struct dir_context *dirctx, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_readdir), args, retval);
}

SEC("fexit/cifs_closedir")
int BPF_PROG(trace_file_closedir_exit, struct inode *inode, struct file *file, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_closedir), args, retval);
}

SEC("fexit/generic_read_dir")
int BPF_PROG(trace_file_generic_read_dir_exit, struct file *file, void *buf, size_t size,
	     loff_t *ppos, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(generic_read_dir), args, retval);
}

SEC("fexit/generic_file_llseek")
int BPF_PROG(trace_file_generic_file_llseek_exit, struct file *file, loff_t offset, int whence,
	     int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), whence,
			    BPF_CORE_READ(cfile, oplock_level), (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|whence=%d|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(generic_file_llseek), args, retval);
}

SEC("fexit/cifs_dir_fsync")
int BPF_PROG(trace_file_dir_fsync_exit, struct file *file, loff_t start, loff_t end, int datasync,
	     int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};
	u64 current_index = bpf_get_current_pid_tgid();
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(file, f_inode, i_ino), start,	       end, datasync,
			    BPF_CORE_READ(cfile, oplock_level),	 (u64)filename };

	bpf_snprintf(args, sizeof(args),
		     "inode=%llu|start=%llu|end=%llu|datasync=0x%x|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "FILE", STR(cifs_dir_fsync), args, retval);
}

/* fexit VFS Address Space callbacks for CIFS */
SEC("fexit/cifs_read_folio")
int BPF_PROG(trace_adspace_read_folio_exit, struct file *file, struct folio *folio, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	if (cfile != NULL) {
		bpf_probe_read_kernel_str(&filename, sizeof(filename),
					  BPF_CORE_READ(file, f_path.dentry, d_iname));

		__u64 argdata[] = { BPF_CORE_READ(cfile, oplock_level), (u64)filename };
		bpf_snprintf(args, sizeof(args), "oplock=%llu|dname=%s", argdata, sizeof(argdata));
	}
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(cifs_read_folio), args, retval);
}

SEC("fexit/cifs_readahead")
int BPF_PROG(trace_adspace_readahead_exit, struct readahead_control *ractl)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	struct file *file = BPF_CORE_READ(ractl, file);
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	if (cfile != NULL) {
		bpf_probe_read_kernel_str(&filename, sizeof(filename),
					  BPF_CORE_READ(file, f_path.dentry, d_iname));

		__u64 argdata[] = { ractl->_nr_pages, BPF_CORE_READ(cfile, oplock_level),
				    (u64)filename };
		bpf_snprintf(args, sizeof(args), "num_pages=%u|oplock=%llu|dname=%s", argdata,
			     sizeof(argdata));
	}
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(cifs_readahead), args, 0);
}

SEC("fexit/cifs_writepages")
int BPF_PROG(trace_adspace_writepages_exit, struct address_space *mapping,
	     struct writeback_control *wbc, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	__u64 argdata[] = { wbc->nr_to_write, wbc->range_cyclic, wbc->range_start, wbc->range_end };
	bpf_snprintf(args, sizeof(args),
		     "nr_to_write=%u|range_cyclic=%u|range_start=%llu|range_end=%llu", argdata,
		     sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(cifs_writepages), args, retval);
}

SEC("fexit/cifs_write_begin")
int BPF_PROG(trace_adspace_write_begin_exit, struct file *file, struct address_space *mapping,
	     loff_t pos, unsigned len, struct page **pagep, void **fsdata, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);
	if (cfile != NULL) {
		bpf_probe_read_kernel_str(&filename, sizeof(filename),
					  BPF_CORE_READ(file, f_path.dentry, d_iname));

		__u64 argdata[] = { pos, len, BPF_CORE_READ(cfile, oplock_level), (u64)filename };
		bpf_snprintf(args, sizeof(args), "writepos=%lld|len=%d|oplock=%llu|dname=%s",
			     argdata, sizeof(argdata));
	}
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(cifs_write_begin), args, retval);
}

SEC("fexit/cifs_write_end")
int BPF_PROG(trace_adspace_write_end_exit, struct file *file, struct address_space *mapping,
	     loff_t pos, unsigned len, unsigned copied, struct page *page, void *fsdata, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);
	if (cfile != NULL) {
		bpf_probe_read_kernel_str(&filename, sizeof(filename),
					  BPF_CORE_READ(file, f_path.dentry, d_iname));

		__u64 argdata[] = { pos, copied, BPF_CORE_READ(cfile, oplock_level),
				    (u64)filename };
		bpf_snprintf(args, sizeof(args), "write_endpos=%lld|bytes=%d|oplock=%llu|dname=%s",
			     argdata, sizeof(argdata));
	}
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(cifs_write_end), args, retval);
}

SEC("fexit/netfs_dirty_folio")
int BPF_PROG(trace_adspace_dirty_folio_exit, struct address_space *mapping, struct folio *folio,
	     bool retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	__u64 argdata[] = { BPF_CORE_READ(mapping, host, i_ino) };
	bpf_snprintf(args, sizeof(args), "inode=%llu", argdata, sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(netfs_dirty_folio), args, retval);
}

SEC("fexit/cifs_release_folio")
int BPF_PROG(trace_adspace_release_folio_exit, struct folio *folio, gfp_t gfp, bool retval)
{
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(cifs_release_folio), "", retval);
}

SEC("fexit/cifs_direct_io")
int BPF_PROG(trace_adspace_direct_io_exit, struct kiocb *iocb, struct iov_iter *iter, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	struct file *file = iocb->ki_filp;
	struct inode *inode = BPF_CORE_READ(iocb, ki_filp, f_mapping, host);
	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), BPF_CORE_READ(cfile, oplock_level),
			    (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|oplock=%llu|dname=%s", argdata,
		     sizeof(argdata));

	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(cifs_direct_io), args, retval);
}

SEC("fexit/cifs_invalidate_folio")
int BPF_PROG(trace_adspace_invalidate_folio_exit, struct folio *folio, size_t offset, size_t length)
{
	char args[MAX_ARGS_LENGTH] = {};
	__u64 argdata[] = { offset, length };
	bpf_snprintf(args, sizeof(args), "offset=%llu|length=%llu", argdata, sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(cifs_invalidate_folio), "args", 0);
}

SEC("fexit/cifs_launder_folio")
int BPF_PROG(trace_adspace_launder_folio_exit, struct folio *folio, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	__u64 argdata[] = { folio->index };
	bpf_snprintf(args, sizeof(args), "launderpage=%llu", argdata, sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(cifs_launder_folio), args, retval);
}

SEC("fexit/filemap_migrate_folio")
int BPF_PROG(trace_adspace_migrate_folio_exit, struct address_space *mapping, struct folio *dst,
	     struct folio *src, enum migrate_mode mode, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	__u64 argdata[] = { mode };
	bpf_snprintf(args, sizeof(args), "mode=%d", argdata, sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(filemap_migrate_folio), args, retval);
}

SEC("fexit/cifs_swap_activate")
int BPF_PROG(trace_adspace_swap_activate_exit, struct swap_info_struct *sis, struct file *swap_file,
	     sector_t *span, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	struct cifsFileInfo *cfile = BPF_CORE_READ(swap_file, private_data);
	struct inode *inode = BPF_CORE_READ(swap_file, f_mapping, host);

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(swap_file, f_path.dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(inode, i_blocks), BPF_CORE_READ(inode, i_size),
			    BPF_CORE_READ(inode, i_ino), (u64)filename };

	bpf_snprintf(args, sizeof(args), "iblocks=%llu|isize=%llu|inode=%llu|swapDname=%s", argdata,
		     sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(cifs_swap_activate), args, retval);
}

SEC("fexit/cifs_swap_deactivate")
int BPF_PROG(trace_adspace_swap_deactivate_exit, struct file *file)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	struct cifsFileInfo *cfile = BPF_CORE_READ(file, private_data);

	if (cfile != NULL) {
		bpf_probe_read_kernel_str(&filename, sizeof(filename),
					  BPF_CORE_READ(file, f_path.dentry, d_iname));

		__u64 argdata[] = { BPF_CORE_READ(cfile, oplock_level), (u64)filename };
		bpf_snprintf(args, sizeof(args), "oplock=%llu|dname=%s", argdata, sizeof(argdata));
	}
	return trace_all_vfs_fexit(ctx, "ADSPACE", STR(cifs_swap_deactivate), args, 0);
}

/* fexit Inode VFS callbacks for CIFS */
SEC("fexit/cifs_create")
int BPF_PROG(trace_inode_create_exit, struct mnt_idmap *idmap, struct inode *inode,
	     struct dentry *direntry, umode_t mode, bool excl, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), mode, excl };
	bpf_snprintf(args, sizeof(args), "parentInode=%llu|mode=0x%x|excl=%d", argdata,
		     sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_create), args, retval);
}

SEC("fexit/cifs_atomic_open")
int BPF_PROG(trace_inode_atomic_open_exit, struct inode *inode, struct dentry *direntry,
	     struct file *file, unsigned oflags, umode_t mode, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), oflags, mode };
	bpf_snprintf(args, sizeof(args), "parentInode=%llu|oflags=0x%x|mode=0x%x", argdata,
		     sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_atomic_open), args, retval);
}

SEC("fexit/cifs_lookup")
int BPF_PROG(trace_inode_lookup_exit, struct inode *parent_dir_inode, struct dentry *direntry,
	     unsigned int flags, struct dentry *retval)
{
	char args[MAX_ARGS_LENGTH] = {};

	__u64 argdata[] = { BPF_CORE_READ(parent_dir_inode, i_ino), flags };
	bpf_snprintf(args, sizeof(args), "parentInode=%llu|flags=0x%x", argdata, sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_lookup), args, retval ? 1 : 0);
}

SEC("fexit/cifs_getattr")
int BPF_PROG(trace_inode_getattr_exit, struct mnt_idmap *idmap, const struct path *path,
	     struct kstat *stat, u32 request_mask, unsigned int flags, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&filename, sizeof(filename),
				  BPF_CORE_READ(path, dentry, d_iname));
	__u64 argdata[] = { request_mask, flags, (u64)filename };

	bpf_snprintf(args, sizeof(args), "request_mask=0x%x|flags=0x%x|dname=%s", argdata,
		     sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_getattr), args, retval);
}

SEC("fexit/cifs_unlink")
int BPF_PROG(trace_inode_unlink_exit, struct inode *dir, struct dentry *dentry, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&filename, sizeof(filename), BPF_CORE_READ(dentry, d_iname));
	__u64 argdata[] = { BPF_CORE_READ(dir, i_ino), (u64)filename };

	bpf_snprintf(args, sizeof(args), "inode=%llu|dname=%s", argdata, sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_unlink), args, retval);
}

SEC("fexit/cifs_hardlink")
int BPF_PROG(trace_inode_hardlink_exit, struct dentry *old_file, struct inode *inode,
	     struct dentry *direntry, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char old_filename[MAX_PATH_LENGTH] = {};
	char new_filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&old_filename, sizeof(old_filename),
				  BPF_CORE_READ(old_file, d_iname));
	bpf_probe_read_kernel_str(&new_filename, sizeof(new_filename),
				  BPF_CORE_READ(direntry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), (u64)old_filename, (u64)new_filename };
	bpf_snprintf(args, sizeof(args), "parentInode=%llu|old_dname=%s|new_dname=%s", argdata,
		     sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_hardlink), args, retval);
}

SEC("fexit/cifs_mkdir")
int BPF_PROG(trace_inode_mkdir_exit, struct mnt_idmap *idmap, struct inode *inode,
	     struct dentry *direntry, umode_t mode, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&filename, sizeof(filename), BPF_CORE_READ(direntry, d_iname));
	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), mode, (u64)filename };
	bpf_snprintf(args, sizeof(args), "inode=%llu|mode=0x%x|dname=%s", argdata, sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_mkdir), args, retval);
}

SEC("fexit/cifs_rmdir")
int BPF_PROG(trace_inode_rmdir_exit, struct inode *inode, struct dentry *direntry, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&filename, sizeof(filename), BPF_CORE_READ(direntry, d_iname));
	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), (u64)filename };
	bpf_snprintf(args, sizeof(args), "inode=%llu|dname=%s", argdata, sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_rmdir), args, retval);
}

SEC("fexit/cifs_rename2")
int BPF_PROG(trace_inode_rename2_exit, struct mnt_idmap *idmap, struct inode *source_dir,
	     struct dentry *source_dentry, struct inode *target_dir, struct dentry *target_dentry,
	     unsigned int flags, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char target_filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&target_filename, sizeof(target_filename),
				  BPF_CORE_READ(target_dentry, d_iname));

	__u64 argdata[] = { BPF_CORE_READ(source_dir, i_ino), BPF_CORE_READ(target_dir, i_ino),
			    (u64)target_filename };
	bpf_snprintf(args, sizeof(args), "src_inode=%llu|dst_inode=%llu|dst_dname=%s", argdata,
		     sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_rename2), args, retval);
}

SEC("fexit/cifs_permission")
int BPF_PROG(trace_inode_permission_exit, struct mnt_idmap *idmap, struct inode *inode, int mask,
	     int retval)
{
	char args[MAX_ARGS_LENGTH] = {};

	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), mask };
	bpf_snprintf(args, sizeof(args), "inode=%llu|mask=0x%x", argdata, sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_permission), args, retval);
}

SEC("fexit/cifs_setattr")
int BPF_PROG(trace_inode_setattr_exit, struct mnt_idmap *idmap, struct dentry *direntry,
	     struct iattr *attrs, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&filename, sizeof(filename), BPF_CORE_READ(direntry, d_iname));
	__u64 argdata[] = { BPF_CORE_READ(direntry, d_inode, i_ino), attrs->ia_mode,
			    attrs->ia_valid, (u64)filename };
	bpf_snprintf(args, sizeof(args), "inode=%llu|mode=0x%x|valid=0x%x|dname=%s", argdata,
		     sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_setattr), args, retval);
}

SEC("fexit/cifs_symlink")
int BPF_PROG(trace_inode_symlink_exit, struct mnt_idmap *idmap, struct inode *inode,
	     struct dentry *direntry, const char *symname, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&filename, sizeof(filename), BPF_CORE_READ(direntry, d_iname));
	if (filename[0]) {
		__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), (u64)symname, (u64)filename };
		bpf_snprintf(args, sizeof(args), "inode=%llu|symname=%s|dname=%s", argdata,
			     sizeof(argdata));
	}
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_symlink), args, retval);
}

SEC("fexit/cifs_mknod")
int BPF_PROG(trace_inode_mknod_exit, struct mnt_idmap *idmap, struct inode *inode,
	     struct dentry *direntry, umode_t mode, dev_t device_number, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&filename, sizeof(filename), BPF_CORE_READ(direntry, d_iname));
	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), mode, device_number, (u64)filename };
	bpf_snprintf(args, sizeof(args), "inode=%llu|mode=0x%x|dev=%llu|dname=%s", argdata,
		     sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_mknod), args, retval);
}

SEC("fexit/cifs_listxattr")
int BPF_PROG(trace_inode_listxattr_exit, struct dentry *dentry, char *data, size_t buf_size,
	     ssize_t retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	bpf_probe_read_kernel_str(&filename, sizeof(filename), BPF_CORE_READ(dentry, d_iname));
	__u64 argdata[] = { (u64)filename, buf_size };
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_listxattr), args, retval);
}

SEC("fexit/cifs_get_acl")
int BPF_PROG(trace_inode_get_acl_exit, struct mnt_idmap *idmap, struct dentry *dentry, int type,
	     struct posix_acl *retval)
{
	// legacy op
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_get_acl), "", IS_ERR_OR_NULL(retval) ? PTR_ERR(retval) : 0);
}

SEC("fexit/cifs_set_acl")
int BPF_PROG(trace_inode_set_acl_exit, struct mnt_idmap *idmap, struct dentry *dentry,
	     struct posix_acl *acl, int type, int retval)
{
	// legacy op
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_set_acl), "", retval);
}

SEC("fexit/cifs_fiemap")
int BPF_PROG(trace_inode_fiemap_exit, struct inode *inode, struct fiemap_extent_info *fei,
	     u64 start, u64 len, int retval)
{
	char args[MAX_ARGS_LENGTH] = {};
	__u64 argdata[] = { BPF_CORE_READ(inode, i_ino), start, len };
	bpf_snprintf(args, sizeof(args), "inode=%llu|start=%llu|len=%llu", argdata,
		     sizeof(argdata));
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_fiemap), args, retval);
}

SEC("fexit/cifs_get_link")
int BPF_PROG(trace_inode_get_link_exit, struct dentry *dentry, struct inode *inode,
	     struct delayed_call *done, char *retval)
{ // retval is path
	char args[MAX_ARGS_LENGTH] = {};
	char filename[MAX_PATH_LENGTH] = {};

	if (dentry) {
		bpf_probe_read_kernel_str(&filename, sizeof(filename),
					  BPF_CORE_READ(dentry, d_iname));
		__u64 argdata[] = { (u64)retval, BPF_CORE_READ(inode, i_ino), (u64)filename };
		bpf_snprintf(args, sizeof(args), "returnTargetPath=%s|inode=%llu|dname=%s", argdata,
			     sizeof(argdata));
	}
	return trace_all_vfs_fexit(ctx, "INODE", STR(cifs_get_link), args,
				   IS_ERR_OR_NULL(retval) ? PTR_ERR(retval) : 0);
}