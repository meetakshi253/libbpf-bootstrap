#include <argp.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "smbvfsiosnoop.h"
#include "smbvfsiosnoop.skel.h"

#define PERF_BUFFER_PAGES    64
#define PERF_POLL_TIMEOUT_MS 1000
#define NSEC_PER_SEC	     1000000000LL

#define warn(...)	     fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

/* options */
static pid_t target_pid = 0;
static time_t duration = 0;
static bool verbose = false;
static bool inode_ops = false;
static bool file_ops = false;
static bool adspace_ops = false;
static bool super_ops = false;
static bool csv = false;

const char *argp_program_version = "smbvfsiosnoop 1.0";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
	"Trace function args and return values from SMB VFS callbacks.\n"
	"\n"
	"Usage: smbvfsiosnoop [-h] [-t PID] [-d DURATION] [-i] [-j] [--inode] [--adspace] [--super] [--file]\n"
	"\n"
	"EXAMPLES:\n"
	"    smbvfsiosnoop --file		               			# trace args and retvals of smb vfs callbacks for file ops\n"
	"    smbvfsiosnoop --adspace -p 1216			   		# trace args and retvals of smb vfs callbacks for address space ops for PID 1216 only\n"
	"    smbvfsiosnoop -d 10 -j --inode --super		    # trace args and retvals of smb vfs callbacks for 10s with csv output, inode and superblock ops only\n";

static const struct argp_option opts[] = {
	{ "csv", 'j', NULL, 0, "Output as csv" },
	{ "inode", 'i', NULL, 0, "Trace inode ops" },
	{ "file", 'f', NULL, 0, "Trace file ops" },
	{ "super", 's', NULL, 0, "Trace superblock ops" },
	{ "adspace", 'a', NULL, 0, "Trace address space ops" },
	{ "duration", 'd', "DURATION", 0, "Total duration of trace in seconds" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		verbose = true;
		break;
	case 'j':
		csv = true;
		break;
	case 'i':
		inode_ops = true;
		break;
	case 'f':
		file_ops = true;
		break;
	case 'a':
		adspace_ops = true;
		break;
	case 's':
		super_ops = true;
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			warn("invalid DURATION: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'p':
		errno = 0;
		target_pid = strtol(arg, NULL, 10);
		if (errno || target_pid <= 0) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int file_fentry_set_attach_target(struct smbvfsiosnoop_bpf *obj)
{
	int err = 0;
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_loose_read_iter_exit, 0,
						     "cifs_loose_read_iter");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_file_write_iter_exit, 0,
						     "cifs_file_write_iter");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_open_exit, 0,
						     "cifs_open");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_close_exit, 0,
						     "cifs_close");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_lock_exit, 0,
						     "cifs_lock");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_flock_exit, 0,
						     "cifs_flock");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_fsync_exit, 0,
						     "cifs_fsync");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_flush_exit, 0,
						     "cifs_flush");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_file_mmap_exit, 0,
						     "cifs_file_mmap");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_filemap_splice_read_exit,
						     0, "filemap_splice_read");

	err = err   ?:
		      bpf_program__set_attach_target(
			      obj->progs.trace_file_iter_file_splice_write_exit, 0,
			      "iter_file_splice_write");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_llseek_exit, 0,
						     "cifs_llseek");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_ioctl_exit, 0,
						     "cifs_ioctl");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_copy_file_range_exit, 0,
						     "cifs_copy_file_range");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_remap_file_range_exit, 0,
						     "cifs_remap_file_range");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_setlease_exit, 0,
						     "cifs_setlease");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_fallocate_exit, 0,
						     "cifs_fallocate");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_strict_readv_exit, 0,
						     "cifs_strict_readv");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_strict_writev_exit, 0,
						     "cifs_strict_writev");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_strict_fsync_exit, 0,
						     "cifs_strict_fsync");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_file_strict_mmap_exit, 0,
						     "cifs_file_strict_mmap");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_direct_readv_exit, 0,
						     "cifs_direct_readv");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_direct_writev_exit, 0,
						     "cifs_direct_writev");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_copy_splice_read_exit, 0,
						     "copy_splice_read");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_readdir_exit, 0,
						     "cifs_readdir");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_closedir_exit, 0,
						     "cifs_closedir");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_generic_read_dir_exit, 0,
						     "generic_read_dir");

	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_generic_file_llseek_exit,
						     0, "generic_file_llseek");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_file_dir_fsync_exit, 0,
						     "cifs_dir_fsync");

	return err;
}

static void file_fentry_disable_target(struct smbvfsiosnoop_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.trace_file_loose_read_iter_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_file_write_iter_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_open_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_close_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_lock_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_flock_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_fsync_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_flush_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_file_mmap_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_filemap_splice_read_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_iter_file_splice_write_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_llseek_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_ioctl_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_copy_file_range_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_remap_file_range_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_setlease_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_fallocate_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_strict_readv_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_strict_writev_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_strict_fsync_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_file_strict_mmap_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_direct_readv_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_direct_writev_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_copy_splice_read_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_readdir_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_closedir_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_generic_read_dir_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_generic_file_llseek_exit, false);
	bpf_program__set_autoload(obj->progs.trace_file_dir_fsync_exit, false);
}

static int super_fexit_set_attach_target(struct smbvfsiosnoop_bpf *obj)
{
	int err = 0;
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_statfs_exit, 0,
						     "cifs_statfs");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_alloc_inode_exit, 0,
						     "cifs_alloc_inode");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_write_inode_exit, 0,
						     "cifs_write_inode");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_free_inode_exit, 0,
						     "cifs_free_inode");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_drop_inode_exit, 0,
						     "cifs_drop_inode");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_evict_inode_exit, 0,
						     "cifs_evict_inode");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_show_devname_exit, 0,
						     "cifs_show_devname");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_show_options_exit, 0,
						     "cifs_show_options");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_umount_begin_exit, 0,
						     "cifs_umount_begin");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_super_freeze_exit, 0,
						     "cifs_freeze");
	return err;
}

static void super_fexit_disable_target(struct smbvfsiosnoop_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.trace_super_statfs_exit, false);
	bpf_program__set_autoload(obj->progs.trace_super_alloc_inode_exit, false);
	bpf_program__set_autoload(obj->progs.trace_super_write_inode_exit, false);
	bpf_program__set_autoload(obj->progs.trace_super_free_inode_exit, false);
	bpf_program__set_autoload(obj->progs.trace_super_drop_inode_exit, false);
	bpf_program__set_autoload(obj->progs.trace_super_evict_inode_exit, false);
	bpf_program__set_autoload(obj->progs.trace_super_show_devname_exit, false);
	bpf_program__set_autoload(obj->progs.trace_super_show_options_exit, false);
	bpf_program__set_autoload(obj->progs.trace_super_umount_begin_exit, false);
	bpf_program__set_autoload(obj->progs.trace_super_freeze_exit, false);
}

static int adspace_fexit_set_attach_target(struct smbvfsiosnoop_bpf *obj)
{
	int err = 0;
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_read_folio_exit, 0,
						     "cifs_read_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_readahead_exit, 0,
						     "cifs_readahead");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_writepages_exit, 0,
						     "cifs_writepages");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_write_begin_exit, 0,
						     "cifs_write_begin");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_write_end_exit, 0,
						     "cifs_write_end");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_dirty_folio_exit, 0,
						     "netfs_dirty_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_release_folio_exit, 0,
						     "netfs_release_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_direct_io_exit, 0,
						     "cifs_direct_io");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_invalidate_folio_exit,
						     0, "cifs_invalidate_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_launder_folio_exit, 0,
						     "cifs_launder_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_migrate_folio_exit, 0,
						     "filemap_migrate_folio");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_swap_activate_exit, 0,
						     "cifs_swap_activate");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_adspace_swap_deactivate_exit,
						     0, "cifs_swap_deactivate");

	return err;
}

static void adspace_fexit_disable_target(struct smbvfsiosnoop_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.trace_adspace_read_folio_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_readahead_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_writepages_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_write_begin_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_write_end_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_dirty_folio_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_release_folio_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_direct_io_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_invalidate_folio_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_launder_folio_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_migrate_folio_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_swap_activate_exit, false);
	bpf_program__set_autoload(obj->progs.trace_adspace_swap_deactivate_exit, false);
}

static int inode_fexit_set_attach_target(struct smbvfsiosnoop_bpf *obj)
{
	int err = 0;
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_create_exit, 0,
						     "cifs_create");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_atomic_open_exit, 0,
						     "cifs_atomic_open");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_lookup_exit, 0,
						     "cifs_lookup");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_getattr_exit, 0,
						     "cifs_getattr");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_unlink_exit, 0,
						     "cifs_unlink");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_hardlink_exit, 0,
						     "cifs_hardlink");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_mkdir_exit, 0,
						     "cifs_mkdir");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_rmdir_exit, 0,
						     "cifs_rmdir");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_rename2_exit, 0,
						     "cifs_rename2");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_permission_exit, 0,
						     "cifs_permission");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_setattr_exit, 0,
						     "cifs_setattr");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_symlink_exit, 0,
						     "cifs_symlink");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_mknod_exit, 0,
						     "cifs_mknod");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_listxattr_exit, 0,
						     "cifs_listxattr");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_get_acl_exit, 0,
						     "cifs_get_acl");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_set_acl_exit, 0,
						     "cifs_set_acl");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_fiemap_exit, 0,
						     "cifs_fiemap");
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.trace_inode_get_link_exit, 0,
						     "cifs_get_link");

	return err;
}

static void inode_fexit_disable_attach_target(struct smbvfsiosnoop_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.trace_inode_create_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_atomic_open_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_lookup_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_getattr_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_unlink_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_hardlink_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_mkdir_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_rmdir_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_rename2_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_permission_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_setattr_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_symlink_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_mknod_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_listxattr_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_get_acl_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_set_acl_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_fiemap_exit, false);
	bpf_program__set_autoload(obj->progs.trace_inode_get_link_exit, false);
}

static void print_headers()
{
	if (csv) {
		printf("TASK,PID,TYPE,FUNCTION,RETVAL,ARGS\n");
		return;
	}

	printf("Tracing SMB VFS callbacks for: ");

	if (file_ops)
		printf("file operations, ");

	if (inode_ops)
		printf("inode operations, ");

	if (adspace_ops)
		printf("address space operations, ");

	if (super_ops)
		printf("superblock operations, ");

	if (target_pid)
		printf("PID=%d, ", target_pid);

	if (duration)
		printf(" for %ld secs.\n", duration);
	else
		printf("Hit Ctrl-C to end.\n");

	printf("%-20s %-7s %-10s %-25s %-10s %-25s\n", "TASK", "PID", "TYPE", "FUNCTION", "RETVAL",
	       "ARGS");
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (csv) {
		printf("%s,%d,%s,%s,%d,%s\n", e.task, e.pid, e.type, e.function, e.retval, e.args);
		return;
	}

	printf("%-20s %-7d %-10s %-25s %-10d %-25s\n", e.task, e.pid, e.type, e.function, e.retval,
	       e.args);
}

static struct timespec get_end_time_from_duration()
{
	struct timespec end_time, start_time;
	clock_gettime(CLOCK_REALTIME, &start_time);
	long long duration_ns = (long long)duration * NSEC_PER_SEC;
	end_time.tv_sec = start_time.tv_sec + duration_ns / NSEC_PER_SEC;
	end_time.tv_nsec = start_time.tv_nsec + duration_ns % NSEC_PER_SEC;

	if (end_time.tv_nsec >= NSEC_PER_SEC) {
		end_time.tv_sec += 1;
		end_time.tv_sec -= NSEC_PER_SEC;
	}
	return end_time;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct smbvfsiosnoop_bpf *skel;
	struct timespec end_time, current_time;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	skel = smbvfsiosnoop_bpf__open_opts(&open_opts);
	if (!skel) {
		warn("failed to open BPF object\n");
		return 1;
	}

	skel->rodata->target_pid = target_pid;

	// conditional attachment: disable rest of the probes
	if (!file_ops && !inode_ops && !adspace_ops && !super_ops) {
		warn("No operations selected. Try 'smbvfsiosnoop --help'\n");
		goto cleanup;
	}

	if (file_ops) {
		err = file_fentry_set_attach_target(skel);
		if (err) {
			printf("Error: %d\n", err);
			warn("failed to set (file ops) attach target\n");
			goto cleanup;
		}
	} else {
		file_fentry_disable_target(skel);
	}

	if (inode_ops) {
		err = inode_fexit_set_attach_target(skel);
		if (err) {
			warn("failed to set (inode ops) attach target\n");
			goto cleanup;
		}
	} else {
		inode_fexit_disable_attach_target(skel);
	}

	if (adspace_ops) {
		err = adspace_fexit_set_attach_target(skel);
		if (err) {
			warn("failed to set (address space ops) attach target: %d\n", err);
			goto cleanup;
		}
	} else {
		adspace_fexit_disable_target(skel);
	}

	if (super_ops) {
		err = super_fexit_set_attach_target(skel);
		if (err) {
			warn("failed to set (super ops) attach target: %d\n", err);
			goto cleanup;
		}
	} else {
		super_fexit_disable_target(skel);
	}

	err = smbvfsiosnoop_bpf__load(skel);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/*
	 * after load
	 * if fentry is supported, let libbpf do auto load
	 */
	err = smbvfsiosnoop_bpf__attach(skel);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started\n");

	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES, handle_event,
			      handle_lost_events, NULL, NULL);

	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	print_headers();

	if (duration)
		end_time = get_end_time_from_duration();

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}

		if (duration) {
			clock_gettime(CLOCK_REALTIME, &current_time);
			double elapsed_seconds = difftime(current_time.tv_sec, end_time.tv_sec);
			if (elapsed_seconds > 0)
				goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	smbvfsiosnoop_bpf__destroy(skel);

	return err != 0;
}
