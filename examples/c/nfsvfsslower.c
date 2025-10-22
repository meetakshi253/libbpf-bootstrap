#include <argp.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <syslog.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "nfsvfsslower.h"
#include "nfsvfsslower.skel.h"

#define PERF_BUFFER_PAGES    64
#define PERF_POLL_TIMEOUT_MS 100
#define NSEC_PER_SEC	     1000000000LL

#define warn(...)	     fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

/* options */
static pid_t target_pid = 0;
static time_t duration = 0;
static bool inode_ops = false;
static bool file_ops = false;
static bool adspace_ops = false;
static bool super_ops = false;
static __u64 min_lat_ms = 10;
static bool csv = false;
static bool nfsdiagnostics = false;
static int log_capture_timeout = 0;
static bool capturenetwork = false;
static char *nfsdiagnostics_path = "./nfsdiagnostics.sh";
static int nfsdiagnostics_pid = -1;
static time_t nfsdiagnostics_end_time = 0;

const char *argp_program_version = "nfsvfsslower 1.0";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
	"Trace function args and return values from SMB VFS callbacks.\n"
	"\n"
	"Usage: smbvfsiosnoop [-h] [-l TIMEOUT] [-t PID] [-d DURATION] [-i] [-j] [--inode] [--adspace] [--super] [--file] [--capturenetwork]\n"
	"\n"
	"EXAMPLES:\n"
	"    smbvfsiosnoop --file		               			# trace args and retvals of smb vfs callbacks for file ops\n"
	"    smbvfsiosnoop --adspace -p 1216			   		# trace args and retvals of smb vfs callbacks for address space ops for PID 1216 only\n"
	"    smbvfsiosnoop -d 10 -j --inode --super		        # trace args and retvals of smb vfs callbacks for 10s with csv output, inode and superblock ops only\n";

static const struct argp_option opts[] = {
    { "csv", 'j', NULL, 0, "Output as csv" },
    { "inode", 'i', NULL, 0, "Trace inode ops" },
    { "file", 'f', NULL, 0, "Trace file ops" },
    { "super", 's', NULL, 0, "Trace superblock ops" },
    { "adspace", 'a', NULL, 0, "Trace address space ops" },
    { "duration", 'd', "DURATION", 0, "Total duration of trace in seconds" },
    { "min", 'm', "MIN", 0, "Min latency to trace, in ms (default 10)" },
    { "pid", 'p', "PID", 0, "Process ID to trace" },
    { "log capture", 'l', "TIMEOUT", 0, "Capture nfsdiagnostics logs with a timeout in seconds in between subsequent captures" },
    { "capturenetwork", 'n', NULL, 0, "Capture network traffic via nfsdiagnostics" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
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
    case 'm':
        errno = 0;
        min_lat_ms = strtoll(arg, NULL, 10);
        if (errno || min_lat_ms < 0) {
            warn("invalid latency (in ms): %s\n", arg);
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
    case 'l':
        errno = 0;
        log_capture_timeout = strtol(arg, NULL, 10);
        if (errno || log_capture_timeout <= 0) {
            warn("invalid TIMEOUT: %s\n", arg);
            argp_usage(state);
        }
        nfsdiagnostics = true;
        break;
    case 'n':
        capturenetwork = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

// static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
// {
// 	if (level == LIBBPF_DEBUG && !verbose)
// 		return 0;
// 	return vfprintf(stderr, format, args);
// }

static void sig_int(int signo)
{
	exiting = 1;
}

static int start_nfsdiagnostics()
{
    int res;
    pid_t pid = fork();
    if (pid == 0) {
        // child process
        if (capturenetwork) {
            res = execl("/bin/bash", "bash", nfsdiagnostics_path, "v4", "./start", "CaptureNetwork", NULL);
        } else {
            res = execl("/bin/bash", "bash", nfsdiagnostics_path, "v4", "./start", NULL);
        }
        if (res == -1) {
            perror("execl failed");
            return(res);
        }
        if (setpgid(0, 0) != 0) {
            perror("setpgid failed");
            return -1;
        }
    }
    else if (pid > 0) {
        nfsdiagnostics_pid = pid;
        printf("nfs diagnostics started with PID %d at time %ld\n", nfsdiagnostics_pid, time(NULL));
    } else {
        perror("fork failed");
        return(pid);
    }
    return 0;
}

static int stop_nfsdiagnostics()
{
    int old_pid = -1;
    int res = 0;
    char command[256];
    if (nfsdiagnostics_pid > 0) {
        old_pid = nfsdiagnostics_pid;
        snprintf(command, sizeof(command), "%s stop", nfsdiagnostics_path);
        res = system(command);
        if (res <0 ) {
            // resort to killing the pg, unfortunately
            kill(-nfsdiagnostics_pid, SIGTERM);
        } 
        waitpid(nfsdiagnostics_pid, NULL, 0);
        printf("nfs diagnostics with PID %d stopped at time %ld\n", nfsdiagnostics_pid, time(NULL));
        nfsdiagnostics_pid = -1;
        nfsdiagnostics_end_time = time(NULL);
    }
    return old_pid;
}


static int file_callbacks_set_attach_target(struct nfsvfsslower_bpf *obj)
{
    int err = 0;
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_read_entry, 0, "nfs_file_read");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_write_entry, 0, "nfs_file_write");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_mmap_entry, 0, "nfs_file_mmap");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_nfs4_file_open_entry, 0, "nfs4_file_open");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_nfs4_file_flush_entry, 0, "nfs4_file_flush");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_release_entry, 0, "nfs_file_release");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_fsync_entry, 0, "nfs_file_fsync");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_lock_entry, 0, "nfs_lock");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_flock_entry, 0, "nfs_flock");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_file_splice_read_entry, 0, "generic_file_splice_read");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_iter_file_splice_write_entry, 0, "iter_file_splice_write");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_check_flags_entry, 0, "nfs_check_flags");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_nfs4_setlease_entry, 0, "nfs4_setlease");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_llseek_dir_entry, 0, "nfs_llseek_dir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_generic_read_dir_entry, 0, "generic_read_dir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_readdir_entry, 0, "nfs_readdir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_opendir_entry, 0, "nfs_opendir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_closedir_entry, 0, "nfs_closedir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_fsync_dir_entry, 0, "nfs_fsync_dir");

    // exit probes
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_read_exit, 0, "nfs_file_read");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_write_exit, 0, "nfs_file_write");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_mmap_exit, 0, "nfs_file_mmap");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_nfs4_file_open_exit, 0, "nfs4_file_open");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_nfs4_file_flush_exit, 0, "nfs4_file_flush");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_release_exit, 0, "nfs_file_release");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_fsync_exit, 0, "nfs_file_fsync");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_lock_exit, 0, "nfs_lock");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_flock_exit, 0, "nfs_flock");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_file_splice_read_exit, 0, "generic_file_splice_read");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_iter_file_splice_write_exit, 0, "iter_file_splice_write");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_check_flags_exit, 0, "nfs_check_flags");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_nfs4_setlease_exit, 0, "nfs4_setlease");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_llseek_dir_exit, 0, "nfs_llseek_dir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_generic_read_dir_exit, 0, "generic_read_dir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_readdir_exit, 0, "nfs_readdir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_opendir_exit, 0, "nfs_opendir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_closedir_exit, 0, "nfs_closedir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_file_fsync_dir_exit, 0, "nfs_fsync_dir");
    err? perror("set attach target file"):NULL;;

    return err;
}

static int inode_callbacks_set_attach_target(struct nfsvfsslower_bpf *obj)
{
    int err = 0;
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_permission_entry, 0, "nfs_permission");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_getattr_entry, 0, "nfs_getattr");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_setattr_entry, 0, "nfs_setattr");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_nfs4_listxattr_entry, 0, "nfs4_listxattr");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_create_entry, 0, "nfs_create");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_lookup_entry, 0, "nfs_lookup");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_atomic_open_entry, 0, "nfs_atomic_open");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_link_entry, 0, "nfs_link");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_unlink_entry, 0, "nfs_unlink");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_symlink_entry, 0, "nfs_symlink");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_mkdir_entry, 0, "nfs_mkdir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_rmdir_entry, 0, "nfs_rmdir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_mknod_entry, 0, "nfs_mknod");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_rename_entry, 0, "nfs_rename");

    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_permission_exit, 0, "nfs_permission");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_getattr_exit, 0, "nfs_getattr");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_setattr_exit, 0, "nfs_setattr");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_nfs4_listxattr_exit, 0, "nfs4_listxattr");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_create_exit, 0, "nfs_create");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_lookup_exit, 0, "nfs_lookup");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_atomic_open_exit, 0, "nfs_atomic_open");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_link_exit, 0, "nfs_link");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_unlink_exit, 0, "nfs_unlink");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_symlink_exit, 0, "nfs_symlink");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_mkdir_exit, 0, "nfs_mkdir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_rmdir_exit, 0, "nfs_rmdir");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_mknod_exit, 0, "nfs_mknod");
    err = err   ?: bpf_program__set_attach_target(obj->progs.trace_inode_rename_exit, 0, "nfs_rename");
    err? perror("set attach target inode"):NULL;;
    return err;
}

static void file_callbacks_disable_target(struct nfsvfsslower_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.trace_file_read_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_write_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_mmap_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_nfs4_file_open_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_nfs4_file_flush_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_release_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_fsync_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_lock_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_flock_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_file_splice_read_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_iter_file_splice_write_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_check_flags_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_nfs4_setlease_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_llseek_dir_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_generic_read_dir_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_readdir_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_opendir_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_closedir_entry, false);
    bpf_program__set_autoload(obj->progs.trace_file_fsync_dir_entry, false);
    
    bpf_program__set_autoload(obj->progs.trace_file_read_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_write_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_mmap_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_nfs4_file_open_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_nfs4_file_flush_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_release_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_fsync_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_lock_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_flock_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_file_splice_read_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_iter_file_splice_write_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_check_flags_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_nfs4_setlease_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_llseek_dir_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_generic_read_dir_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_readdir_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_opendir_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_closedir_exit, false);
    bpf_program__set_autoload(obj->progs.trace_file_fsync_dir_exit, false);
}

static void inode_callbacks_disable_target(struct nfsvfsslower_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.trace_inode_permission_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_getattr_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_setattr_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_nfs4_listxattr_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_create_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_lookup_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_atomic_open_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_link_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_unlink_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_symlink_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_mkdir_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_rmdir_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_mknod_entry, false);
    bpf_program__set_autoload(obj->progs.trace_inode_rename_entry, false);
   
    bpf_program__set_autoload(obj->progs.trace_inode_permission_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_getattr_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_setattr_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_nfs4_listxattr_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_create_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_lookup_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_atomic_open_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_link_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_unlink_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_symlink_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_mkdir_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_rmdir_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_mknod_exit, false);
    bpf_program__set_autoload(obj->progs.trace_inode_rename_exit, false);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct tm *tm;
	char ts[32];
	time_t t;
    const struct event *e = data;
	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return 0;
	}

    time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    syslog(LOG_ERR, "SLOW OPERATION! AT TIME %s PID %ld COMM %s TYPE %d FUNC %d LATENCY(s) %f PATH/FILEID %s RETVAL %d",
           ts, e->pid, e->task, e->type, e->function, (e->delta_us / (1000.0 * 1000.0)), e->path, e->retval);
    
    // if the events are older than the timeout, we dont need to stop the capture because these are old events
    if (nfsdiagnostics && nfsdiagnostics_pid > 0 && time(NULL) - t < 10) {
        printf("stopping nfsdiagnostics capture due to slow operation event at time %ld\n", time(NULL));
        stop_nfsdiagnostics();
    }
    return 0;
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct ring_buffer *rb = NULL;
	struct nfsvfsslower_bpf *skel;
	struct timespec end_time, current_time;
	int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    skel = nfsvfsslower_bpf__open_opts(&open_opts);
    if (!skel) {
        warn("failed to open BPF object\n");
		return 1;
    }

    skel->rodata->target_pid = target_pid;
	skel->rodata->min_lat_ns = min_lat_ms * 1000 * 1000;

	// conditional attachment: disable rest of the probes
	if (!file_ops && !inode_ops && !adspace_ops && !super_ops) {
		warn("No operations selected. Try 'nfsvfsslower --help'\n");
		goto cleanup;
	}

    if (file_ops) {
        err = file_callbacks_set_attach_target(skel);
        if (err) {
            warn("failed to set (file) attach target: %d\n", err);
            goto cleanup;
        }
    } else {
        file_callbacks_disable_target(skel);
    }

    if (inode_ops) {
        err = inode_callbacks_set_attach_target(skel);
        if (err) {
            warn("failed to set (inode) attach target: %d\n", err);
            goto cleanup;
        }
    } else {
        inode_callbacks_disable_target(skel);
    }

    //adspace

    //super

    err = nfsvfsslower_bpf__load(skel);
    if (err) {
        warn("failed to load BPF object: %d\n", err);
		goto cleanup;
    }

    /*
	 * after load
	 * if fentry is supported, let libbpf do auto load
	 */
	err = nfsvfsslower_bpf__attach(skel);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

    rb = ring_buffer__new(bpf_map__fd(skel->maps.nfsvfsrb), handle_event, NULL, NULL);
    if (!rb) {
        warn("failed to create ring buffer: %d\n", err);
        goto cleanup;
    }

    if (duration)
        end_time = get_end_time_from_duration();

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        warn("can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    openlog("nfsvfsslower_logger", LOG_PID | LOG_CONS, LOG_USER);

    printf("started reading from ring buffer\n");

    while (!exiting)
    {
        // start a new capture after it has been stopped for at least 30 seconds
        if (nfsdiagnostics && nfsdiagnostics_pid < 0 && nfsdiagnostics_end_time >= 0 && time(NULL) - nfsdiagnostics_end_time >= log_capture_timeout)
        {
            printf("nfs diagnostics is stopped, starting again\n");
            err = start_nfsdiagnostics();
            if (err < 0) {
                warn("failed to start nfsdiagnostics: %d\n", err);
                goto cleanup;
            }
        }

        err = ring_buffer__poll(rb, 10000 /* timeout, ms */);
        if (err <0 && err != -EINTR) {
            warn("error polling perf buffer: %d\n", err);
            goto cleanup;
        }

        if (duration) {
            clock_gettime(CLOCK_REALTIME, &current_time);
            double elapsed_seconds = current_time.tv_sec - end_time.tv_sec + (current_time.tv_nsec - end_time.tv_nsec) / 1e9;
            if (elapsed_seconds >= 0) {
                printf("Ending trace after %ld seconds\n", duration);
                goto cleanup;
            }
        }
        err = 0;
    }

cleanup:
    closelog();
    if (rb)
        ring_buffer__free(rb);
    nfsvfsslower_bpf__destroy(skel);
    stop_nfsdiagnostics();
    return err < 0 ? -err : 0;
}



