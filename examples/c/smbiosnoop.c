#include <argp.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <endian.h>
#include <errno.h>
#include <iconv.h>
#include <wchar.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "smbiosnoop.h"
#include "smbiosnoop.skel.h"

#define PERF_BUFFER_PAGES    64
#define PERF_POLL_TIMEOUT_MS 100
#define NSEC_PER_SEC	     1000000000LL

#define warn(...)	     fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

/* options */
static pid_t target_pid = 0;
static __u32 target_cid = 0;
static int target_eid = 0;
static time_t duration = 0;
static bool csv = false;
static bool verbose = false;

const char *argp_program_version = "smbiosnoop 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
	"Trace smb file system operations slower than a threshold.\n"
	"\n"
	"Usage: smbiosnoop [-h] [-p PID] [-c CID] [-d DURATION] [-j] [-e EID]\n"
	"\n"
	"EXAMPLES:\n"
	"    smbiosnoop 		               # trace all failed smb operations\n"
	"    smbiosnoop -p 1216			   # trace smb operations with PID 1216 only\n"
	"    smbiosnoop -d 1 -j   		   # trace smb operations for 1s with csv output\n"
	"    smbiosnoop -e 5   		       # trace smb operations with err code -5\n";

static const struct argp_option opts[] = {
	{ "csv", 'j', NULL, 0, "Output as csv" },
	{ "duration", 'd', "DURATION", 0, "Total duration of trace in seconds" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "cid", 'c', "CID", 0, "SMB command to trace" },
	{ "err", 'e', "EID", 0, "Server error to trace" },
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
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			warn("invalid DURATION: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		errno = 0;
		target_cid = strtol(arg, NULL, 10);
		if (errno || target_cid <= 0) { //add greater than condition aslo
			warn("invalid CID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'e':
		errno = 0;
		target_eid = strtoll(arg, NULL, 10);
		if (errno || target_eid < 0) { // add err code check
			warn("invalid EID: %s\n", arg);
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

const char *get_smb_command(unsigned short smbcommand)
{
	switch (smbcommand) {
	case 0x0000:
		return "SMB2_NEGOTIATE";
	case 0x0001:
		return "SMB2_SESSION_SETUP";
	case 0x0002:
		return "SMB2_LOGOFF";
	case 0x0003:
		return "SMB2_TREE_CONNECT";
	case 0x0004:
		return "SMB2_TREE_DISCONNECT";
	case 0x0005:
		return "SMB2_CREATE";
	case 0x0006:
		return "SMB2_CLOSE";
	case 0x0007:
		return "SMB2_FLUSH";
	case 0x0008:
		return "SMB2_READ";
	case 0x0009:
		return "SMB2_WRITE";
	case 0x000A:
		return "SMB2_LOCK";
	case 0x000B:
		return "SMB2_IOCTL";
	case 0x000C:
		return "SMB2_CANCEL";
	case 0x000D:
		return "SMB2_ECHO";
	case 0x000E:
		return "SMB2_QUERY_DIRECTORY";
	case 0x000F:
		return "SMB2_CHANGE_NOTIFY";
	case 0x0010:
		return "SMB2_QUERY_INFO";
	case 0x0011:
		return "SMB2_SET_INFO";
	case 0x0012:
		return "SMB2_OPLOCK_BREAK";
	case 0x0013:
		return "SMB2_SERVER_TO_CLIENT_NOTIFICATION";
	default:
		return "UNKNOWN_COMMAND";
	}
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

static int fentry_set_attach_target(struct smbiosnoop_bpf *obj)
{
	int err = 0;
	err = err   ?:
		      bpf_program__set_attach_target(obj->progs.smb_network_req_fentry, 0,
						     "compound_send_recv");
	return err;
}

static void print_headers()
{
	if (csv) {
		printf("TASK,PID,ERR_TYPE,NUM_RQST,SESSION_ID,CONN_ID,COMMAND,OPLOCK\n");
		return;
	}

	if (target_pid)
		printf("Tracing SMB operations only for PID %d\n", target_pid);

	if (target_eid)
		printf("Tracing SMB operations that fail with error %d\n", target_eid);

	if (duration)
		printf(" for %ld secs.\n", duration);
	else
		printf("Hit Ctrl-C to end.\n");

	printf("%-14s %-7s %-10s %-10s %15s %15s %16s %30s\n", "TASK", "PID", "ERR_TYPE",
	       "NUM_RQST", "SESSION_ID", "CONN_ID", "COMMAND", "PARAMS");
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}

    memcpy(&e, data, sizeof(e));

	if (csv) {
		//reverse map the command
		printf("%s,%d,%d,%d,0x%llx,%lld,%s,%s\n", e.task, e.pid, e.server_retval, e.num_rqst,
		       e.session_id, e.connection_id, get_smb_command(e.smbcommand), "e.commandargs");
		return;
	}

    printf("%-14s %-7d %-10d %-10d 0x%-23llx %-12lld %16s %30s\n", e.task, e.pid, e.server_retval,
           e.num_rqst, e.session_id, e.connection_id, get_smb_command(e.smbcommand), "e.commandargs");

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
	struct smbiosnoop_bpf *skel;
	struct timespec end_time, current_time;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	skel = smbiosnoop_bpf__open_opts(&open_opts);
	if (!skel) {
		warn("failed to open BPF object\n");
		return 1;
	}

	skel->rodata->target_pid = target_pid;
	skel->rodata->target_cid = target_cid;
	// skel->rodata->target_eid = target_eid;

	err = fentry_set_attach_target(skel);
	if (err) {
		warn("failed to set attach target: %d\n", err);
		goto cleanup;
	}

	err = smbiosnoop_bpf__load(skel);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/*
	 * after load
	 * if fentry is supported, let libbpf do auto load
	 */
	err = smbiosnoop_bpf__attach(skel);
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
	smbiosnoop_bpf__destroy(skel);

	return err != 0;
}


