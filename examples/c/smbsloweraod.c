// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "shm_writer.h"
#include "smbdiag.h"
#include "cmdtranslator.h"
#include "smbsloweraod.skel.h"

#define NSEC_PER_SEC	     1000000000LL
#define warn(...)	     fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;
static struct shm_ringbuf *shm_ptr;

static time_t duration = 0;
static __u64 min_lat_ms = 10;
static __u64 wakeup_data_size = 0; /* used to wake up the user space handler */

static bool include_mode = false, exclude_mode = false;
static __u8 cmd_filter[MAX_SMB_COMMANDS] = {0};

const char *argp_program_version = "smbslower 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";

static const struct argp_option opts[] = {
	{ "wakeupsize", 'w', "WAKEUPSIZE", 0, "Wake up the userspace handler" },
	{ "duration", 'd', "DURATION", 0, "Total duration of trace in seconds" },
	{ "include-cmds", 'c', "INCLUDE", 0, "Allowed SMB commands to trace" },
	{ "exclude-cmds", 'x', "EXCLUDE", 0, "SMB commands to exclude from tracing"},
	{ "min", 'm', "MIN", 0, "Min latency to trace, in ms (default 10)" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static int parse_cmd_list(const char *arg, int max_cmds) {
	int count = 0;
	char *input = strdup(arg);
	if (!input) {
		return -1;
	}
	char *token = strtok(input, ",");
	while (token != NULL && count < max_cmds) {
		int cmd = (__u16)atoi(token);
		if (cmd >= 0 && cmd < MAX_SMB_COMMANDS) {
			cmd_filter[cmd] = 1;
			count++;
			token = strtok(NULL, ",");
		}
		token = strtok(NULL, ",");
	}
	free(input);
	return count;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			warn("invalid DURATION: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'w':
		errno = 0;
		wakeup_data_size = strtoll(arg, NULL, 10);
		if (errno || wakeup_data_size < 0) {
			warn("invalid wakeup data size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		if (exclude_mode) {
			warn("Cannot use --include-cmds with --exclude-cmds\n");
			argp_usage(state);
			return 1;
		}
		include_mode = true;
		printf("Include mode enabled, parsing commands: %s\n", arg);
		int err = parse_cmd_list(arg, MAX_SMB_COMMANDS);
		if (err < 0) {
			warn("Failed to parse include commands: %s\n", arg);
			argp_usage(state);
		} else if (err == 0) {
			warn("No valid commands specified in include list: %s\n", arg);
			argp_usage(state);
		}
		printf("%d", err);
		break;
	case 'x':
		if (include_mode) {
			warn("Cannot use --exclude-cmds with --include-cmds\n");
			argp_usage(state);
			return 1;
		}
		exclude_mode = true;
		printf("Exclude mode enabled, parsing commands: %s\n", arg);
		err = parse_cmd_list(arg, MAX_SMB_COMMANDS);
		if (err < 0) {
			warn("Failed to parse exclude commands: %s\n", arg);
			argp_usage(state);
		} else if (err == 0) {
			warn("No valid commands specified in exclude list: %s\n", arg);
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
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return 0;
	}

	printf("%d %s %d %lld %lld\n", e->pid, e->task, e->command, e->mid, e->cmd_end_time_ns);	
	printf("writing to shared memory");
	if (shm_ringbuf_write(shm_ptr, e) < 0) {
		fprintf(stderr, "Failed to write event to shared memory\n");
		return -1; // Not enough space
	}
	/* We have opened shared memory here between the python event dispatcher and this program */

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

int update_denylist_map(struct smbsloweraod_bpf *skel) {
	for (__u16 cmd = 0; cmd < MAX_SMB_COMMANDS; cmd ++) {
		bool deny = false;
		if (exclude_mode && cmd_filter[cmd]) deny = true;
		else if (include_mode && !cmd_filter[cmd]) deny = true;

		if (deny) {
			printf("Denying command %d (%s)\n", cmd, get_smb_command(cmd));
			if (bpf_map_update_elem(bpf_map__fd(skel->maps.denylist), &cmd, &deny, BPF_ANY) < 0) {
				warn("Failed to update denylist map for command %d\n", cmd);
				return -1;
			}
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct smbsloweraod_bpf *skel;
	struct timespec end_time, current_time;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) return err;
	
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);

	skel = smbsloweraod_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	skel->rodata->min_lat_ns = min_lat_ms * 1000 * 1000;
	skel->rodata->wakeup_data_size = wakeup_data_size;

	err = smbsloweraod_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	if (update_denylist_map(skel) < 0) {
		fprintf(stderr, "Failed to update denylist map\n");
		goto cleanup;
	}

	/* Open shared memory */
	int shm_fd = init_shared_memory(SHM_NAME, SHM_SIZE, &shm_ptr);
	if (shm_fd < 0) {
		fprintf(stderr, "Shared memory init failed from C program\n");
		goto cleanup_shm;
	}

	err = smbsloweraod_bpf__attach(skel);
	if(err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup_shm;
	}

	int map_fd = bpf_obj_get(RINGBUF_PINNED);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        err = -1;
        goto cleanup;
    }

	// need to edit size also
	rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup_shm;
	}

	if (duration) end_time = get_end_time_from_duration();

	/* Poll */
	while (!exiting) {
		err = ring_buffer__poll(rb, 5); /* wait only for 5ms to collect other events */
		if (err < 0 && err != -EINTR) {
			printf("error polling the ring buffer: %d\n", err);
			goto cleanup_shm;
		}
		if (duration) {
			clock_gettime(CLOCK_REALTIME, &current_time);
			double elapsed_seconds = difftime(current_time.tv_sec, end_time.tv_sec);
			if (elapsed_seconds > 0)
				goto cleanup_shm;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup_shm:
	munmap(shm_ptr, SHM_SIZE);
	close(shm_fd);
cleanup:
	if (rb)
		ring_buffer__free(rb);
	if (map_fd >= 0)
		close(map_fd);
	smbsloweraod_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}