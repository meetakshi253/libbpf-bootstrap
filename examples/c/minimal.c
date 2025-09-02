// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "minimal.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *pid, size_t data_sz)
{
	printf("here");

	return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int get_map_id(int fd)
{
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	int err;

	err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
	if (err) {
		perror("bpf_obj_get_info_by_fd");
		return -1;
	}

	return info.id; // unique kernel id for this map
}

int main(int argc, char **argv)
{
	struct minimal_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = minimal_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */
	skel->bss->my_pid = getpid();

	int pinned_fd = bpf_obj_get("/sys/fs/bpf/rb");
	if (pinned_fd >= 0) {
		printf("reusing the same ringbuffer");
		err = bpf_map__reuse_fd(skel->maps.rb, pinned_fd);
		if (err) {
			fprintf(stderr, "bpf_map__reuse_fd failed: %s\n", strerror(-err));
			goto cleanup;
		}
		close(pinned_fd);
		pinned_fd = -1;
	}

	/* Load & verify BPF programs */
	err = minimal_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	if (bpf_obj_get("/sys/fs/bpf/rb") < 0) {
		err = bpf_map__pin(skel->maps.rb, "/sys/fs/bpf/rb");
		if (err) {
			fprintf(stderr, "Failed to pin ring buffer map: %s\n", strerror(-err));
			goto cleanup;
		}
		printf("Pinned ring buffer at /sys/fs/bpf/rb\n");
	}

	err = minimal_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	int map_fd = bpf_obj_get("/sys/fs/bpf/rb");
	if (map_fd < 0) {
		perror("bpf_obj_get");
		err = -1;
		goto cleanup;
	}

	printf("%d %d", get_map_id(map_fd), get_map_id(bpf_map__fd(skel->maps.rb)));

	rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	if (rb)
		ring_buffer__free(rb);
	if (map_fd >= 0)
		close(map_fd);
	minimal_bpf__destroy(skel);
	return -err;
}
