/**
 * This is a C-extension to directly use libbpf APIs in Python.
 * Specifically, we can poll from the eBPF ringbuffer without relying
 * on IPC to communicate the data from C to Python program.
 * 
 * Each eBPF script should use the same pinned eBPF ringbuffer. As soon
 * as the eBPF script is loaded, the bpf object should be created and
 * pinned.
 * 
 * By default, LIBBPF_PIN_BY_NAME pins the maps by name in
 * /sys/fs/bpf. This means that we should take the path where bpffs is
 * mounted from the AOD app.
 * 
 * This module enables the following:
 * 
 * 1. Create a new ringbuffer object after looking up the pinned bpf
 * object fd.
 * 2. Poll from the eBPF ringbuffer and return the data to the Python
 * caller.
 * 3. Destroy the ringbuffer.
 * 4. Close/unlink the pinned fd.
 * 
 */

#include <Python.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct ring_buffer *rb = NULL;

// in handle_event, we pass the dequeued C structs to a Python Callback
static int handle_event(void *ctx, void *data, size_t data_sz) {
	const struct event *e = data;
	if (data_sz < sizeof(e)) {
		return -1;
	}
	return 0;
}

static PyObject *libbpf_ring_buffer__init(PyObject *self, PyObject *args) {
	const char* pinned_map_path;

	if (!PyArg_ParseTuple(args, "s", &pinned_map_path));
		return NULL;
	int map_fd = bpf_obj_get(pinned_map_path);
	if (map_fd < 0) {
		perror("bpf_obj_get");
		return -1;
	}

	rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
}
