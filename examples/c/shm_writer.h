#ifndef SHM_WRITER_H
#define SHM_WRITER_H

#include <sys/mman.h>
#include <stddef.h>
#include "smbdiag.h"

#define SHM_NAME "/bpf_shm"
#define SHM_SIZE ((MAX_ENTRIES + 1) * 4096) // should always be a multiple of the page size
#define SHM_DATA_SIZE (SHM_SIZE - sizeof(size_t) * 2) // size of data minus head and tail

struct shm_ringbuf {
    size_t head;
    size_t tail;
    char data[SHM_DATA_SIZE];
};

extern int init_shared_memory(const char *name, size_t size, struct shm_ringbuf **shm_ptr);
extern int shm_ringbuf_write(struct shm_ringbuf *shm_ptr,const  struct event *event);

#endif
