
#include "shm_writer.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int init_shared_memory(const char *name, size_t size, struct shm_ringbuf **shm_ptr) {
    int created = 0;
    int shm_fd = shm_open(name, O_RDWR, 0666);
    if (shm_fd < 0 && errno == ENOENT) {
        // If shm_open fails, try to create the shared memory object
        shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
        if (shm_fd < 0) {
            perror("Failed to create shared memory from C program");
            return -1;
        }
        created = 1; // Indicate that we created the shared memory
    }

    if (shm_fd < 0) {
        perror("Failed to open shared memory from C program");
        return -1;
    }

    if (created) {
        if (ftruncate(shm_fd, size) < 0) {
            perror("Failed to set size of shared memory from C program");
            close(shm_fd);
            return -1;
        }
    }

    *shm_ptr = mmap(0, size, PROT_WRITE | PROT_READ, MAP_SHARED, shm_fd, 0);
    if (*shm_ptr == MAP_FAILED) {
        perror("Failed to map shared memory in C program");
        close(shm_fd);
        return -1;
    }

    if (created) {
        // Initialize the shared memory structure
        (*shm_ptr)->head = 0;
        (*shm_ptr)->tail = 0;
        memset((*shm_ptr)->data, 0, SHM_DATA_SIZE);
        printf("Created and initialized shared memory: %s\n", name);
    } else {
        // If not created, read the existing head and tail
        printf("Opened existing shared memory: %s, head=%zu, tail=%zu\n", name, (*shm_ptr)->head, (*shm_ptr)->tail);
    }

    return shm_fd;
}

int shm_ringbuf_write(struct shm_ringbuf *buf, const struct event *e) {
    printf("In shm_ringbuf_write\n");
    size_t len = sizeof(struct event);
    size_t head = buf->head;
    size_t tail = buf->tail;
    size_t free_space = (tail + SHM_DATA_SIZE - head - 1);

    if (len > free_space) {
        fprintf(stderr, "Not enough space in shared memory to write event\n");
        return -1; // Not enough space
    }

    size_t offset = head % SHM_DATA_SIZE;
    size_t first_chunk = SHM_DATA_SIZE - offset;

    if (len <= first_chunk) {
        memcpy(&buf->data[offset], e, len);
    } else {
        memcpy(&buf->data[offset], e, first_chunk);
        memcpy(buf->data, (char *)e + first_chunk, len - first_chunk);
    }
    
    // Memory barrier to ensure data is visible before updating head
    __sync_synchronize();

    buf->head = (head + len);
    printf("Wrote event to shared memory: head=%zu, tail=%zu\n", buf->head, buf->tail);
    return 0;