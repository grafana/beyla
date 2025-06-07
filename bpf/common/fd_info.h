#pragma once

#include <bpfcore/utils.h>

#include <pid/types/pid_key.h>
#include <pid/pid_helpers.h>

typedef enum _fd_type {
    FD_CLIENT = 0, // connect calls
    FD_SERVER = 1, // accept calls
} fd_type_t;

typedef struct _fd_info {
    pid_key_t pid;  // current PID info
    int fd;         // the file descriptor
    fd_type_t type; // type of file descriptor
} fd_info_t;

static __always_inline void fd_info(fd_info_t *key, int fd, fd_type_t type) {
    key->fd = fd;
    key->type = type;
    task_tid(&key->pid);
}