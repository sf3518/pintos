#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "list.h"

#define FAIL -1

void syscall_init (void);

struct file_fd_entry {
    struct file *file;
    int fd;
    struct list_elem local_elem;
};

#endif /* userprog/syscall.h */
