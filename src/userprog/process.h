#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <threads/synch.h>
#include "threads/thread.h"
#include "syscall.h"

struct exit_status {
    tid_t tid;
    struct semaphore has_exited;
    int status;
    struct thread *thread;
    struct list_elem elem;
};

tid_t process_execute (const char *cmd_line);
int process_wait (tid_t child_tid);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
