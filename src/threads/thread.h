#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdbool.h>
#include <stdint.h>
#include "synch.h"
#include "lib/kernel/hash.h"
#include "threads/fixed-point.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;

#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* Nice value special */
#define NICE_MAX (20)                   /* Maximum value of Nice */
#define NICE_MIN (-20)                  /* Minimum value of Nice */
/* Macro which detects if a nice value is between MAX and MIN */
#define IS_ERROR_NICE(n) ((n) > NICE_MAX || (n) < NICE_MIN)

#define MAX_FILE_OPEN_PER_THREAD 128

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Effective Priority. */
    int base_priority;                  /* Base Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    int64_t wake_up_time;               /* Time for a sleeping thread to wake up.*/
    fp_t nice_fp;
    fp_t recent_cpu_fp;

    struct lock *waiting_for_this_lock; /* The lock needed to be acquired */
    struct list holding_lock_list;      /* The locks possessed. */
    bool during_system_call;            /* Whether the thread is during system call. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    struct thread *parent;              /* Parent thread of this thread */
    struct thread *last_created_child;  /* Temporary pointer for keeping track of last created process' thread
                                         * Used only in process_exec, allow child process to set the parent thread's
                                         * last_created_child, so that the parent can add child to exit_status */
    struct list child_list;             /* Keep track of the children */
    struct list local_file_fd_list;     /* List for storing fd and files */

    struct semaphore added_entry_for_child;       /* Semaphore, parent tells child it has setup the entry */
    struct semaphore child_reported_load_status;  /* Semaphore, child tells parent it has reported load_status to parent */

    bool child_load_successful;         /* Child updates this member of its parent after load */
    struct file *exec_file;             /* file that the current process is executing on */

    uint32_t *pagedir;                  /* Page directory. */

#endif
    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);
size_t threads_ready(void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
struct thread *get_thread(tid_t tid);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Yield to a thread of higher priority if necessary. */
void thread_check_and_yield(void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

void thread_set_priority_mlfqs(void);
int thread_get_priority_mlfqs (void);

/* Functions for comparing 2 threads based on their priority.
 * For inserting threads to ready list. */
bool
thread_priority_compare(
        const struct list_elem *e1,
        const struct list_elem *e2,
        void *aux UNUSED);
bool
thread_priority_compare_greater(
        const struct list_elem *e1,
        const struct list_elem *e2,
        void *aux UNUSED);

int thread_get_nice (void);
void thread_set_nice (int);
void thread_update_recent_cpu (void);
int thread_get_recent_cpu (void);
void thread_update_load_avg(void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */