#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <lib/user/syscall.h>
#include <threads/vaddr.h>
#include <string.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "pagedir.h"

#define FD_READ_FROM_CONSOLE 0
#define FD_WRITE_TO_CONSOLE 1
#define MAX_FILE_NAME_LENGTH 14

static inline bool is_valid_vaddr(const void *vaddr);
static inline struct file *look_up_file_by_fd(int fd);
static inline void check_vaddr(const void *vaddr);
static inline void read_char_to_buffer(char *buffer, int offset, char c);

static struct file_fd_entry *get_fd_entry(int fd);
static void syscall_handler (struct intr_frame *);

static int fd_allocator;
struct lock file_lock;

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  fd_allocator = 2;
  lock_init(&file_lock);
}

/* Pop the next value of type type_t from the given pointer
 * This macro merely moves the address, it does not modify where and how the
 * values are stored.
 * To use this macro, DO NOT pass the pointer to the address in directly!
 * e.g.
 *     (void **)ptr -> (void *)addr -> (type_t)value_you_want_to_change
 *               |               |
 *     Don't pass this in   Pass this in
 *     */
#define POP(esp, type_t)  ({                                                                      \
          check_vaddr(esp);               /* Check if esp is valid, if not exit(-1) immediately*/ \
          type_t val = *(type_t *)(esp);  /* Get the value stored at esp, in the form of type_t*/ \
          (esp) = (typeof(esp))((type_t *)(esp) + 1); /* Shift esp to its next location */        \
          val;                            /*Return the value*/                                    \
          })

static void
syscall_handler (struct intr_frame *f)
{
  thread_current()->during_system_call = true;
  void *esp = f->esp;
  int syscall_nr = POP(esp, int);
  switch (syscall_nr) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT: {
      int status = POP(esp, int);
      exit(status);
      break;
    }
    case SYS_EXEC: {
      const char *cmd_line = POP(esp, const char *);
      check_vaddr(cmd_line);
      f->eax = (uint32_t) exec(cmd_line);
      break;
    }
    case SYS_WAIT: {
      pid_t pid = POP(esp, pid_t);
      f->eax = (uint32_t) wait(pid);
      break;
    }
    case SYS_CREATE: {
      const char *file = POP(esp, const char *);
      unsigned initial_size = POP(esp, unsigned);
      check_vaddr(file);
      f->eax = (uint32_t) create(file, initial_size);
      break;
    }
    case SYS_REMOVE: {
      const char *file = POP(esp, const char *);
      check_vaddr(file);
      f->eax = (uint32_t) remove(file);
      break;
    }
    case SYS_OPEN: {
      const char *file = POP(esp, const char *);
      check_vaddr(file);
      f->eax = (uint32_t) open(file);
      break;
    }
    case SYS_FILESIZE: {
      int fd = POP(esp, int);
      f->eax = (uint32_t) filesize(fd);
      break;
    }
    case SYS_READ: {
      int fd = POP(esp, int);
      void *buffer = POP(esp, void *);
      check_vaddr(buffer);
      unsigned size = POP(esp, unsigned);
      f->eax = (uint32_t)read(fd, buffer, size);
      break;
    }
    case SYS_WRITE: {
      int fd = POP(esp, int);
      void *buffer = POP(esp, void *);
      check_vaddr(buffer);
      unsigned size = POP(esp, unsigned);
      f->eax = (uint32_t) write(fd, buffer, size);
      break;
    }
    case SYS_SEEK: {
      int fd = POP(esp, int);
      unsigned position = POP(esp, unsigned);
      seek(fd, position);
      break;
    }
    case SYS_TELL: {
      int fd = POP(esp, int);
      f->eax = tell(fd);
      break;
    }
    case SYS_CLOSE: {
      int fd = POP(esp, int);
      close(fd);
      break;
    }
    default:
      NOT_REACHED();
  }
}

/* Check if the given vaddr is valid */
static inline bool
is_valid_vaddr(const void *vaddr) {
  uint32_t *pd = thread_current()->pagedir;
  return (vaddr != NULL) && is_user_vaddr(vaddr) && (pagedir_get_page(pd, vaddr) != NULL);
}

/* If the given vaddr is not valid, exit(-1) immediately */
static inline void
check_vaddr(const void *vaddr) {
  if (!is_valid_vaddr(vaddr)) {
    exit(FAIL);
  }
}

/* Read a character to given buffer */
static inline void
read_char_to_buffer(char *buffer, int offset, char c) {
  *(buffer + offset) = c;
}

/* Get an fd_entry from current thread's file_fd list by a given fd
 * Return NULL if no such entry exists */
static struct file_fd_entry *
get_fd_entry(int fd) {
  struct list *file_fd_list = &thread_current()->local_file_fd_list;
  for (struct list_elem *e = list_begin(file_fd_list)
          ; e != list_end(file_fd_list)
          ; e = list_next(e)) {
    struct file_fd_entry *entry = list_entry(e, struct file_fd_entry, local_elem);
    if (entry->fd == fd) {
      return entry;
    }
  }
  return NULL;
}

/* Look up a file from current thread's file_fd list by given fd
 * return NULL if no such file can be found */
static inline struct file *
look_up_file_by_fd(int fd) {
  struct file_fd_entry *entry = get_fd_entry(fd);
  if (entry != NULL) {
    return entry->file;
  }
  return NULL;
}

/* Update exit status to parent thread before exiting
 * Notify parent this update is finished by sema_up */
static void
update_exit_status(int status) {
  enum intr_level old_level = intr_disable();
  struct thread *parent = thread_current()->parent;
  if (parent != NULL) {
    for (struct list_elem *e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e)) {
      struct exit_status *entry = list_entry(e, struct exit_status, elem);
      if (entry->tid == thread_current()->tid) {
        entry->status = status;
        sema_up(&entry->has_exited);
        break;
      }
    }
  }
  intr_set_level(old_level);
}

/**-----SYSTEM CALLS-----**/

void
halt(void) {
  shutdown_power_off();
}

void
exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);
  if (thread_current()->exec_file != NULL) {
      file_allow_write(thread_current()->exec_file);
  }
  update_exit_status(status);
  thread_exit();
  NOT_REACHED();
}

pid_t
exec(const char *cmd_line) {
  tid_t tid = process_execute(cmd_line);
  return tid;
}

int
wait(pid_t pid) {
  return process_wait(pid);
}

bool
create(const char *file, unsigned initial_size) {
  /* Do not allow empty file name
   * exit(-1) directly in this scenario. */
  if (*file == '\0') {
    exit(FAIL);
  }
  /* Do not allow too long file name
   * instead of exit directly, return false. */
  if (strnlen(file, MAX_FILE_NAME_LENGTH + 1) > MAX_FILE_NAME_LENGTH) {
    return false;
  }
  return filesys_create(file, initial_size);
}

bool
remove(const char *file) {
  return filesys_remove(file);
}

int
open(const char *file) {
  if (file_lock.holder != thread_current()) {
    lock_acquire(&file_lock);
  }
  struct file *f = filesys_open(file);
  if (f != NULL) {
    struct file_fd_entry *entry = malloc(sizeof(struct file_fd_entry));
    if (entry == NULL) {
      lock_release(&file_lock);
      exit(FAIL);
      NOT_REACHED();
    }
    entry->file = f;
    entry->fd = fd_allocator++;
    list_push_back(&thread_current()->local_file_fd_list, &entry->local_elem);
    lock_release(&file_lock);
    return entry->fd;
  }
  lock_release(&file_lock);
  return FAIL;
}

int
filesize(int fd) {
  struct file *f = look_up_file_by_fd(fd);
  if (f != NULL) {
    return file_length(f);
  }
  return FAIL;
}

int
read(int fd, void *buffer, unsigned size) {
  if (fd == FD_READ_FROM_CONSOLE) {
    for (unsigned i = 0; i < size; i++) {
      read_char_to_buffer(buffer, i, input_getc());
    }
    return size;
  }
  struct file *f = look_up_file_by_fd(fd);
  if (f != NULL) {
    int result = file_read(f, buffer, size);
    return result;
  }
  return FAIL;
}

int
write(int fd, const void *buffer, unsigned size) {
  if (fd == FD_WRITE_TO_CONSOLE) {
    putbuf(buffer, size);
    return size;
  }
  struct file *f = look_up_file_by_fd(fd);
    if (f != NULL) {
        int result = file_write(f, buffer, size);
        return result;
  }
  return FAIL;
}

void
seek(int fd, unsigned position) {
  struct file *f = look_up_file_by_fd(fd);
  if (f != NULL) {
    file_seek(f, position);
  }
}

unsigned
tell(int fd) {
  struct file *f = look_up_file_by_fd(fd);
  if (f != NULL) {
    return (unsigned) file_tell(f);
  }
  /* Exit -1 if no file is found */
  exit(FAIL);
}

void
close (int fd) {
  struct file_fd_entry *entry = get_fd_entry(fd);
  if (entry != NULL) {
    file_close(entry->file);
    list_remove(&entry->local_elem);
    free(entry);
  }
}
