#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads/synch.h>
#include <threads/malloc.h>
#include <lib/user/syscall.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define MAX_CMD_LINE_LENGTH 512
#define MAX_TOKEN_COUNT  25
#define MAX_TOKEN_BUFFER_LENGTH 255

static inline void close_all_files(void);
static inline void free_child_list_entries(void);

static thread_func start_process NO_RETURN;
static bool load (const char *cmd_line, void (**eip) (void), void **esp);
static struct exit_status *get_exit_status_by_tid(tid_t child_tid);

extern struct lock file_lock;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmd_line)
{
  char *fn_copy;
  tid_t tid;

  thread_current()->child_load_successful = false;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, cmd_line, PGSIZE);

  /* Get file name from command line
   * Since cmd_line is const char *, we need to create another copy of
   * it to tokenize. */
  int cmd_line_len = (int) strnlen(cmd_line, MAX_CMD_LINE_LENGTH);
  char cmd_line_cpy[cmd_line_len + 1];
  strlcpy(cmd_line_cpy, cmd_line, MAX_CMD_LINE_LENGTH + 1);
  char *save_ptr;
  char *file_name = strtok_r(cmd_line_cpy, " ", &save_ptr);
  lock_acquire(&file_lock);
  struct file *file = filesys_open(file_name);
  lock_release(&file_lock);
  if (file == NULL) {
    palloc_free_page (fn_copy);
    return TID_ERROR;
  } else {
    file_close(file);
  }

  /* Allocate exit status entry for child process */
  struct exit_status *es = malloc(sizeof(struct exit_status));
  if (es == NULL) {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  /* Initialize necessary semaphores */
  sema_init(&thread_current()->added_entry_for_child, 0);
  sema_init(&thread_current()->child_reported_load_status, 0);
  sema_init(&es->has_exited, 0);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR) {
    free(es);
    palloc_free_page (fn_copy);
    return tid;
  }

  /* setup exit_status entry and add to parent's entry list */
  es->tid = tid;
  list_push_back(&thread_current()->child_list, &es->elem);
  /* Tell child the entry has set up */
  sema_up(&thread_current()->added_entry_for_child);
  /* Wait for child to update whether it is successfully loaded or not */
  sema_down(&thread_current()->child_reported_load_status);
  es->thread = thread_current()->last_created_child;
  /* Return ERROR if load is unsuccessful */
  if (!thread_current()->child_load_successful) {
    return TID_ERROR;
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (file_name, &if_.eip, &if_.esp);
  struct thread *parent = thread_current()->parent;

  /* Wait for parent to setup exit_status entry. */
  sema_down(&parent->added_entry_for_child);
  /* Report to parent whether load is successful and update parent's last create child. */
  parent->last_created_child = thread_current();
  parent->child_load_successful = success;
  /* Tell parent I have already reported my load status. */
  sema_up(&parent->child_reported_load_status);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) {
    exit(FAIL);
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct exit_status *entry = get_exit_status_by_tid(child_tid);
  /* If either not a child or have waited for this child more than once.*/
  if (entry == NULL) {
    return FAIL;
  }
  sema_down(&entry->has_exited);
  int status = entry->status;
  list_remove(&entry->elem);
  free(entry);
  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      close_all_files();

      free_child_list_entries();

      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *args);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *cmd_line, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Copy const string to another string */
  size_t length = strlen(cmd_line);
  char args[length + 1], line[length + 1];
  strlcpy(args, cmd_line, length + 1);
  strlcpy(line, cmd_line, length + 1);

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) {
    goto done;
  }
  process_activate ();

  /* Open executable file. */
  const char *file_name = thread_current()->name;
  lock_acquire(&file_lock);
  file = filesys_open (file_name);
  lock_release(&file_lock);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, args))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  thread_current()->exec_file = file;
  if (file != NULL) {
    file_deny_write(file);
  }
  return success;
}

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* This macro pushes a value of type @param:type to the given address in the stack */
/* It simply changes the VALUE of the given esp pointer
 * To use this macro, pass the ADDRESS of the value u wish to change in to this macro
 * as esp, do NOT pass the POINTER TO THE ADDRESS directly!
 * e.g.
 *     (void **)ptr -> (void *)addr -> (type_t)value_you_want_to_change
 *               |               |
 *     Don't pass this in   Pass this in
 */
#define PUSH(esp, type_t, value)  esp = (typeof(esp)) ((type_t *)esp - 1);  /* Shift esp to its next location */  \
                                  if (esp < PHYS_BASE - PGSIZE) {           /* If esp is invalid, return false */ \
                                    intr_set_level(old_level);                                                    \
                                    palloc_free_page (kpage);                                                     \
                                    return false;                                                                 \
                                  }                                                                               \
                                  *(type_t *)(esp) = (value);               /* Push the given value to esp */     \

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char *args)
{
  uint8_t *kpage;
  bool success = false;
  enum intr_level old_level = intr_disable();

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) {
        /* Push everything to the stack */
        *esp = PHYS_BASE;
        int argc = 0;
        char *addr[MAX_TOKEN_COUNT];
        char argv_buffer[MAX_TOKEN_BUFFER_LENGTH + 1];
        char *token, *save_ptr;
        /* Push all argv strings to the stack from last to first */
        for (token = strtok_r(args, " ", &save_ptr)
                ; token != NULL
                ; token = strtok_r(NULL, " ", &save_ptr)) {
          /* First tokenize remaining cmd_line */
          strlcpy(argv_buffer, token, MAX_TOKEN_BUFFER_LENGTH);
          int num_of_chars = (int) strnlen(argv_buffer, MAX_TOKEN_BUFFER_LENGTH);
          /* PUSH each arg to the stack in reverse order
           * So when retrieving args, they will be in the right order */
          for (int i = num_of_chars; i >= 0; i--) {
            PUSH(*esp, char, argv_buffer[i]);
          }
          /* Update address and argc */
          addr[argc++] = *esp;
        }
        /* Word align */
        while ((uint32_t)*esp % 4 != 0) {
          PUSH(*esp, uint8_t, 0);
        }
        /* Push addresses of each token */
        PUSH(*esp, char *, NULL);
        for (int i = argc - 1; i >= 0; i--) {
          PUSH(*esp, char *, addr[i]);
        }
        /* Push argv and argc */
        char **argv_addr = (char **) *esp;
        PUSH(*esp, char **, argv_addr);
        PUSH(*esp, int, argc);
        PUSH(*esp, void *, NULL);
      } else {
        palloc_free_page (kpage);
      }
    }
  intr_set_level(old_level);
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* load() helpers. */
/* Get exit_status entry by a given tid
 * If such entry cannot be found, return NULL */
static struct exit_status *
get_exit_status_by_tid(tid_t child_tid) {
  struct list *child_list = &thread_current()->child_list;
  for (struct list_elem *e = list_begin(child_list)
          ; e != list_end(child_list)
          ; e = list_next(e)) {
    struct exit_status *entry = list_entry(e, struct exit_status, elem);
    if (entry->tid == child_tid) {
      return entry;
    }
  }
  return NULL;
}

/* Close all files opened by the current process
 * Only be called when the current process is exiting */
static inline void
close_all_files() {
  struct list *file_list = &thread_current()->local_file_fd_list;
  for (struct list_elem *e = list_begin(file_list)
          ; e != list_end(file_list)
          ;) {
    struct file_fd_entry *entry = list_entry(e, struct file_fd_entry, local_elem);
    file_close(entry->file);
    e = list_remove(e);
    free(entry);
  }
}

/* Free all child entries holding by the current process
 * Only be called when the current process is exiting */
static inline void
free_child_list_entries() {
  enum intr_level old_level = intr_disable();
  struct list *child_list = &thread_current()->child_list;
  for (struct list_elem *e = list_begin(child_list)
          ; e != list_end(child_list)
          ; ) {
    struct exit_status *entry = list_entry(e, struct exit_status, elem);
    /* set child's parent to null */
    struct thread *child = entry->thread;
    if (child != NULL) {
      child->parent = NULL;
    }
    e = list_remove(e);
    free(entry);
  }
  intr_set_level(old_level);
}