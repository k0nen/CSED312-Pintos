#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "user/syscall.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "filesys/filesys.h"

struct file_desc
  {
    int fd;                             /* File descriptor. */
    tid_t owner;                        /* Owner of this file. */
    struct file *file;                  /* Pointer to struct file. */
    struct list_elem elem;              /* List element for file_list. */
  };

struct child
  {
    tid_t parent_id, child_id;          /* tid of parent/child. */
    bool is_dead;						            /* Status of child process. */
    struct lock exec_lock;
	  struct condition exec_flag;
    int exec_code;                      /* Execution code of child process. */
    int exit_code;                      /* Exit code of child process. */
    struct list_elem elem;         /* List element for child_list. */
  };

/* Utility functions */
void assert_valid_ptr(void *p);

/* Syscalls */
void syscall_init (void);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);


#endif /* userprog/syscall.h */
