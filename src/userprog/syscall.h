#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <user/syscall.h>
#include <threads/synch.h>
#include <threads/vaddr.h>

/* Only a single thread(either user or kernel) can access the file system
   at any time. */
struct lock file_system_lock;

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
