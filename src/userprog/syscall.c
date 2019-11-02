#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Check if the giver pointer has a valid address. Every
   memory access attempts inside system calls must check
   this for validity. */
bool
is_valid_ptr(void *p)
{
  return true;
}

static void
syscall_handler (struct intr_frame *f) 
{
  // esp holds address to syscall code
  int32_t *esp = f->esp;
  
  if(!is_valid_ptr(esp))
    exit(-1);

  switch(*esp)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    break;
  case SYS_EXEC:
    break;
  case SYS_WAIT:
    break;
  case SYS_CREATE:
    break;
  case SYS_REMOVE:
    break;
  case SYS_OPEN:
    break;
  case SYS_FILESIZE:
    break;
  case SYS_READ:
    break;
  case SYS_WRITE:
    break;
  case SYS_SEEK:
    break;
  case SYS_TELL:
    break;
  case SYS_CLOSE:
    break;
  default:
    break;
  }
}

/* Terminates Pintos by calling shutdown_power_off(). */
void
halt (void)
{
  shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel */
void
exit (int status)
{
  
}

/* Runs the executable whose name is given in cmd_line, passing any given
   arguments, and returns the new process’s program id (pid). Must return
   pid -1, if the program cannot load or run for any reason. */
pid_t
exec (const char *cmd_line)
{

}

/* Waits for a process which has the same Program ID as pid, and returns the
   target process’s exit status. If the target process did not call exit(),
   but was terminated by the kernel (e.g. killed due to an exception), wait
   must return -1.  */
int
wait (pid_t pid)
{

}

/* Creates a new file called file initially initial_size bytes in size. Returns
   true if successful, false otherwise. */
bool
create (const char *file, unsigned initial_size)
{

}

/* Deletes the file called file. Returns true if successful, false otherwise. */
bool
remove (const char *file)
{

}

/* Opens the file called file. Returns a nonnegative integer handle called a
   “file descriptor” (fd), or -1 if the file could not be opened. */
int
open (const char *file)
{

}

/* : Returns the size, in bytes, of the file open as fd. */
int
filesize (int fd)
{

}

/* Reads size bytes from the file open as fd into buffer. Returns the number
   of bytes actually read (0 at end of file), or -1 if the file could not be
   read (due to a condition other than end of file). fd 0 reads from the
   keyboard using input_getc(). */
int
read (int fd, void *buffer, unsigned size)
{

}

/* Writes size bytes from buffer to the open file fd. Returns the number of
   bytes actually written. The expected behavior is to write as many bytes
   as possible up to end-of-file and return the actual number written (0 at
   end of file). fd 1 writes to the console using putbuf(). */
int
write (int fd, const void *buffer, unsigned size)
{

}

/* Changes the next byte to be read or written in open file fd to position,
   expressed in bytes from the beginning of the file. (Thus, a position of 0
   is the file’s start.) */
void
seek (int fd, unsigned position)
{

}

/* Returns the position of the next byte to be read or written in open file
   fd, expressed in bytes from the beginning of the file. */
unsigned
tell (int fd)
{

}

/* Closes file descriptor fd. Exiting or terminating a process implicitly
   closes all its open file descriptors, as if by calling this function for
  each one. */
void
close (int fd)
{

}
