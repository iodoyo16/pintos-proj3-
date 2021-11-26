#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#define INPUT_ARG_MAX 128
#define WORD_SIZE 4
#include <stdio.h>
#include "threads/thread.h"
#include "threads/synch.h"

/* Process identifier type.
   You can redefine this to whatever type you like. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)          /* Error value for tid_t. */
#define PID_INIT ((pid_t) -2)

struct process_control_block {
    pid_t pid;

    const char *cmdline;

    struct list_elem elem;
    struct thread *parent_thread;

    bool waiting;   //indicates whether parent process is waiting.
    bool exited;    //indicates whether the process is done.
    bool orphan;    //indicates whether the parent process has terminated before.
    int32_t exitcode;   //the exit code passed from exit(), when exited = true

    //Synchronization
    struct semaphore sema_init; //the semaphore used between start_process() and process_execute()
    struct semaphore sema_wait; //the semaphore used for wait()
};

//File descriptor
struct fd_struct {
    int id;
    struct list_elem elem;
    struct file* file;
};

#ifdef VM
typedef int mmapid_t;

struct mmap_desc {
  mmapid_t id;
  struct list_elem elem;
  struct file* file;

  void *addr;   // where it is mapped to? store the user virtual address
  size_t size;  // file size
};
#endif

pid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
/* Project 3 */
struct process_control_block *process_find_child(pid_t pid);
int parse_file_name(char *input, const char **parsed_filename_argv);
#endif /* userprog/process.h */
