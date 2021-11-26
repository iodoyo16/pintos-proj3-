#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <string.h>

static void syscall_handler (struct intr_frame *);

struct lock filesync_lock;
void
syscall_init (void) 
{
  lock_init(&filesync_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void halt(void){
  shutdown_power_off();
}

void exit(int status){
  struct thread* t=thread_current();
  int i=3;
  t->exit_status=status;
  printf("%s: exit(%d)\n",thread_name(),status);
  while (i<FD_MAX){
    if((t->fd_arr[i])!=NULL){
      close(i);
    }
    i++;
  }
  thread_exit();
}

pid_t exec(const char *cmd_line){
  return process_execute(cmd_line);
}

int wait(pid_t pid){
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
  // create does not do open
  // base filesys does not change file size
  if(file==NULL||!is_user_vaddr(file))
    exit(-1);
  return filesys_create(file,initial_size);
}

bool remove (const char *file){
  if(file==NULL||!is_user_vaddr(file))
    exit(-1);
  return filesys_remove(file);
}

int open (const char *file){
  int ret=-1;
  if(file==NULL||!is_user_vaddr(file))
    exit(-1);
  lock_acquire(&filesync_lock);
  struct file* fp=filesys_open(file);
  struct thread* cur_t=thread_current();
  if(fp==NULL){
    ret= -1;
  }
  else{
    if(!strcmp(thread_name(),file)){
      file_deny_write(fp);
    }
    for(int i=3;i<FD_MAX;i++){
        if(cur_t->fd_arr[i]==NULL){
          cur_t->fd_arr[i]=fp;
          ret= i;
          break;
        }
    }
  }
  lock_release(&filesync_lock);
  return ret;
}

int filesize (int fd){
  struct file* fp=thread_current()->fd_arr[fd];
  if(fp==NULL){
    exit(-1);
  }
  return file_length(fp);
}

int read(int fd, void* buffer, unsigned size){
  unsigned i=0;
  int ret=0;
  if(!is_user_vaddr(buffer)){
    exit(-1);
  }
  lock_acquire(&filesync_lock);
  if(fd==0){
    for(i=0;i<size;i++){
      if(((char*)buffer)[i]=='\0'){
        lock_release(&filesync_lock);
        return i;
      }
    }
  }
  else{
    struct file* fp=thread_current()->fd_arr[fd];
    if(fp==NULL){
      lock_release(&filesync_lock);
      exit(-1);
    }
    ret=file_read(fp,buffer,size);
  }
  lock_release(&filesync_lock);
  return ret;
}

int write(int fd, const void *buffer, unsigned size){
  if(!is_user_vaddr(buffer)){
    exit(-1);
  }
  lock_acquire(&filesync_lock);
  int ret;
  if(fd<0){
    ret= -1;
  }
  else if(fd==1){
    putbuf(buffer, size);
    ret=size;
  }
  else{
    struct file* fp=thread_current()->fd_arr[fd];
    if(fp==NULL){
      lock_release(&filesync_lock);
      exit(-1);
    }
    ret=file_write(fp,buffer,size);
  }
  lock_release(&filesync_lock);
  return ret;
}

void seek(int fd,unsigned position){
  struct file* fp=thread_current()->fd_arr[fd];
  if(fp==NULL){
      exit(-1);
    }
  file_seek(fp,position);
}
unsigned tell(int fd){
  struct file* fp=thread_current()->fd_arr[fd];
  if(fp==NULL){
      exit(-1);
  }
  return file_tell(fp);
}
void close(int fd){
  struct thread* t=thread_current();
  struct file* fp=t->fd_arr[fd];
  if(fp==NULL){
      exit(-1);
  }
  t->fd_arr[fd]=NULL;
  file_close(fp);
}
int fibonacci(int n){
  int i;
  int tmp1=0,tmp2=1,ret;
  switch(n){
    case 0:
      return 0;
    case 1:
      return 1;
    default:
      for(i=2;i<=n;i++){
        ret=tmp1+tmp2;
        tmp1=tmp2;
        tmp2=ret;
      }
      return ret;
  }
}
int max_of_four_int(int a, int b, int c, int d){
  int tmp1,tmp2;
  tmp1=a>b? a:b;
  tmp2=c>d? c:d;
  return tmp1>tmp2?tmp1:tmp2;
}
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf("esp: %x\n",(uint32_t *)(f->esp));
  //printf("syscall num : %d\n",*(uint32_t *)(f->esp));
  //hex_dump(f->esp,f->esp,100,1);
  switch(*(uint32_t *)(f->esp)){
    case SYS_HALT:                   /* Halt the operating system. */
      halt();
    break;
    case SYS_EXIT:                   /* Terminate this process. */
      // void exit (int status)
      if(!is_user_vaddr(f->esp+4)){
        exit(-1);
      }
      exit(*(int32_t *)(f->esp + 4));
    break;
    case SYS_EXEC:                   /* Start another process. */
      // pit_d exec(const char *cmd_line);
      if(!is_user_vaddr(f->esp+4)){
        exit(-1);
      }
      f->eax=exec(*(const char**)(f->esp +4));
    break;
    case SYS_WAIT:                   /* Wait for a child process to die. */
      // int wait(pit_d pid);
      if(!is_user_vaddr(f->esp+4)){
        exit(-1);
      }
      f->eax=wait(*(pid_t*)(f->esp + 4));
    break;
    case SYS_CREATE:                 /* Create a file. */
    // bool create(const char *file, unsigned initial_size);
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)){
        exit(-1);
      }
      f->eax=create(*(const char**)(f->esp+4),*(unsigned*)(f->esp+8));
    break;
    case SYS_REMOVE:                 /* Delete a file. */
    // bool remove (const char *file);
      if(!is_user_vaddr(f->esp+4)){
        exit(-1);
      }
      f->eax=remove(*(const char**)(f->esp+4));
    break;
    case SYS_OPEN:                   /* Open a file. */
    // int open (const char *file);
      if(!is_user_vaddr(f->esp+4)){
        exit(-1);
      }
      f->eax=open(*(const char**)(f->esp+4));
    break;
    case SYS_FILESIZE:               /* Obtain a file's size. */
    // int filesize (int fd);
      if(!is_user_vaddr(f->esp+4)){
        exit(-1);
      }
      f->eax=filesize(*(int*)(f->esp+4));
    break;
    case SYS_READ:                   /* Read from a file. */
    // int read(int fd, void *buffer, unsigned size);
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)||!is_user_vaddr(f->esp+12)){
        exit(-1);
      }
      f->eax=read(*(int *)(f->esp + 4), (void *)*(uint32_t *)(f->esp +8), *(unsigned *)(f->esp+12));
    break;
    case SYS_WRITE:                  /* Write to a file. */
    // int write (int fd, const void *buffer, unsigned size);
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)||!is_user_vaddr(f->esp+12)){
          exit(-1);
      }
      f->eax=write(*(int *)(f->esp + 4), (void *)*(uint32_t *)(f->esp +8), *(unsigned *)(f->esp+12));
    break;
    case SYS_SEEK:                   /* Change position in a file. */
    // void seek(int fd,unsigned position);
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)){
        exit(-1);
      }
      seek(*(int*)(f->esp+4),*(unsigned*)(f->esp+8));
    break;
    case SYS_TELL:                   /* Report current position in a file. */
    // unsigned tell(int fd);
    if(!is_user_vaddr(f->esp+4)){
        exit(-1);
      }
      f->eax=tell(*(int*)(f->esp+4));
    break;
    case SYS_CLOSE:                  /* Close a file. */
    // void close(int fd);
      if(!is_user_vaddr(f->esp+4)){
        exit(-1);
      }
      filesize(*(int*)(f->esp+4));
    break;
    case SYS_FIBO:
      if(!is_user_vaddr(f->esp+4)){
        exit(-1);
      }
      f->eax=fibonacci(*(int *)(f->esp + 4));
    break;
    case SYS_MAXFOUR:
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)||!is_user_vaddr(f->esp+12)||!is_user_vaddr(f->esp+16)){
          exit(-1);
      }
      f->eax=max_of_four_int(*(int *)(f->esp +4),*(int *)(f->esp +8),*(int *)(f->esp +12),*(int *)(f->esp +16));
    break;
  }
  //printf ("system call!\n");
}

