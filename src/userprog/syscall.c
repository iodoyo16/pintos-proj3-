#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

struct lock file_system_lock;

void check_user(const uint8_t *addr);
static int get_user(const uint8_t *addr);
//static bool put_user(uint8_t *udst,uint8_t byte);
static int read_user(void *src, void *dst, size_t bytes);
static void syscall_handler (struct intr_frame *);
static struct fd_struct* find_file_desc(struct thread *t,int fd);
static void is_invalid(void);

#ifdef VM
static struct mmap_desc* find_mmap_desc(struct thread *, mmapid_t fd);
#endif

void
syscall_init (void) 
{
  lock_init(&file_system_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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

void sys_halt(void){
  shutdown_power_off();
}

void sys_exit(int status){
  struct thread *t =thread_current();
  printf("%s: exit(%d)\n",thread_name(),status);

  struct process_control_block *proc_ctrl_blk = t -> pcb;
  if(proc_ctrl_blk != NULL)
    proc_ctrl_blk -> exitcode = status;
  thread_exit();
}

pid_t sys_exec(const char *cmd_line){
  check_user((const uint8_t *)cmd_line);
  lock_acquire(&file_system_lock);
  pid_t pid = process_execute(cmd_line);
  lock_release(&file_system_lock);
  return  pid;
}
int sys_wait(pid_t pid){
  return process_wait(pid);
}

bool sys_create(const char *file_name, unsigned initial_size){
  if(file_name==NULL||!is_user_vaddr(file_name))
    sys_exit(-1);
  check_user((const uint8_t*)file_name);
  lock_acquire(&file_system_lock);
  bool success = filesys_create(file_name,initial_size);
  lock_release(&file_system_lock);
  return success;
}

bool sys_remove(const char *file_name){
  if(file_name==NULL||!is_user_vaddr(file_name))
    sys_exit(-1);
  check_user((const uint8_t*)file_name);
  lock_acquire(&file_system_lock);
  bool success = filesys_remove(file_name);
  lock_release(&file_system_lock);
  return success;
}

int sys_open(const char *file_name){
  struct fd_struct* fd;
  struct file *openfile;
  if(file_name==NULL||!is_user_vaddr(file_name))
    sys_exit(-1);  
  check_user((const uint8_t*)file_name);
  fd = palloc_get_page(0);
  if(!fd) 
    return -1;

  lock_acquire(&file_system_lock);
  openfile = filesys_open(file_name);
  if(openfile != NULL){
    if(strcmp(thread_name(),file_name) == 0){
    file_deny_write(openfile);
    }
    fd->file = openfile;
    struct list* fd_list = &thread_current()->file_descriptors;
    if(list_empty(fd_list)){
      fd->id = 3;
    }
    else{
      fd->id = (list_entry(list_back(fd_list),struct fd_struct,elem)->id) + 1;
    }
    list_push_back(fd_list,&(fd->elem));
    lock_release(&file_system_lock);
    return fd->id;
  }
  palloc_free_page(fd);
  lock_release(&file_system_lock);
  return -1;
}

int sys_filesize(int fd){
  struct fd_struct* fd_ptr;
  lock_acquire(&file_system_lock);
  fd_ptr = find_file_desc(thread_current(),fd);

  if(fd_ptr == NULL){
    lock_release(&file_system_lock);
    return -1;
  }
  int ret_value = file_length(fd_ptr->file);
  lock_release(&file_system_lock);
  return ret_value;
}

int sys_read(int fd, void *buffer, unsigned size){
  check_user((const uint8_t *)buffer);
  check_user((const uint8_t *)buffer + size -1);

  lock_acquire(&file_system_lock);
  int ret_value;

  if(fd == 0){
    unsigned i;
    for(i = 0;i<size;i++){//STDIN
      if(!input_getc()){
        sys_exit(-1);
      }
    }
    ret_value = size;
  }

  else{
    struct fd_struct* fd_ptr = find_file_desc(thread_current(),fd);
    if(fd_ptr==NULL){
      lock_release(&file_system_lock);
      sys_exit(-1);
    }
    if(fd && fd_ptr->file){
#ifdef VM
      preload_and_pin_pages(buffer, size);
#endif
      ret_value = file_read(fd_ptr->file,buffer,size);
#ifdef VM
      unpin_preloaded_pages(buffer, size);
#endif
    }
    else{
      ret_value = -1;
    }
  }
  lock_release(&file_system_lock);
  return ret_value;
}

int sys_write(int fd, const void *buffer,unsigned size){
  //printf("%d\n",size);
  int ret_value;
  check_user((const uint8_t*)buffer);
  check_user((const uint8_t*)buffer + size -1);

  lock_acquire(&file_system_lock);
  if(fd == 1){
    putbuf(buffer,size);
    ret_value = size;
  }
  else {
    struct fd_struct *fd_ptr = find_file_desc(thread_current(),fd);
    if(fd_ptr==NULL){
      lock_release(&file_system_lock);
      sys_exit(-1);
    }
    if(fd_ptr && fd_ptr->file){
#ifdef VM
      preload_and_pin_pages(buffer, size);
#endif
      ret_value = file_write(fd_ptr->file,buffer,size);
#ifdef VM
      unpin_preloaded_pages(buffer, size);
#endif
    }
    else{
      ret_value = -1;
    }
  }
  lock_release(&file_system_lock);
  return ret_value;
}

void sys_seek(int fd, unsigned position){
  lock_acquire(&file_system_lock);
  struct fd_struct* fd_ptr = find_file_desc(thread_current(),fd);
  if(fd_ptr && fd_ptr->file){
    file_seek(fd_ptr->file,position);
  }
  else
    return;
  lock_release(&file_system_lock);
}

unsigned sys_tell(int fd){
  lock_acquire(&file_system_lock);
  struct fd_struct* fd_ptr = find_file_desc(thread_current(),fd);
  unsigned ret;
  if(fd_ptr && fd_ptr->file){
    ret = file_tell(fd_ptr->file);
  }
  else
    ret = -1;
  lock_release(&file_system_lock);
  return ret;
}

void sys_close(int fd){
  lock_acquire(&file_system_lock);
  struct fd_struct *fd_ptr = find_file_desc(thread_current(),fd);
  if(fd_ptr && fd_ptr->file){
    file_close(fd_ptr->file);
    list_remove(&(fd_ptr->elem));
    palloc_free_page(fd_ptr);
  }
  lock_release(&file_system_lock);
}

#ifdef VM
mmapid_t sys_mmap(int fd, void *upage) {
  struct file *f = NULL;
  if (upage == NULL || pg_ofs(upage) != 0) 
    return -1;
  if (fd <= 1) 
    return -1; 
  struct thread *cur = thread_current();

  lock_acquire (&file_system_lock);

  /* 1. Open file */
  struct fd_struct* fd_ptr = find_file_desc(thread_current(), fd);
  if(fd_ptr && fd_ptr->file) {
    // reopen file so that it doesn't interfere with process itself
    // it will be store in the mmap_desc struct (later closed on munmap)
    f = file_reopen (fd_ptr->file);
  }
  if(f == NULL) 
    goto MMAP_FAIL;

  size_t file_size = file_length(f);
  if(file_size == 0) 
    goto MMAP_FAIL;

  /* 2. Mapping memory pages
   First, ensure that all the page address is NON-EXIESENT. */
  size_t offset;
  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;
    if (vm_supt_has_entry(cur->supt, addr)) goto MMAP_FAIL;
  }

  /* Now, map each page to filesystem */
  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;

    size_t read_bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
    size_t zero_bytes = PGSIZE - read_bytes;

    vm_supt_install_filesys(cur->supt, addr,
        f, offset, read_bytes, zero_bytes, true);
  }

  /* 3. Assign mmapid */
  mmapid_t mid;
  if (! list_empty(&cur->mmap_list)) {
    mid = list_entry(list_back(&cur->mmap_list), struct mmap_desc, elem)->id + 1;
  }
  else mid = 1;

  struct mmap_desc *mmap_d = (struct mmap_desc*) malloc(sizeof(struct mmap_desc));
  mmap_d->id = mid;
  mmap_d->file = f;
  mmap_d->addr = upage;
  mmap_d->size = file_size;

  list_push_back (&cur->mmap_list, &mmap_d->elem);

  lock_release (&file_system_lock);
  return mid;

MMAP_FAIL:
  lock_release (&file_system_lock);
  return -1;
}

void sys_munmap(mmapid_t mid)
{
  struct thread *curr = thread_current();
  struct mmap_desc *mmap_d = find_mmap_desc(curr, mid);

  if(mmap_d == NULL) { // not found such mid
    return ; // or fail_invalid_access() ?
  }

  lock_acquire (&file_system_lock);
  {
    // Iterate through each page
    size_t offset, file_size = mmap_d->size;
    for(offset = 0; offset < file_size; offset += PGSIZE) {
      void *addr = mmap_d->addr + offset;
      size_t bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
      vm_supt_mm_unmap (curr->supt, curr->pagedir, addr, mmap_d->file, offset, bytes);
    }

    // Free resources, and remove from the list
    list_remove(& mmap_d->elem);
    file_close(mmap_d->file);
    free(mmap_d);
  }
  lock_release (&file_system_lock);

  return ;
}
#endif
static void
syscall_handler (struct intr_frame *f) 
{
  //hex_dump(0xbfffffe0,f->esp,100,1);
  int syscall_number;
  read_user(f->esp,&syscall_number,sizeof(syscall_number));
  //ASSERT(sizeof(syscall_number == 4));
  //printf("system call number = %d\n",syscall_number);
  
  //Store the esp, which is needed in the page fault handler.
  thread_current()->current_esp = f->esp;
  
  switch(*(uint32_t *)(f->esp)){
   case SYS_HALT:                   /* Halt the operating system. */
      sys_halt();
    break;

  case SYS_EXIT:                   /* Terminate this process. */
      // void exit (int status)
      if(!is_user_vaddr(f->esp+4)){
        sys_exit(-1);
      }
      sys_exit(*(int32_t *)(f->esp + 4));
    break;

    case SYS_EXEC: //2
    {
      void *cmd;
      read_user(f->esp+4,&cmd,sizeof(cmd));
      int ret_value = sys_exec((const char*)cmd);
      f->eax = (uint32_t) ret_value;
      break;
    }

    case SYS_WAIT:                   /* Wait for a child process to die. */
      // int wait(pit_d pid);
      if(!is_user_vaddr(f->esp+4)){
        sys_exit(-1);
      }
      f->eax=sys_wait(*(pid_t*)(f->esp + 4));
    break;
  
    case SYS_CREATE:                 /* Create a file. */
    // bool create(const char *file, unsigned initial_size);
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)){
        sys_exit(-1);
      }
      f->eax=sys_create(*(const char**)(f->esp+4),*(unsigned*)(f->esp+8));
    break;

    case SYS_REMOVE:                 /* Delete a file. */
    // bool remove (const char *file);
      if(!is_user_vaddr(f->esp+4)){
        sys_exit(-1);
      }
      f->eax=sys_remove(*(const char**)(f->esp+4));
    break;

    case SYS_OPEN:                   /* Open a file. */
    // int open (const char *file);
      if(!is_user_vaddr(f->esp+4)){
        sys_exit(-1);
      }
      f->eax=sys_open(*(const char**)(f->esp+4));
    break;

    case SYS_FILESIZE:               /* Obtain a file's size. */
    // int filesize (int fd);
      if(!is_user_vaddr(f->esp+4)){
        sys_exit(-1);
      }
      f->eax=sys_filesize(*(int*)(f->esp+4));
    break;

    case SYS_READ:                   /* Read from a file. */
    // int read(int fd, void *buffer, unsigned size);
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)||!is_user_vaddr(f->esp+12)){
        sys_exit(-1);
      }
      f->eax=sys_read(*(int *)(f->esp + 4), (void *)*(uint32_t *)(f->esp +8), *(unsigned *)(f->esp+12));
    break;

    case SYS_WRITE:                  /* Write to a file. */
    // int write (int fd, const void *buffer, unsigned size);
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)||!is_user_vaddr(f->esp+12)){
          sys_exit(-1);
      }
      f->eax=sys_write(*(int *)(f->esp + 4), (void *)*(uint32_t *)(f->esp +8), *(unsigned *)(f->esp+12));
    break;

    case SYS_SEEK:                   /* Change position in a file. */
    // void seek(int fd,unsigned position);
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)){
        sys_exit(-1);
      }
      sys_seek(*(int*)(f->esp+4),*(unsigned*)(f->esp+8));
    break;

    case SYS_TELL:                   /* Report current position in a file. */
    // unsigned tell(int fd);
      if(!is_user_vaddr(f->esp+4)){
        sys_exit(-1);
      }
      f->eax=sys_tell(*(int*)(f->esp+4));
    break;

    case SYS_CLOSE:                  /* Close a file. */
    // void close(int fd);
      if(!is_user_vaddr(f->esp+4)){
        sys_exit(-1);
      }
      sys_close(*(int*)(f->esp+4));
    break;
    case SYS_FIBO:
      if(!is_user_vaddr(f->esp+4)){
        sys_exit(-1);
      }
      f->eax=fibonacci(*(int *)(f->esp + 4));
    break;
    case SYS_MAXFOUR:
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)||!is_user_vaddr(f->esp+12)||!is_user_vaddr(f->esp+16)){
          sys_exit(-1);
      }
      f->eax=max_of_four_int(*(int *)(f->esp +4),*(int *)(f->esp +8),*(int *)(f->esp +12),*(int *)(f->esp +16));
    break;
#ifdef VM
    case SYS_MMAP:// 13
    {
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)){
        sys_exit(-1);
      }
      mmapid_t ret_val = sys_mmap (*(int *)(f->esp+4), (void *)*(uint32_t *)(f->esp+8));
      f->eax = ret_val;
      break;
    }

  case SYS_MUNMAP:// 14
    {
      mmapid_t mid;
      if(!is_user_vaddr(f->esp+4)){
        sys_exit(-1);
      }
      sys_munmap(*(mmapid_t *)(f->esp+4));
      break;
    }
#endif
  }
}



/************Memory Check******/


void check_user(const uint8_t *addr){
  if(get_user(addr) == -1){
    is_invalid();
  }
}

static int get_user(const uint8_t *addr){//address must be below PHYS_BASE
  if(!is_user_vaddr((void*)addr)){
  //if(!((void*)uaddr < PHYS_BASE)){
    return -1;
  }
  //printf("address : %d\n",*addr);
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result): "m"(*addr));
  return result;
}

static int read_user(void *src, void *dst, size_t bytes){
  int32_t value;
  size_t i;
  for(i=0;i < bytes;i++){
    value = get_user(src + i);
    if(value == -1)//invalide memory access
      is_invalid();
    
    *(char*)(dst + i) = value & 0xff;
  }
  return (int)bytes;
}

static struct fd_struct* find_file_desc(struct thread *t,int fd){
  ASSERT(t!=NULL);
  if(fd < 3){
    return NULL;
  }

  struct list_elem *e;
  if(!list_empty(&t->file_descriptors)){
    for(e = list_begin(&t->file_descriptors);e !=list_end(&t->file_descriptors);e = list_next(e)){
      struct fd_struct *desc = list_entry(e, struct fd_struct, elem);
      if(desc -> id == fd){
        return desc;
      }
    }
  }
  return NULL;
}

static void is_invalid(void){
  if(lock_held_by_current_thread(&file_system_lock))
    lock_release(&file_system_lock);
  sys_exit(-1);
}

#ifdef VM
static struct mmap_desc* find_mmap_desc(struct thread *t, mmapid_t mid)
{
  ASSERT (t != NULL);

  struct list_elem *e;

  if (! list_empty(&t->mmap_list)) {
    for(e = list_begin(&t->mmap_list);
        e != list_end(&t->mmap_list); e = list_next(e))
    {
      struct mmap_desc *desc = list_entry(e, struct mmap_desc, elem);
      if(desc->id == mid) {
        return desc;
      }
    }
  }

  return NULL; // not found
}
#endif