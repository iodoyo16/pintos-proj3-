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

struct lock filesys_lock;

void check_user(const uint8_t *addr);
static int get_user(const uint8_t *addr);
//static bool put_user(uint8_t *udst,uint8_t byte);
static int read_user(void *src, void *dst, size_t bytes);
static void syscall_handler (struct intr_frame *);
static struct file_desc* find_file_desc(struct thread *t,int fd);
static void is_invalid(void);

#ifdef VM
mmapid_t sys_mmap(int fd, void *);
bool sys_munmap(mmapid_t);
static struct mmap_desc* find_mmap_desc(struct thread *, mmapid_t fd);
#endif
void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

///////////////////////////////////////
////////////Implementation/////////////
///////////////////////////////////////

void sys_halt(void){
  shutdown_power_off();
}

void sys_exit(int status){
  struct thread *t=thread_current();

  printf("%s: exit(%d)\n",thread_name(),status);

  struct process_control_block *pcb = t -> pcb;
  if(pcb != NULL)
    pcb -> exitcode = status;
  thread_exit();
}

pid_t sys_exec(const char *cmd_line){
  //1. Check the validity
  //check_user((const uint8_t *)cmd_line);
  if(!is_user_vaddr(cmd_line)){
    sys_exit(-1);
  }
  //printf("Exec : %s\n",cmd_line);
  //2. Create a new process
  lock_acquire(&filesys_lock);
  pid_t pid = process_execute(cmd_line);
  lock_release(&filesys_lock);
  return  pid;
}
int sys_wait(pid_t pid){
  //printf("Wait : %d\n",pid);
  return process_wait(pid);
}


bool sys_create(const char *file_name, unsigned initial_size){
  if(file_name == NULL)
    sys_exit(-1);
  check_user((const uint8_t*)file_name);
  if(file_name==NULL)
    sys_exit(-1);
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file_name,initial_size);
  lock_release(&filesys_lock);
  return success;
}

bool sys_remove(const char *file_name){
  if(file_name == NULL)
    sys_exit(-1);
  check_user((const uint8_t*)file_name);
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file_name);
  lock_release(&filesys_lock);
  return success;
}

int sys_open(const char *file_name){
  struct file_desc* fd;
  struct file *openfile;
  if(file_name==NULL||!is_user_vaddr(file_name))
    sys_exit(-1);  
  check_user((const uint8_t*)file_name);
  fd = palloc_get_page(0);
  if(!fd) 
    return -1;

  lock_acquire(&filesys_lock);
  openfile = filesys_open(file_name);
  if(openfile != NULL){
    if(strcmp(thread_name(),file_name) == 0){
      file_deny_write(openfile);
    }

    //save the file to the file descriptor
    fd->file = openfile;
    //no directory
    //fd_list
    struct list* fd_list = &thread_current()->file_descriptors;
    if(list_empty(fd_list)){
      fd->id = 3;
    }
    else{
      fd->id = (list_entry(list_back(fd_list),struct file_desc,elem)->id) + 1;
    }
    list_push_back(fd_list,&(fd->elem));
    lock_release(&filesys_lock);
    return fd->id;
  }
  palloc_free_page(fd);
  lock_release(&filesys_lock);
  return -1;
}

int sys_filesize(int fd){
  struct file_desc* desc;
  lock_acquire(&filesys_lock);
  desc = find_file_desc(thread_current(),fd);

  if(desc == NULL){
    lock_release(&filesys_lock);
    return -1;
  }
  int ret_val = file_length(desc->file);
  lock_release(&filesys_lock);
  return ret_val;
}

int sys_read(int fd, void *buffer, unsigned size){
  check_user((const uint8_t *)buffer);
  check_user((const uint8_t *)buffer + size -1);

  lock_acquire(&filesys_lock);
  int ret_val;

  if(fd == 0){
    unsigned i;
    for(i = 0;i<size;i++){//STDIN
      if(!input_getc()){
        sys_exit(-1);
      }
    }
    ret_val = size;
  }

  else{
    struct file_desc* desc = find_file_desc(thread_current(),fd);
    if(desc==NULL){
      lock_release(&filesys_lock);
      sys_exit(-1);
    }
    if(desc && desc->file){
#ifdef VM
      preload_and_pin_pages(buffer, size);
#endif
      ret_val = file_read(desc->file,buffer,size);
#ifdef VM
      unpin_preloaded_pages(buffer, size);
#endif
    }
    else
      ret_val = -1;
  }
  lock_release(&filesys_lock);
  return ret_val;
}

int sys_write(int fd, const void *buffer,unsigned size){
  //printf("%d\n",size);
  int ret_val;
  check_user((const uint8_t*)buffer);
  check_user((const uint8_t*)buffer + size -1);

  lock_acquire(&filesys_lock);
  if(fd == 1){
    putbuf(buffer,size);
    ret_val = size;
  }
  else {
    struct file_desc *desc = find_file_desc(thread_current(),fd);
    if(desc==NULL){
      lock_release(&filesys_lock);
      sys_exit(-1);
    }
    if(desc && desc->file){
#ifdef VM
      preload_and_pin_pages(buffer, size);
#endif
      ret_val = file_write(desc->file,buffer,size);
#ifdef VM
      unpin_preloaded_pages(buffer, size);
#endif
    }
    else{
      ret_val = -1;
    }
  }
  lock_release(&filesys_lock);
  return ret_val;
}

void sys_seek(int fd, unsigned position){
  lock_acquire(&filesys_lock);
  struct file_desc* desc = find_file_desc(thread_current(),fd);
  if(desc && desc->file){
    file_seek(desc->file,position);
  }
  else
    return;
  lock_release(&filesys_lock);
}

unsigned sys_tell(int fd){
  lock_acquire(&filesys_lock);
  struct file_desc* desc = find_file_desc(thread_current(),fd);
  unsigned ret;
  if(desc && desc->file){
    ret = file_tell(desc->file);
  }
  else
    ret = -1;
  lock_release(&filesys_lock);
  return ret;
}

void sys_close(int fd){
  lock_acquire(&filesys_lock);
  struct file_desc *desc = find_file_desc(thread_current(),fd);
  if(desc && desc->file){
    file_close(desc->file);
    list_remove(&(desc->elem));
    palloc_free_page(desc);
  }
  lock_release(&filesys_lock);
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
#ifdef VM
mmapid_t sys_mmap(int fd, void *upage) {
  struct file *f = NULL;
  if (upage == NULL || pg_ofs(upage) != 0) 
    return -1;
  if (fd <= 1) 
    return -1; 
  struct thread *cur = thread_current();

  lock_acquire (&filesys_lock);

  /* 1. Open file */
  struct file_desc* desc = find_file_desc(thread_current(), fd);
  if(desc && desc->file) {
    // reopen file so that it doesn't interfere with process itself
    // it will be store in the mmap_desc struct (later closed on munmap)
    f = file_reopen (desc->file);
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

  lock_release (&filesys_lock);
  return mid;

MMAP_FAIL:
  lock_release (&filesys_lock);
  return -1;
}

bool sys_munmap(mmapid_t mid)
{
  struct thread *curr = thread_current();
  struct mmap_desc *mmap_d = find_mmap_desc(curr, mid);

  if(mmap_d == NULL) { // not found such mid
    return false; // or fail_invalid_access() ?
  }

  lock_acquire (&filesys_lock);
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
  lock_release (&filesys_lock);

  return true;
}
#endif

///////////////////////////////////////
/////////////Memory Access/////////////
///////////////////////////////////////



static struct file_desc* find_file_desc(struct thread *t,int fd){
  ASSERT(t!=NULL);
  if(fd < 3){
    return NULL;
  }

  struct list_elem *e;
  if(!list_empty(&t->file_descriptors)){
    for(e = list_begin(&t->file_descriptors);e !=list_end(&t->file_descriptors);e = list_next(e)){
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc -> id == fd){
        return desc;
      }
    }
  }
  return NULL;
}

static void is_invalid(void){
  if(lock_held_by_current_thread(&filesys_lock))
    lock_release(&filesys_lock);
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

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_number;
  read_user(f->esp,&syscall_number,sizeof(syscall_number));
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
    case SYS_EXEC:                   /* Start another process. */
      // pit_d exec(const char *cmd_line);
    {
      void *cmd_line;
      read_user(f->esp+4,&cmd_line,sizeof(cmd_line));
      int return_code = sys_exec((const char*)cmd_line);
      f->eax = (uint32_t) return_code;
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
      // int fd;
      // void *addr;
      // read_user(f->esp + 4, &fd, sizeof(fd));
      // read_user(f->esp + 8, &addr, sizeof(addr));
      if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)){
        sys_exit(-1);
      }
      mmapid_t ret_val = sys_mmap (*(int *)(f->esp+4), (void *)*(uint32_t *)(f->esp+8));
      f->eax = ret_val;
      break;
    }
    break;

  case SYS_MUNMAP:// 14
  {
      mmapid_t mid;
      if(!is_user_vaddr(f->esp+4)){
        sys_exit(-1);
      }
      sys_munmap(*(mmapid_t *)(f->esp+4));
      break;
  }
  break;
#endif
  }
}


void check_user(const uint8_t *addr){
  if(get_user(addr) == -1){
    is_invalid();
  }
  // if(!is_user_vaddr((void*)addr)){
  //   return -1;
  // }
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