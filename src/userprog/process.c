#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

#ifndef VM
#define vm_frame_allocate(x, y) palloc_get_page(x)
#define vm_frame_free(x) palloc_free_page(x)
#endif

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

pid_t
process_execute (const char *file_name) 
{
  char *fn_copy = NULL;
  char *cmd_copy = NULL;
  struct process_control_block *pcb = NULL;
  tid_t tid;
  char *save_ptr = NULL;

  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    goto failed;
  strlcpy (fn_copy, file_name, PGSIZE);
  
  cmd_copy = palloc_get_page(0);
  if(cmd_copy == NULL)
    goto failed;
  strlcpy(cmd_copy,file_name,PGSIZE);
  cmd_copy = strtok_r(cmd_copy," ",&save_ptr);

  for(int i=0;i<strlen(cmd_copy);i++){
    if(cmd_copy[i]==' ')
      cmd_copy[i]='\0';
  }
  if(filesys_open(cmd_copy)==NULL)
    return -1;
  
  pcb = palloc_get_page(0);
  if(pcb == NULL)
    goto failed;
  pcb -> pid = PID_INIT;
  pcb -> parent_thread = thread_current();
  pcb -> cmdline = fn_copy;
  pcb -> waiting = false;
  pcb -> exited = false;
  pcb -> orphan = false;
  pcb -> exitcode = -1;

  
  sema_init(&pcb->sema_init,0);
  sema_init(&pcb->sema_wait,0);

  
  tid = thread_create (cmd_copy, PRI_DEFAULT, start_process, pcb);
  if (tid == TID_ERROR)
    goto failed;
  
  sema_down(&pcb->sema_init);

  if(cmd_copy){
    palloc_free_page(cmd_copy);
  }
  
  if(pcb->pid>=0){
    list_push_back(&(thread_current()->child_list),&(pcb->elem));
  }
  
  return pcb->pid;

failed:
  if(cmd_copy)
    palloc_free_page(cmd_copy);
  if(fn_copy)
    palloc_free_page(fn_copy);
  if(pcb){
    palloc_free_page(pcb->cmdline);
    palloc_free_page(pcb);
  }

  return PID_ERROR;
}



static void
start_process (void *pcb_)
{
  struct thread *t = thread_current();
  struct process_control_block *pcb = pcb_;

  char *file_name = (char*) pcb->cmdline;
  bool success = false;

  
  const char **parsed_filename_argv = (const char**) palloc_get_page(0);

  if (parsed_filename_argv == NULL) {
    printf("Not enough memory\n");
    
    goto finish; 
  }
  int argc=0;
  argc=parse_file_name(file_name,parsed_filename_argv);
  

  
  struct intr_frame if_;
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  if (success) {
    push_userstack(parsed_filename_argv, argc,&if_.esp);
  }
  palloc_free_page (parsed_filename_argv);

finish:
  pcb->pid = success ? (pid_t)(t->tid) : PID_ERROR;
  t->pcb = pcb;
  sema_up(&pcb->sema_init);

  if (!success)
    sys_exit (-1);
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}


int parse_file_name(char *input, const char **parsed_filename_argv){
  char* tmp;
  char* check_ptr;
  int argc = 0;
  tmp = strtok_r(input, " ", &check_ptr);
  while(tmp != NULL){
    parsed_filename_argv[argc++] = tmp;
    tmp = strtok_r(NULL, " ", &check_ptr);
  }
  return argc;
}
void push_userstack(const char** parsed_filename_argv, int argc,void **esp){
  /* 1. argv[3][...]~[0][...] 
   file name is also counted as argc*/
  int total_size=0;
  for(int i=argc-1;i>=0;i--){
    int size=strlen(parsed_filename_argv[i])+1;   // ex) size(bar\0 )= 4
    *esp-=size;
    total_size+=size;
    strlcpy(*esp, parsed_filename_argv[i],size);
    parsed_filename_argv[i]=*esp;                 // address updated
  }
  // 2. word-align
  while(total_size%WORD_SIZE!=0){
    total_size++;
    (*esp)--;  
  }
  /* 3. null + 4. argv[4]~[0]
  */
  for(int i=argc;i>=0;i--){
    *esp-=WORD_SIZE;
    **(uint32_t **)esp=parsed_filename_argv[i];
  }
  // argv ,argc, return address
  *esp-=WORD_SIZE;
  **(uint32_t **)esp=*esp+WORD_SIZE;
  *esp-=WORD_SIZE;
  **(uint32_t **)esp=argc;
  *esp-=WORD_SIZE;
  **(uint32_t **)esp=0;
}
int
process_wait (tid_t child_tid)
{
  struct process_control_block *child_pcb = find_child_process(child_tid);
  if (child_pcb == NULL) {
    return -1;
  }

  if (child_pcb->waiting) {
    return -1; 
  }
  else {
    child_pcb->waiting = true;
  }

  if (! child_pcb->exited) {
    sema_down(& (child_pcb->sema_wait));
  }
  ASSERT (child_pcb->exited == true);

  ASSERT (child_pcb != NULL);
  list_remove (&(child_pcb->elem));

  int ret = child_pcb->exitcode;

  palloc_free_page(child_pcb);

  return ret;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *page_dir;

  struct list *fdlist = &cur->file_descriptors;
  while (!list_empty(fdlist)) {
    struct list_elem *cur_e = list_pop_front (fdlist);
    struct fd_struct *fd_ptr = list_entry(cur_e, struct fd_struct, elem);
    file_close(fd_ptr->file);
    palloc_free_page(fd_ptr); 
  }

  struct list *pcb_list  = &cur -> child_list;
  while(!list_empty(pcb_list)){
    struct list_elem *cur_e = list_pop_front(pcb_list);
    struct process_control_block *cur_pcb;
    cur_pcb = list_entry(cur_e, struct process_control_block,elem);
    if(!cur_pcb->exited){
      cur_pcb->orphan = true;
      cur_pcb->parent_thread = NULL;
    }
    else{
      palloc_free_page(cur_pcb->cmdline);
      palloc_free_page(cur_pcb);
    }
  }

#ifdef VM
  // descriptors erase
  struct list *mmlist = &cur->mmap_list;
  while (!list_empty(mmlist)) {
    struct list_elem *cur_e = list_begin (mmlist);
    struct mmap_desc *desc = list_entry(cur_e, struct mmap_desc, elem);
    sys_munmap (desc->id);
  }
#endif
  cur->pcb->exited = true;
  bool cur_orphan = cur->pcb->orphan;
  sema_up (&cur->pcb->sema_wait);
  if (cur_orphan) {
    palloc_free_page (& cur->pcb);
  }

#ifdef VM
  vm_page_table_destroy (cur->supt);
  cur->supt = NULL;
#endif

  page_dir = cur->pagedir;
  if (page_dir != NULL)
    {
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (page_dir);
    }
}

void
process_activate (void)
{
  struct thread *t = thread_current ();

  pagedir_activate (t->pagedir);

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

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory, as well as SPTE. */
  t->pagedir = pagedir_create ();
#ifdef VM
  t->supt = vm_pt_create ();
#endif

  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
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
                
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
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
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  /* Deny writes to executables. */
  thread_current()->executing_file = file;
  file_deny_write (file);

  success = true;

 done:
  return success;
}

/* load() helpers. */

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
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

#ifdef VM
      // demand paging(lazy load) 구현
      struct thread *curr = thread_current ();
      ASSERT (pagedir_get_page(curr->pagedir, upage) == NULL);

      if (! vm_pt_install_filesys(curr->supt, upage,
            file, ofs, page_read_bytes, page_zero_bytes, writable) ) {
        return false;
      }
#else
      uint8_t *kpage = vm_frame_allocate (PAL_USER, upage);
      if (kpage == NULL)
        return false;
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          vm_frame_free (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);
      if (!install_page (upage, kpage, writable))
        {
          vm_frame_free (kpage);
          return false;
        }
#endif

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
#ifdef VM
      ofs += PGSIZE;
#endif
    }
  return true;
}


/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  // upage address is the first segment of stack.
  kpage = vm_frame_allocate (PAL_USER | PAL_ZERO, PHYS_BASE - PGSIZE);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        vm_frame_free (kpage);
    }
  return success;
}

static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool get_success = (pagedir_get_page (t->pagedir, upage) == NULL);
  bool success = get_success && pagedir_set_page (t->pagedir, upage, kpage, writable);
#ifdef VM
  success = success && vm_pt_install_frame (t->supt, upage, kpage);
  if(success) vm_frame_unpin(kpage);
#endif
  return success;
}

struct process_control_block *find_child_process(pid_t child_tid){
  struct thread *t = thread_current();
  struct list *chld_lst = &(t->child_list);

  struct list_elem *cur_e = NULL;
  if(!list_empty(chld_lst)){
    for(cur_e = list_begin(chld_lst);cur_e != list_end(chld_lst);cur_e = list_next(cur_e)){
      struct process_control_block * child_pcb = list_entry(cur_e,struct process_control_block,elem);
      if(child_pcb -> pid == child_tid){
        return child_pcb;
      }
    }
  }
  return NULL;
}