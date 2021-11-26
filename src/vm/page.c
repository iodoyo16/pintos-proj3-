#include <hash.h>
#include <string.h>

#include "lib/kernel/hash.h"
#include "page.h"
#include "frame.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static unsigned supte_hash_func(const struct hash_elem *elem, void *aux);
static bool supte_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);
static void supte_destroy_func(struct hash_elem *elem, void *aux);
static bool vm_load_page_from_filesys(struct supplemental_page_table_entry *, void *);

//vm_supt 을 생성하는 함수
struct supplemental_page_table *vm_supt_create(void){
    struct supplemental_page_table *supt = 
    (struct supplemental_page_table *) malloc(sizeof(struct supplemental_page_table));
    struct hash* page_hash_table=&supt->page_map;
    hash_init(page_hash_table, supte_hash_func, supte_less_func, NULL);
    return supt;
}

//vm_supt 을 삭제하는 함수
void vm_supt_destroy(struct supplemental_page_table *supt){
    ASSERT(supt != NULL);
    struct hash* page_hash_table=&supt->page_map;
    hash_destroy(page_hash_table, supte_destroy_func);
    free(supt);
}

/*생성된 page의 주소(upage,kpage) 를 전달받고, 
page table entry를 생성해 초기화하고
page_hash_table에 insert한다.*/
bool vm_supt_install_frame(struct supplemental_page_table *supt, void *upage, void *kpage){
    struct supplemental_page_table_entry *page_hash_table_entry;
    page_hash_table_entry = (struct supplemental_page_table_entry *) malloc(sizeof(struct supplemental_page_table_entry));

    page_hash_table_entry -> upage = upage;
    page_hash_table_entry -> kpage = kpage;
    page_hash_table_entry -> dirty = false;
    page_hash_table_entry -> status = ON_FRAME;
    page_hash_table_entry -> swap_index = -1;

    struct hash* page_hash_table=&supt->page_map;
    struct hash_elem* pt_entry_elem=&page_hash_table_entry->elem;
    struct hash_elem *prev = hash_insert(page_hash_table, pt_entry_elem);
    if(prev != NULL){
        free(page_hash_table_entry);
        return false;
    }
    return true;
}

/*생성된 page의 주소(upage) 를 전달받고, 
page table entry를 생성해 초기화하고 (status 가 ALL_ZERO)
page_hash_table에 insert한다.*/
bool expand_stack (struct supplemental_page_table *supt, void *upage){
    struct supplemental_page_table_entry *page_hash_table_entry;
    page_hash_table_entry = (struct supplemental_page_table_entry *) malloc(sizeof(struct supplemental_page_table_entry));

    page_hash_table_entry -> upage = upage;
    page_hash_table_entry -> kpage = NULL;
    page_hash_table_entry -> dirty = false;
    page_hash_table_entry -> status = ALL_ZERO;

    struct hash* page_hash_table=&supt->page_map;
    struct hash_elem* pt_entry_elem=&page_hash_table_entry->elem;
    struct hash_elem *prev = hash_insert(page_hash_table, pt_entry_elem);
    if(prev != NULL){
        free(page_hash_table_entry);
        return false;
    }
    return true;
}
/*생성된 page의 주소(upage) 를 전달받고, 
page table entry를 생성해 초기화하고 (status 가 FROM_FILESYS)
page_hash_table에 insert한다.*/
bool vm_supt_install_filesys(struct supplemental_page_table *supt, void *upage,
    struct file *file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes,bool writable){
    struct supplemental_page_table_entry *page_hash_table_entry;
    page_hash_table_entry = (struct supplemental_page_table_entry *) malloc(sizeof(struct supplemental_page_table_entry));
    
    page_hash_table_entry -> upage = upage;
    page_hash_table_entry -> kpage = NULL;
    page_hash_table_entry -> status = FROM_FILESYS;
    page_hash_table_entry -> dirty = false;
    page_hash_table_entry -> file = file;
    page_hash_table_entry -> file_offset = offset;
    page_hash_table_entry -> read_bytes = read_bytes;
    page_hash_table_entry -> zero_bytes = zero_bytes;
    page_hash_table_entry -> writable = writable;

    struct hash* page_hash_table=&supt->page_map;
    struct hash_elem* pt_entry_elem=&page_hash_table_entry->elem;
    struct hash_elem *prev = hash_insert(page_hash_table, pt_entry_elem);
    if(prev != NULL){
        free(page_hash_table_entry);
        return false;
    }
    return true;
}
/*vm_supt_look_up을 이용해서 page_table_entry의 flag
를 swap 으로 set 한다 (ON_SWAP)*/
bool vm_supt_set_swap(struct supplemental_page_table *supt, void *page, swap_index_t swap_index){
    struct supplemental_page_table_entry *page_hash_table_entry;
    page_hash_table_entry = vm_supt_look_up(supt,page);
    if(page_hash_table_entry != NULL){
        page_hash_table_entry -> status = ON_SWAP;
        page_hash_table_entry -> kpage = NULL;
        page_hash_table_entry -> swap_index = swap_index;
        return true;
    }
    return false;
}
struct supplemental_page_table_entry *vm_supt_look_up (struct supplemental_page_table *supt, void *page){
    struct supplemental_page_table_entry supte_tmp;
    supte_tmp.upage = page;
    struct hash_elem *elem = hash_find(&supt->page_map, &supte_tmp.elem);
    if(elem == NULL)
        return NULL;
    else 
        return hash_entry(elem,struct supplemental_page_table_entry,elem);
}
bool vm_supt_has_entry(struct supplemental_page_table *supt, void *page){
    struct supplemental_page_table_entry *supte = vm_supt_look_up(supt, page);
    if(supte == NULL)
        return false;
    else
        return true;
}
bool vm_supt_set_dirty(struct supplemental_page_table *supt, void *page, bool value){
    struct supplemental_page_table_entry *supte = vm_supt_look_up(supt,page);
    if(supte == NULL)
        PANIC("No exist.");
    else {
        supte -> dirty = supte->dirty || value;
        return true;
    }
}
/* Load the page with the address of 'upage'. */
bool handle_mm_fault(struct supplemental_page_table *supt, uint32_t *pagedir, void *upage){
    //1. Check the validity of memory reference.
    struct supplemental_page_table_entry *supte;
    supte = vm_supt_look_up(supt, upage);
    if(supte == NULL)
        return false;
    //If already loaded
    if(supte->status == ON_FRAME)
        return true;
    
    //2. Obtain a frame to store the page.
    void *frame_page = vm_frame_allocate(PAL_USER, upage);
    if(frame_page == NULL){
        return false;
    }

    //3. Fetch the data into the frame.
    bool writable = true;
    switch(supte->status){
        case ALL_ZERO:
            memset(frame_page, 0 , PGSIZE);
            break;
        case ON_FRAME:
            break;
        case ON_SWAP:
            //Swap in (swap disc -> data)
            vm_swap_in(supte->swap_index, frame_page);
            break;
        case FROM_FILESYS:
            if(vm_load_page_from_filesys(supte, frame_page) == false){
                vm_frame_free(frame_page);
                return false;
            }
            writable = supte->writable;
            break;
        default:
            PANIC("Exception");
    }
    //4. Find the page table entry that faults virtual address to physical page.
    if(!pagedir_set_page(pagedir, upage, frame_page, writable)){
        vm_frame_free(frame_page);
        return false;
    }
    supte->kpage = frame_page;
    supte->status = ON_FRAME;

    pagedir_set_dirty(pagedir, frame_page, false);

    vm_frame_unpin(frame_page);
    return true;
}

bool vm_supt_mm_unmap(struct supplemental_page_table *supt, uint32_t *pagedir, void *page, 
      struct file *file, off_t offset, size_t bytes){
    struct supplemental_page_table_entry *supte = vm_supt_look_up(supt, page);
    if(supte == NULL)
        PANIC("Some pages are missing");
    if(supte->status == ON_FRAME){
        ASSERT(supte -> kpage != NULL);
        vm_frame_pin(supte->kpage);
    }
    bool is_dirty;
    switch(supte->status){
        case ON_FRAME:
            ASSERT (supte->kpage != NULL);
            //If upage or mapped frame is dirty, write that to file.
            is_dirty = supte->dirty;
            is_dirty = is_dirty || pagedir_is_dirty(pagedir, supte->upage)||
                pagedir_is_dirty(pagedir, supte->kpage);
            if(is_dirty){
                file_write_at(file, supte->upage, bytes, offset);
            }

            //clear the page mapping and free it.
            vm_frame_free(supte->kpage);
            pagedir_clear_page(pagedir, supte->upage);
            break;

        case ON_SWAP:
            is_dirty = supte->dirty;
            is_dirty = is_dirty || pagedir_is_dirty(pagedir,supte->upage);
            //If it's dirty, then load from the swap and write that to the file.
            if(is_dirty){
                void *tmp_page = palloc_get_page(0);
                vm_swap_in(supte->swap_index, tmp_page);
                file_write_at(file,tmp_page,PGSIZE,offset);
                palloc_free_page(tmp_page);
            }
            else {
                vm_swap_free(supte->swap_index);
            }
            break;
        case FROM_FILESYS:
            break;

        default : 
            PANIC("NO WAY.");
    }

    hash_delete(&supt->page_map, &supte->elem);
    return true;
}    

void vm_pin_page(struct supplemental_page_table *supt, void *page){
    struct supplemental_page_table_entry *supte = vm_supt_look_up(supt, page);
    if(supte == NULL){
        return;
    }
    ASSERT(supte->status == ON_FRAME);
    vm_frame_pin(supte->kpage);
}
void vm_unpin_page(struct supplemental_page_table *supt, void *page){
    struct supplemental_page_table_entry *supte = vm_supt_look_up(supt, page);
    if(supte == NULL)
        PANIC("Requested page doesn't exist");
    if(supte->status == ON_FRAME)
        vm_frame_unpin(supte->kpage);
}


// supplemental table 의 entry를 초기화 할때 쓰는 hash func;
static unsigned supte_hash_func(const struct hash_elem *elem, void *aux UNUSED){
    struct supplemental_page_table_entry *entry = hash_entry(elem, struct supplemental_page_table_entry, elem);
    return hash_int((int)entry->upage);
}
static bool supte_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
    struct supplemental_page_table_entry *e1 = hash_entry(a, struct supplemental_page_table_entry, elem);
    struct supplemental_page_table_entry *e2 = hash_entry(b, struct supplemental_page_table_entry, elem);
    return e1 -> upage < e2 -> upage;
}
static void supte_destroy_func(struct hash_elem *elem, void *aux UNUSED){
    struct supplemental_page_table_entry *entry = hash_entry(elem, struct supplemental_page_table_entry, elem);

    //Clean up the associated frame.
    if(entry->kpage != NULL){
        ASSERT(entry -> status == ON_FRAME);
        vm_frame_remove_entry(entry->kpage);
    }

    else if(entry -> status == ON_SWAP){
        vm_swap_free(entry->swap_index);
    }
    //Finally remove the entry.
    free(entry);
}
static bool vm_load_page_from_filesys(struct supplemental_page_table_entry *supte, void *kpage){
    file_seek(supte->file, supte->file_offset);

    //read bytes from the file
    int read = file_read(supte->file, kpage, supte->read_bytes);
    if(read != (int) supte->read_bytes)
        return false;
    ASSERT(supte->read_bytes + supte-> zero_bytes == PGSIZE);
    memset(kpage + read, 0, supte->zero_bytes);
    return true;
}

void preload_and_pin_pages(const void *buffer, size_t size)
{
  struct supplemental_page_table *supt = thread_current()->supt;
  uint32_t *pagedir = thread_current()->pagedir;

  void *upage;
  for(upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
    handle_mm_fault(supt, pagedir, upage);
    vm_pin_page (supt, upage);
  }
}

void unpin_preloaded_pages(const void *buffer, size_t size)
{
  struct supplemental_page_table *supt = thread_current()->supt;

  void *upage;
  for(upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
    vm_unpin_page (supt, upage);
  }
}