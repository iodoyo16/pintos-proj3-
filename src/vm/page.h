#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <hash.h>
#include "vm/swap.h"
#include "filesys/off_t.h"

enum page_status {
    ALL_ZERO,   /* Filled with zeros. */
    ON_FRAME,   /* Active in memory. */
    ON_SWAP,    /* Being Swapped. */
    FROM_FILESYS/* In filesystem. */
};

/* Supplemental page table. It is preprocessable. */
struct vm_page_table {
    struct hash page_hashmap;
};

struct vm_pt_entry {
    void *upage;     /* Virtual address of the page. */
    void *kpage;     /* Kernel page(frame) associated, */

    struct hash_elem elem;
    enum page_status status;
    bool dirty;
    //if ON_SWAP status
    swap_index_t swap_index;    /* Store the swap index if the page is swapped out. */

    //if FROM_FILESYS status
    struct file *file;
    off_t file_offset;
    uint32_t read_bytes, zero_bytes;
    bool writable;
};

/* Functions for manipulating supplemental page table. */
struct vm_page_table *vm_pt_create(void);
void vm_page_table_destroy(struct vm_page_table *pt);

bool vm_pt_install_frame(struct vm_page_table *pt, void *upage, void *kpage);
bool expand_stack(struct vm_page_table *pt, void *);
bool vm_pt_install_filesys(struct vm_page_table *pt, void *page,
    struct file *file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes,bool writable);

bool vm_pt_set_swap(struct vm_page_table *pt, void *, swap_index_t);
struct vm_pt_entry *vm_pt_look_up (struct vm_page_table *pt, void * page);
bool vm_pt_has_entry(struct vm_page_table *pt, void *page);
bool vm_pt_set_dirty(struct vm_page_table *pt, void *, bool);
bool handle_mm_fault(struct vm_page_table *pt, uint32_t *pagedir, void *upage);
bool vm_pt_mm_unmap(struct vm_page_table *pt, uint32_t *pagedir, 
    void *page, struct file *file, off_t offset, size_t bytes); 

void vm_pin_page(struct vm_page_table *pt, void *page);
void vm_unpin_page(struct vm_page_table *pt, void *page);

void preload_and_pin_pages(const void *, size_t);
void unpin_preloaded_pages(const void *, size_t);
#endif


