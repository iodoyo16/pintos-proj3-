#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/palloc.h"


/*
kpage : The address of kernel page of mapped frame which is the key in the hash table.
upage : The address of virtual memory or user page that loads the frame.
*/

/* Initialize */
void vm_frame_init(void);

/* Create a frame page corresponding to user virtual address upage. 
After the page mapping, return the kernel address of created page frame. */
void* vm_frame_allocate(enum palloc_flags flag, void *upage);

/* Free the page frame. 
Remove the entry in the frame table, free the memory resource. */ 
void vm_frame_free(void* kpage);
/* Just remove the entry from table, do not palloc free */
void vm_frame_remove_entry(void *kpage);
void vm_frame_do_free (void *kpage, bool free_page);

/*For pinning*/
void vm_frame_pin(void*kpage);
void vm_frame_unpin(void *kapge);



#endif