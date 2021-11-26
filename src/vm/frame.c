#include <hash.h>
#include <list.h>
#include <stdio.h>
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"

#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

/* A global lock, to ensure critical sections on frame operations. */
static struct lock frame_lock;

/* A mapping from physical address to frame table entry. */
static struct hash frame_map;

/* A (circular) list of frames for the clock eviction algorithm. */
static struct list frame_list;      /* the list */
static struct list_elem *victim_ptr; /* the pointer in clock algorithm */

static unsigned frame_hash_func(const struct hash_elem *elem, void *aux);
static bool     frame_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);

/* Frame Table Entry */
struct frame_table_entry
  {
    void *kpage;               /* Kernel page, mapped to physical address */

    void *upage;               /* User (Virtual Memory) Address, pointer to page */
    struct thread *t;          /* The associated thread. */

    bool pinned;               /* Used to prevent a frame from being evicted, while it is acquiring some resources.
                                  If it is true, it is never evicted. */

    struct hash_elem helem;    /* frame_map */
    struct list_elem lelem;    /* frame_list */
  };


static struct frame_table_entry* second_chance(uint32_t* pagedir);


void
vm_frame_init ()
{
  lock_init (&frame_lock);
  hash_init (&frame_map, frame_hash_func, frame_less_func, NULL);
  list_init (&frame_list);
  victim_ptr = NULL;
}

/* Allocate a new frame */
void*
vm_frame_allocate (enum palloc_flags flags, void *upage)
{
  lock_acquire (&frame_lock);

  void *frame_page = palloc_get_page (PAL_USER | flags);
  if (frame_page == NULL) {
    // page allocation failed.

    /* first, swap out the page */
    struct frame_table_entry *evicted = second_chance( thread_current()->pagedir );
    ASSERT (evicted != NULL && evicted->t != NULL);

    // clear the page mapping, and replace it with swap
    ASSERT (evicted->t->pagedir != (void*)0xcccccccc);
    pagedir_clear_page(evicted->t->pagedir, evicted->upage);

    bool is_dirty = false;
    is_dirty = is_dirty || pagedir_is_dirty(evicted->t->pagedir, evicted->upage)
      || pagedir_is_dirty(evicted->t->pagedir, evicted->kpage);

    swap_index_t swap_idx = vm_swap_out( evicted->kpage );
    vm_supt_set_swap(evicted->t->supt, evicted->upage, swap_idx);
    vm_supt_set_dirty(evicted->t->supt, evicted->upage, is_dirty);
    vm_frame_do_free(evicted->kpage, true); 

    frame_page = palloc_get_page (PAL_USER | flags);
    ASSERT (frame_page != NULL); 
  }

  struct frame_table_entry *frame = malloc(sizeof(struct frame_table_entry));
  if(frame == NULL) {
    // frame allocation failed. a critical state or panic?
    lock_release (&frame_lock);
    return NULL;
  }

  frame->t = thread_current ();
  frame->upage = upage;
  frame->kpage = frame_page;
  frame->pinned = true;  

  // insert into hash table
  hash_insert (&frame_map, &frame->helem);
  list_push_back (&frame_list, &frame->lelem);

  lock_release (&frame_lock);
  return frame_page;
}

/* Deallocate a frame or page. */
void
vm_frame_free (void *kpage)
{
  lock_acquire (&frame_lock);
  vm_frame_do_free (kpage, true);
  lock_release (&frame_lock);
}

/* Just removes then entry from table, do not palloc free. */
void vm_frame_remove_entry (void *kpage)
{
  lock_acquire (&frame_lock);
  vm_frame_do_free (kpage, false);
  lock_release (&frame_lock);
}

void
vm_frame_do_free (void *kpage, bool free_page)
{
  ASSERT (lock_held_by_current_thread(&frame_lock) == true);
  ASSERT (is_kernel_vaddr(kpage));
  ASSERT (pg_ofs (kpage) == 0); // should be aligned

  // hash lookup : a temporary entry
  struct frame_table_entry f_tmp;
  f_tmp.kpage = kpage;

  struct hash_elem *h = hash_find (&frame_map, &(f_tmp.helem));
  if (h == NULL) {
    PANIC ("The page to be freed is not stored in the table");
  }

  struct frame_table_entry *f;
  f = hash_entry(h, struct frame_table_entry, helem);

  hash_delete (&frame_map, &f->helem);
  list_remove (&f->lelem);

  // Free resources
  if(free_page) palloc_free_page(kpage);
  free(f);
}

/* Second Chance Algorithm */
struct frame_table_entry* next_frame(void);
struct frame_table_entry* second_chance( uint32_t *pagedir ) {
  size_t n = hash_size(&frame_map);
  if(n == 0) 
    PANIC("Frame table is empty.");

  size_t it;
  for(it = 0; it <= n + n; ++ it) // prevent infinite loop. 
  {
    struct frame_table_entry *e = next_frame();
    // if pinned, continue
    if(e->pinned) continue;
    // if referenced, give a second chance.
    else if( pagedir_is_accessed(pagedir, e->upage)) {
      pagedir_set_accessed(pagedir, e->upage, false);
      continue;
    }

    // victim
    return e;
  }

  PANIC ("Can't evict any frame. \n");
}
struct frame_table_entry* next_frame(void)
{
  if (list_empty(&frame_list))
    PANIC("Frame table is empty, can't happen - there is a leak somewhere");

  if (victim_ptr == NULL || victim_ptr == list_end(&frame_list))
    victim_ptr = list_begin (&frame_list);
  else
    victim_ptr = list_next (victim_ptr);

  struct frame_table_entry *e = list_entry(victim_ptr, struct frame_table_entry, lelem);
  return e;
}


static void
vm_frame_set_pinned (void *kpage, bool new_value)
{
  lock_acquire (&frame_lock);

  // hash lookup : a temporary entry
  struct frame_table_entry f_tmp;
  f_tmp.kpage = kpage;
  struct hash_elem *h = hash_find (&frame_map, &(f_tmp.helem));
  if (h == NULL) {
    PANIC ("The frame to be pinned/unpinned does not exist");
  }

  struct frame_table_entry *f;
  f = hash_entry(h, struct frame_table_entry, helem);
  f->pinned = new_value;

  lock_release (&frame_lock);
}

void
vm_frame_pin (void* kpage) {
  vm_frame_set_pinned (kpage, true);
}

void
vm_frame_unpin (void* kpage) {
  vm_frame_set_pinned (kpage, false);
}

// 'kpage' as key.
static unsigned frame_hash_func(const struct hash_elem *elem, void *aux UNUSED)
{
  struct frame_table_entry *entry = hash_entry(elem, struct frame_table_entry, helem);
  return hash_bytes( &entry->kpage, sizeof entry->kpage );
}
static bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct frame_table_entry *a_entry = hash_entry(a, struct frame_table_entry, helem);
  struct frame_table_entry *b_entry = hash_entry(b, struct frame_table_entry, helem);
  return a_entry->kpage < b_entry->kpage;
}